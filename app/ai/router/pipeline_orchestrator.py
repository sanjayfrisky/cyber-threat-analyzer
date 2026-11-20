"""Pipeline Orchestrator: Single-step distribution (RAG only OR single Tool only OR General).
No multi-tool looping — fast, deterministic, single-step execution.
"""
from __future__ import annotations

import json
import logging
import time
from collections.abc import AsyncIterator
from typing import Any

from langchain_core.messages import BaseMessage, HumanMessage, SystemMessage
from sqlalchemy.orm import Session

from app.ai.llm.model_factory import build_model_with_retry_and_fallback
from app.ai.prompts.gemini_prompt import KNOWLEDGE_SYSTEM_PROMPT
from app.ai.rag.pipeline import RAGPipeline, build_context
from app.ai.router.llm_router import LLMRouter, RoutingDecision, default_router
from app.ai.tools import ALL_TOOLS
from app.core.config import settings
from app.db.database import ChatMessage, SessionLocal

logger = logging.getLogger(__name__)


class PipelineOrchestrator:
    """
    Coordinates single-step query distribution:
    1. User Prompt
    2. LLM Router (Branch to RAG only, specific Tool only, or General)
    3. Distribution Execution (Zero multi-tool looping)
    4. Stream Final Grounded Answer
    """

    def __init__(
        self,
        router: LLMRouter | None = None,
        rag: RAGPipeline | None = None,
        tools: list | None = None,
        llm=None,
    ):
        self.router = router or default_router
        self.rag = rag or RAGPipeline()
        self.tools = tools or ALL_TOOLS
        self.tool_map = {t.name: t for t in self.tools}
        self.llm = llm or build_model_with_retry_and_fallback()

    async def stream_execute(
        self,
        prompt: str,
        session_id: str = "default-session",
    ) -> AsyncIterator[str]:
        """
        Execute single-step distribution and stream SSE events.
        Events:
        1. routing: {"type": "routing", "destination": ..., "selected_tool": ...}
        2. sources: {"type": "sources", "sources": [...], "retrieved_count": ...}
        3. tool_executed: {"type": "tool_executed", "tool": ...} (if tool branch)
        4. chunk: {"type": "chunk", "text": ...} (streamed tokens)
        5. done: {"type": "done", "session_id": ..., "destination": ...}
        """
        t0 = time.perf_counter()
        db: Session = SessionLocal()
        collected_tokens: list[str] = []
        sources: list[dict[str, Any]] = []
        tool_used: str | None = None

        try:
            # ============================================================
            # STEP 1: ROUTER LLM (Single-Step Classification)
            # ============================================================
            logger.info("[orchestrator] Step 1: Routing prompt '%s'", prompt[:80])
            decision: RoutingDecision = await self.router.route(prompt)

            yield (
                f"data: {json.dumps({'type': 'routing', 'destination': decision.destination, 'selected_tool': decision.selected_tool, 'intent': decision.intent})}\n\n"
            )

            # ============================================================
            # STEP 2: DISTRIBUTE
            # ============================================================
            model = self.llm

            # ------------------------------------------------------------
            # BRANCH A: RAG (RAG alone answers)
            # ------------------------------------------------------------
            if decision.destination == "rag":
                search_query = decision.rag_query or prompt
                logger.info("[orchestrator] Branch: RAG retrieval for '%s'", search_query[:60])
                try:
                    rag_results = self.rag.retrieve(db, search_query, top_k=settings.top_k)
                except Exception as rag_err:
                    logger.warning("[orchestrator] RAG retrieval error: %s", rag_err)
                    rag_results = []

                for idx, item in enumerate(rag_results, 1):
                    sources.append({
                        "citation": f"S{idx}",
                        "source": item.get("source", "NVD"),
                        "id": item.get("external_id", "doc"),
                        "title": item.get("title", "Threat Intelligence"),
                        "url": item.get("url"),
                    })

                yield (
                    f"data: {json.dumps({'type': 'sources', 'sources': sources, 'retrieved_count': len(sources)})}\n\n"
                )

                rag_context = build_context(rag_results)
                grounded_prompt = (
                    f"USER QUESTION:\n{prompt}\n\n"
                    f"RETRIEVED KNOWLEDGE BASE EVIDENCE:\n{rag_context}\n\n"
                    f"Provide a clear, beginner-friendly defensive explanation based strictly on the retrieved evidence. "
                    f"Cite sources as [S1], [S2], etc."
                )

                messages: list[BaseMessage] = [
                    SystemMessage(content=KNOWLEDGE_SYSTEM_PROMPT),
                    HumanMessage(content=grounded_prompt),
                ]
                ai_resp = await model.ainvoke(messages)
                complete_text = str(ai_resp.content).strip()

            # ------------------------------------------------------------
            # BRANCH B: SPECIFIC TOOL (That tool alone answers, no looping)
            # ------------------------------------------------------------
            elif decision.destination == "tool" and decision.selected_tool:
                tool_name = decision.selected_tool
                target_tool = self.tool_map.get(tool_name)
                tool_used = tool_name
                logger.info("[orchestrator] Branch: Single tool execution '%s'", tool_name)

                if target_tool:
                    try:
                        args = decision.tool_args or {}
                        if hasattr(target_tool, "ainvoke"):
                            tool_output = await target_tool.ainvoke(args)
                        else:
                            tool_output = target_tool.invoke(args)
                    except Exception as tool_err:
                        logger.error("[orchestrator] Tool '%s' execution error: %s", tool_name, tool_err)
                        tool_output = {"error": f"Tool execution error: {str(tool_err)}"}
                else:
                    tool_output = {"error": f"Tool '{tool_name}' not found."}

                yield (
                    f"data: {json.dumps({'type': 'tool_executed', 'tool': tool_name, 'status': 'completed'})}\n\n"
                )

                # Extract citations from tool result
                if isinstance(tool_output, dict):
                    tool_url = tool_output.get("url")
                    if tool_url:
                        sources.append({
                            "citation": "S1",
                            "source": tool_output.get("confirmed_source") or tool_name,
                            "id": tool_output.get("cve_id") or tool_output.get("technique_id") or tool_name,
                            "title": tool_output.get("title") or tool_output.get("vulnerability_name") or tool_name,
                            "url": tool_url,
                        })

                yield (
                    f"data: {json.dumps({'type': 'sources', 'sources': sources, 'retrieved_count': len(sources)})}\n\n"
                )

                tool_context = json.dumps(tool_output, indent=2) if isinstance(tool_output, (dict, list)) else str(tool_output)
                tool_prompt = (
                    f"USER QUESTION:\n{prompt}\n\n"
                    f"TOOL EXECUTION EVIDENCE ({tool_name}):\n{tool_context}\n\n"
                    f"Explain the technical findings clearly and provide practical defensive recommendations. "
                    f"Cite the source using [S1] if a reference URL is present."
                )

                messages = [
                    SystemMessage(content=KNOWLEDGE_SYSTEM_PROMPT),
                    HumanMessage(content=tool_prompt),
                ]
                ai_resp = await model.ainvoke(messages)
                complete_text = str(ai_resp.content).strip()

            # ------------------------------------------------------------
            # BRANCH C: GENERAL CONVERSATION
            # ------------------------------------------------------------
            else:
                logger.info("[orchestrator] Branch: General conversational answer")
                yield (
                    f"data: {json.dumps({'type': 'sources', 'sources': [], 'retrieved_count': 0})}\n\n"
                )
                messages = [
                    SystemMessage(content=KNOWLEDGE_SYSTEM_PROMPT),
                    HumanMessage(content=prompt),
                ]
                ai_resp = await model.ainvoke(messages)
                complete_text = str(ai_resp.content).strip()

            # ============================================================
            # STEP 3: STREAM ANSWER TO CLIENT
            # ============================================================
            chunk_size = 45
            for i in range(0, len(complete_text), chunk_size):
                token = complete_text[i : i + chunk_size]
                collected_tokens.append(token)
                yield f"data: {json.dumps({'type': 'chunk', 'text': token})}\n\n"

            # Persist message history
            full_response = "".join(collected_tokens)
            try:
                db.add_all([
                    ChatMessage(session_id=session_id, role="user", content=prompt),
                    ChatMessage(session_id=session_id, role="assistant", content=full_response),
                ])
                db.commit()
            except Exception as db_err:
                logger.warning("[orchestrator] DB save error: %s", db_err)
                db.rollback()

            elapsed_ms = (time.perf_counter() - t0) * 1000
            yield (
                f"data: {json.dumps({'type': 'done', 'session_id': session_id, 'destination': decision.destination, 'tool_used': tool_used, 'elapsed_ms': elapsed_ms})}\n\n"
            )

        except Exception as exc:
            logger.exception("[orchestrator] Pipeline failed: %s", exc)
            yield f"data: {json.dumps({'type': 'error', 'detail': f'Execution failed: {str(exc)}'})}\n\n"
        finally:
            db.close()


# Global shared instance
default_orchestrator = PipelineOrchestrator()
