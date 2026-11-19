"""Pipeline Orchestrator: User Prompt -> LLM Router -> RAG Retrieval -> Tool Calling -> Final Answer."""
from __future__ import annotations

import json
import logging
import time
from collections.abc import AsyncIterator
from typing import Any

from langchain_core.messages import AIMessage, BaseMessage, HumanMessage, SystemMessage, ToolMessage
from sqlalchemy.orm import Session

from app.ai.agent.tool_registry import ToolRegistry, registry as default_registry
from app.ai.llm.model_factory import build_model_with_retry_and_fallback
from app.ai.prompts.gemini_prompt import KNOWLEDGE_SYSTEM_PROMPT
from app.ai.rag.pipeline import RAGPipeline, build_context
from app.ai.router.llm_router import LLMRouter, RoutingDecision, default_router
from app.core.config import settings
from app.db.database import ChatMessage, SessionLocal

logger = logging.getLogger(__name__)


class PipelineOrchestrator:
    """
    Coordinates the full defensive analysis lifecycle:
    1. User Prompt
    2. LLM Router (Intent, query rewrite, candidate tools)
    3. RAG Retrieval (Hybrid search in PostgreSQL / pgvector)
    4. Tool Calling Evaluation (If tool needed -> execute & fetch)
    5. Final Synthesis & Streaming
    """

    def __init__(
        self,
        router: LLMRouter | None = None,
        rag: RAGPipeline | None = None,
        tool_registry: ToolRegistry | None = None,
        llm=None,
    ):
        self.router = router or default_router
        self.rag = rag or RAGPipeline()
        self.registry = tool_registry or default_registry
        self.llm = llm or build_model_with_retry_and_fallback()

    async def stream_execute(
        self,
        prompt: str,
        session_id: str = "default-session",
    ) -> AsyncIterator[str]:
        """
        Execute the complete pipeline and yield SSE-compliant event strings.

        Events emitted:
        1. data: {"type": "routing", "intent": ..., "rewritten_query": ...}
        2. data: {"type": "sources", "sources": [...], "retrieved_count": ...}
        3. data: {"type": "tool_executed", "tool": ..., "output": ...} (if tool called)
        4. data: {"type": "chunk", "text": ...} (streaming tokens)
        5. data: {"type": "done", "session_id": ..., "provider": ..., "tools_used": [...]}
        """
        t0 = time.perf_counter()
        db: Session = SessionLocal()
        collected_tokens: list[str] = []
        tools_executed: list[str] = []
        all_sources: list[dict[str, Any]] = []

        try:
            # ============================================================
            # STEP 1: ROUTER (LLM)
            # ============================================================
            logger.info("[orchestrator] Step 1: Routing prompt '%s'", prompt[:80])
            decision: RoutingDecision = await self.router.route(prompt)

            yield (
                f"data: {json.dumps({'type': 'routing', 'intent': decision.intent, 'rewritten_query': decision.rewritten_rag_query})}\n\n"
            )

            # ============================================================
            # STEP 2: RAG RETRIEVAL
            # ============================================================
            rag_results = []
            if decision.needs_rag:
                search_query = decision.rewritten_rag_query or prompt
                logger.info("[orchestrator] Step 2: Executing RAG hybrid search for query: '%s'", search_query[:80])
                try:
                    rag_results = self.rag.retrieve(db, search_query, top_k=settings.top_k)
                except Exception as rag_err:
                    logger.warning("[orchestrator] RAG retrieval error: %s", rag_err)
                    rag_results = []

            # Format RAG sources for UI citations
            for idx, item in enumerate(rag_results, 1):
                all_sources.append({
                    "citation": f"S{idx}",
                    "source": item.get("source", "NVD"),
                    "id": item.get("external_id", "doc"),
                    "title": item.get("title", "Threat Intelligence"),
                    "url": item.get("url"),
                })

            # Emit initial sources event to the client
            yield (
                f"data: {json.dumps({'type': 'sources', 'sources': all_sources, 'retrieved_count': len(all_sources)})}\n\n"
            )

            # ============================================================
            # STEP 3: TOOL CALLING EVALUATION
            # ============================================================
            # Resolve candidate tools from the registry
            candidate_tool_objs = []
            for name in decision.candidate_tools:
                t = self.registry.get_tool(name)
                if t:
                    candidate_tool_objs.append(t)

            if not candidate_tool_objs and decision.intent != "general_rag":
                candidate_tool_objs = self.registry.select_tools_for_query(prompt)

            tool_map = {t.name: t for t in candidate_tool_objs}

            rag_context_str = build_context(rag_results)
            grounded_instructions = (
                f"USER QUESTION:\n{prompt}\n\n"
                f"RETRIEVED RAG EVIDENCE FROM INDEXED KNOWLEDGE BASE:\n{rag_context_str}\n\n"
                f"EVALUATION INSTRUCTIONS:\n"
                f"1. Check if the retrieved RAG evidence contains complete, verified details for the user's question.\n"
                f"2. If additional verification or specialized analysis is required (e.g. live CISA KEV exploitation check, "
                f"NVD fallback, CVSS score breakdown, suspicious command inspection, or IOC extraction), "
                f"invoke the appropriate tool.\n"
                f"3. Otherwise, if the RAG evidence is sufficient, provide a thorough, beginner-friendly defensive explanation.\n"
                f"4. Cite sources as [S1], [S2], etc."
            )

            messages: list[BaseMessage] = [
                SystemMessage(content=KNOWLEDGE_SYSTEM_PROMPT),
                HumanMessage(content=grounded_instructions),
            ]

            # Bind candidate tools if available
            model = self.llm
            if candidate_tool_objs and hasattr(model, "bind_tools"):
                model_with_tools = model.bind_tools(candidate_tool_objs)
            else:
                model_with_tools = model

            logger.info(
                "[orchestrator] Step 3: Evaluating tool calling with %d candidate tools: %s",
                len(candidate_tool_objs),
                [t.name for t in candidate_tool_objs],
            )

            try:
                ai_message: AIMessage = await model_with_tools.ainvoke(messages)
            except Exception as invoke_err:
                logger.warning("[orchestrator] model invocation with tools failed: %s; falling back to direct", invoke_err)
                ai_message = await model.ainvoke(messages)

            messages.append(ai_message)

            # Check if the LLM requested tool execution
            tool_calls = getattr(ai_message, "tool_calls", []) or []
            if tool_calls:
                logger.info("[orchestrator] Model requested %d tool calls: %s", len(tool_calls), [c.get("name") for c in tool_calls])
                for call in tool_calls:
                    t_name = call.get("name")
                    t_args = call.get("args", {})
                    call_id = call.get("id", f"call_{len(tools_executed)}")
                    target_tool = tool_map.get(t_name)

                    if target_tool:
                        try:
                            logger.info("[orchestrator] Executing tool '%s' with args %s", t_name, list(t_args.keys()))
                            if hasattr(target_tool, "ainvoke"):
                                tool_output = await target_tool.ainvoke(t_args)
                            else:
                                tool_output = target_tool.invoke(t_args)
                        except Exception as tool_err:
                            logger.error("[orchestrator] Tool execution error for '%s': %s", t_name, tool_err)
                            tool_output = {"error": f"Tool execution failed: {str(tool_err)}"}
                    else:
                        tool_output = {"error": f"Tool '{t_name}' not available in candidate list"}

                    tools_executed.append(t_name)

                    # Extract new citations from tool output if present
                    if isinstance(tool_output, dict):
                        tool_url = tool_output.get("url")
                        if tool_url and not any(s.get("url") == tool_url for s in all_sources):
                            new_cite = f"S{len(all_sources) + 1}"
                            all_sources.append({
                                "citation": new_cite,
                                "source": tool_output.get("confirmed_source") or t_name,
                                "id": tool_output.get("cve_id") or tool_output.get("technique_id") or t_name,
                                "title": tool_output.get("title") or t_name,
                                "url": tool_url,
                            })

                    # Notify client about tool execution
                    yield (
                        f"data: {json.dumps({'type': 'tool_executed', 'tool': t_name, 'status': 'completed'})}\n\n"
                    )

                    serialised = json.dumps(tool_output) if isinstance(tool_output, (dict, list)) else str(tool_output)
                    messages.append(
                        ToolMessage(
                            content=serialised,
                            tool_call_id=call_id,
                        )
                    )

                # Update sources event if tool produced additional references
                if len(all_sources) > len(rag_results):
                    yield (
                        f"data: {json.dumps({'type': 'sources', 'sources': all_sources, 'retrieved_count': len(all_sources)})}\n\n"
                    )

                # ============================================================
                # STEP 4: FINAL SYNTHESIS WITH TOOL OUTPUTS
                # ============================================================
                logger.info("[orchestrator] Step 4: Generating final synthesis from RAG + Tool outputs")
                final_ai = await model.ainvoke(messages)
                complete_text = str(final_ai.content).strip()
            else:
                logger.info("[orchestrator] No tool calls required; RAG evidence was sufficient")
                complete_text = str(ai_message.content).strip()

            # Stream out the final text in manageable chunks for smooth rendering
            chunk_size = 40
            for i in range(0, len(complete_text), chunk_size):
                token = complete_text[i : i + chunk_size]
                collected_tokens.append(token)
                yield f"data: {json.dumps({'type': 'chunk', 'text': token})}\n\n"

            # Persist to database history
            full_response = "".join(collected_tokens)
            try:
                db.add_all([
                    ChatMessage(session_id=session_id, role="user", content=prompt),
                    ChatMessage(session_id=session_id, role="assistant", content=full_response),
                ])
                db.commit()
            except Exception as db_err:
                logger.warning("[orchestrator] Failed to persist chat message: %s", db_err)
                db.rollback()

            elapsed_ms = (time.perf_counter() - t0) * 1000
            logger.info(
                "[orchestrator] Finished session '%s' in %.1f ms (tools: %s, sources: %d)",
                session_id,
                elapsed_ms,
                tools_executed,
                len(all_sources),
            )

            yield (
                f"data: {json.dumps({'type': 'done', 'session_id': session_id, 'provider': 'orchestrator', 'tools_used': tools_executed})}\n\n"
            )

        except Exception as exc:
            logger.exception("[orchestrator] Pipeline execution failed: %s", exc)
            yield f"data: {json.dumps({'type': 'error', 'detail': f'Pipeline failed: {str(exc)}'})}\n\n"
        finally:
            db.close()


# Global pipeline instance
default_orchestrator = PipelineOrchestrator()
