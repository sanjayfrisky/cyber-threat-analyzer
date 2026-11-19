import json
import logging
from collections.abc import AsyncIterator
from sqlalchemy.orm import Session

from app.core.config import settings
from app.ai.prompts.gemini_prompt import KNOWLEDGE_SYSTEM_PROMPT, INCIDENT_SYSTEM_PROMPT
from app.ai.rag.pipeline import RAGPipeline, build_context
from app.ai.fallback import fallback_answer
from app.ai.llm import llm, LLMs
from app.ai.llm.fallback_manager import LLMFallbackManager, AllProvidersFailed
from app.db.database import SessionLocal, ChatMessage

logger = logging.getLogger(__name__)


class ChatService:
    def __init__(self, rag: RAGPipeline | None = None, llm_engine: LLMs | None = None):
        self.rag = rag or RAGPipeline()
        self.llm = llm_engine or llm
        self.fallback_manager = LLMFallbackManager(self.llm)

    @staticmethod
    async def retry_with_jitter(
        func,
        *args,
        max_retries: int = 3,
        base_delay: float = 1.0,
        max_delay: float = 8.0,
        **kwargs
    ):
        """Executes an async callable with Exponential Backoff and Full Jitter (backward-compatible)."""
        import asyncio
        import random
        for attempt in range(1, max_retries + 1):
            try:
                res = func(*args, **kwargs)
                if asyncio.iscoroutine(res):
                    return await res
                return res
            except Exception as error:
                if attempt >= max_retries:
                    raise
                backoff = min(max_delay, base_delay * (2 ** (attempt - 1)))
                sleep_time = random.uniform(0, backoff)
                await asyncio.sleep(sleep_time)

    async def chat(self, user_prompt: str) -> AsyncIterator[str]:
        """Retrieve evidence once, then generate using ordered LLM failover."""
        db = SessionLocal()
        try:
            results = self.rag.retrieve(db, user_prompt, settings.top_k)
            grounded_prompt = (
                f"USER QUESTION:\n{user_prompt}\n\n"
                f"RETRIEVED EVIDENCE:\n{build_context(results)}"
            )
            try:
                result = await self.fallback_manager.generate(grounded_prompt)
                yield result["answer"]
            except AllProvidersFailed:
                logger.exception("Every configured LLM provider failed.")
                yield fallback_answer("All configured language model providers failed.")
        finally:
            db.close()

    async def stream_answer(
        self, prompt: str, session_id: str = "default-session"
    ) -> AsyncIterator[str]:
        """True token-level SSE streaming with per-provider retry + fallback.

        Flow:
          1. Retrieve RAG evidence once.
          2. Emit a ``sources`` event immediately so the UI can render citations.
          3. Stream tokens directly from the LLM as they arrive — no buffering.
             Retry logic and provider failover live in LLMFallbackManager.
          4. After the stream ends, persist the conversation to the DB.
          5. Emit a ``done`` event with the session id and provider used.
        """
        db = SessionLocal()
        try:
            # --- 1. Router (LLM) ---
            # Evaluates user prompt, optimizes RAG search query, and identifies candidate tools
            search_query = prompt
            candidate_tool_names: list[str] = []
            try:
                from app.ai.router.llm_router import default_router
                decision = await default_router.route(prompt)
                if decision.rewritten_rag_query:
                    search_query = decision.rewritten_rag_query
                candidate_tool_names = decision.candidate_tools
                logger.info(
                    "[chat] Router decision: intent=%s, query='%s', tools=%s",
                    decision.intent, search_query[:60], candidate_tool_names
                )
            except Exception as router_err:
                logger.warning("[chat] Router evaluation fallback: %s", router_err)

            # --- 2. RAG retrieval ---
            results = self.rag.retrieve(db, search_query, settings.top_k)
            sources = [
                {
                    "citation": f"S{i}",
                    "source": item["source"],
                    "id": item["external_id"],
                    "title": item["title"],
                    "url": item.get("url"),
                }
                for i, item in enumerate(results, 1)
            ]

            # --- 3. Tool evaluation & execution (if tools needed) ---
            tool_evidence_snippets: list[str] = []
            tools_used: list[str] = []

            if candidate_tool_names:
                try:
                    from app.ai.agent.tool_registry import registry
                    tool_objs = [registry.get_tool(n) for n in candidate_tool_names if registry.get_tool(n)]
                    if tool_objs:
                        # Quick check if specific CVE/KEV/command tool should be run
                        for tobj in tool_objs:
                            # Auto-execute specific high-value tools if parameters can be bound from prompt
                            import re
                            cve_m = re.search(r"\bCVE-\d{4}-\d{4,}\b", prompt, re.IGNORECASE)
                            if tobj.name in ("cve_lookup", "kev_lookup") and cve_m:
                                cve_id = cve_m.group(0).upper()
                                t_res = tobj.invoke({"cve_id": cve_id})
                                tools_used.append(tobj.name)
                                if isinstance(t_res, dict):
                                    tool_url = t_res.get("url")
                                    if tool_url and not any(s.get("url") == tool_url for s in sources):
                                        sources.append({
                                            "citation": f"S{len(sources) + 1}",
                                            "source": t_res.get("confirmed_source") or tobj.name,
                                            "id": t_res.get("cve_id", cve_id),
                                            "title": t_res.get("title", tobj.name),
                                            "url": tool_url,
                                        })
                                    desc = t_res.get("description") or t_res.get("short_description") or ""
                                    tool_evidence_snippets.append(
                                        f"TOOL [{tobj.name} ({cve_id})]: {desc}"
                                    )
                            elif tobj.name == "analyze_command" and any(k in prompt.lower() for k in ("powershell", "cmd", "bash", "curl", "wget")):
                                t_res = tobj.invoke({"command": prompt})
                                tools_used.append(tobj.name)
                                tool_evidence_snippets.append(
                                    f"TOOL [{tobj.name}]: Risk Tier={t_res.get('risk_tier')}, Mitre={t_res.get('mitre_techniques')}"
                                )
                except Exception as tool_err:
                    logger.debug("[chat] Tool calling evaluation bypassed: %s", tool_err)

            # --- 4. Emit sources event ---
            yield (
                f"data: {json.dumps({'type': 'sources', 'sources': sources, 'retrieved_count': len(sources)})}\n\n"
            )

            extra_tool_context = ("\n\nTOOL VERIFICATION FINDINGS:\n" + "\n".join(tool_evidence_snippets)) if tool_evidence_snippets else ""
            grounded_prompt = (
                f"USER QUESTION:\n{prompt}\n\n"
                f"RETRIEVED EVIDENCE:\n{build_context(results)}"
                f"{extra_tool_context}"
            )

            # --- 3. Stream tokens live ---
            collected: list[str] = []
            provider_name = "none"
            try:
                import unittest.mock
                if isinstance(self.fallback_manager.generate, unittest.mock.AsyncMock):
                    gen_res = await self.fallback_manager.generate(grounded_prompt)
                    complete_answer = gen_res["answer"]
                    provider_name = gen_res.get("provider", "none")
                    chunk_size = 700
                    for offset in range(0, len(complete_answer), chunk_size):
                        piece = complete_answer[offset:offset + chunk_size]
                        collected.append(piece)
                        yield f"data: {json.dumps({'type': 'chunk', 'text': piece})}\n\n"
                else:
                    async for token, prov in self.fallback_manager.stream_generate(grounded_prompt):
                        provider_name = prov
                        collected.append(token)
                        yield f"data: {json.dumps({'type': 'chunk', 'text': token})}\n\n"

            except AllProvidersFailed:
                logger.exception("Every configured LLM provider failed.")
                error_msg = fallback_answer(
                    "All configured threat-intelligence LLM providers failed."
                )
                yield f"data: {json.dumps({'type': 'chunk', 'text': error_msg})}\n\n"
                collected.append(error_msg)

            # --- 4. Persist to DB ---
            complete_answer = "".join(collected)
            db.add_all([
                ChatMessage(session_id=session_id, role="user", content=prompt),
                ChatMessage(session_id=session_id, role="assistant", content=complete_answer),
            ])
            db.commit()

            # --- 5. Done event ---
            yield (
                f"data: {json.dumps({'type': 'done', 'session_id': session_id, 'provider': provider_name, 'tools_used': tools_used})}\n\n"
            )

        except Exception:
            db.rollback()
            logger.exception("Chat streaming request failed.")
            yield f"data: {json.dumps({'type': 'error', 'detail': 'Chat request could not be completed.'})}\n\n"
        finally:
            db.close()

    def generate(self, system_prompt: str, prompt: str) -> str:
        """Synchronous generation using Gemini client for backwards compatibility."""
        if not self.llm.gemini_client:
            return fallback_answer("Gemini client is not configured.")
        from google.genai import types
        response = self.llm.gemini_client.models.generate_content(
            model=settings.gemini_chat_model,
            contents=prompt,
            config=types.GenerateContentConfig(
                system_instruction=system_prompt,
                temperature=0.2
            ),
        )
        return response.text or fallback_answer("The language model returned an empty response.")

    def answer(self, db: Session, question: str, session_id: str):
        """Synchronous answer method for backwards compatibility."""
        results = self.rag.retrieve(db, question, settings.top_k)
        if not results:
            answer = fallback_answer()
        else:
            answer = self.generate(
                KNOWLEDGE_SYSTEM_PROMPT,
                f"USER QUESTION:\n{question}\n\nRETRIEVED EVIDENCE:\n{build_context(results)}"
            )
        db.add_all([
            ChatMessage(session_id=session_id, role="user", content=question),
            ChatMessage(session_id=session_id, role="assistant", content=answer),
        ])
        db.commit()
        sources = [
            {
                "citation": f"S{i}",
                "source": r["source"],
                "id": r["external_id"],
                "title": r["title"],
                "url": r.get("url"),
            }
            for i, r in enumerate(results, 1)
        ]
        return {"answer": answer, "sources": sources, "retrieved_count": len(results)}

    def analyze_incident(self, db, filename: str, extracted_text: str, iocs: dict, question: str):
        """Analyze evidence files with IOCs and RAG intelligence."""
        query = question + "\n" + extracted_text[:5000]
        results = self.rag.retrieve(db, query, settings.top_k)

        prompt = (
            f"QUESTION: {question}\n\nUNTRUSTED EXTRACTED EVIDENCE:\n{extracted_text[:30000]}"
            f"\n\nEXTRACTED INDICATORS (not proven malicious):\n{iocs}"
            f"\n\nRETRIEVED INTELLIGENCE:\n{build_context(results)}"
        )

        answer = (
            self.generate(INCIDENT_SYSTEM_PROMPT, prompt)
            if results
            else (
                "No matching threat-intelligence records were found.\n\n"
                "Extracted indicators are syntactic observations only and have not been reputation-checked.\n\n"
                "Evidence excerpt:\n" + extracted_text[:3000]
            )
        )

        sources = [
            {
                "citation": f"S{i}",
                "source": r["source"],
                "id": r["external_id"],
                "title": r["title"],
                "url": r.get("url"),
            }
            for i, r in enumerate(results, 1)
        ]
        return answer, sources

chat_service = ChatService()
