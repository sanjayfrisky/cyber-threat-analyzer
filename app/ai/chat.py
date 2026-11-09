import asyncio
import json
import logging
import random
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
        """
        Executes an async callable with Exponential Backoff and Full Jitter.
        Formula:
            backoff = min(max_delay, base_delay * (2 ** (attempt - 1)))
            sleep_time = random.uniform(0, backoff)
        """
        for attempt in range(1, max_retries + 1):
            try:
                res = func(*args, **kwargs)
                if asyncio.iscoroutine(res):
                    return await res
                return res
            except Exception as error:
                if attempt >= max_retries:
                    logger.warning("Attempt %d/%d failed: %s", attempt, max_retries, error)
                    raise
                backoff = min(max_delay, base_delay * (2 ** (attempt - 1)))
                sleep_time = random.uniform(0, backoff)
                logger.info(
                    "Attempt %d/%d failed: %s — retrying in %.2fs",
                    attempt, max_retries, error, sleep_time
                )
                await asyncio.sleep(sleep_time)

    async def chat(self, user_prompt: str) -> AsyncIterator[str]:
        """Retrieve evidence once, then generate using ordered LLM failover."""
        db = SessionLocal()
        try:
            results = self.rag.retrieve(db, user_prompt, settings.top_k)
            grounded_prompt = (
                f"USER QUESTION:\\n{user_prompt}\\n\\n"
                f"RETRIEVED EVIDENCE:\\n{build_context(results)}"
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
        """SSE chat endpoint with safe provider failover.

        Retrieval runs once. A provider's complete answer is buffered before
        the first answer chunk is emitted, preventing mixed partial answers
        when a provider fails mid-generation.
        """
        db = SessionLocal()
        try:
            results = self.rag.retrieve(db, prompt, settings.top_k)
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

            yield (
                f"data: {json.dumps({'type': 'sources', 'sources': sources, 'retrieved_count': len(results)})}\\n\\n"
            )

            provider_name = "none"
            grounded_prompt = (
                f"USER QUESTION:\\n{prompt}\\n\\n"
                f"RETRIEVED EVIDENCE:\\n{build_context(results)}"
            )
            try:
                generated = await self.fallback_manager.generate(grounded_prompt)
                complete_answer = generated["answer"]
                provider_name = generated["provider"]
            except AllProvidersFailed:
                logger.exception("Every configured LLM provider failed.")
                complete_answer = fallback_answer(
                    "All configured threat-intelligence LLM providers failed."
                )

            # Emit only after a provider has completed successfully.
            chunk_size = 700
            for offset in range(0, len(complete_answer), chunk_size):
                piece = complete_answer[offset:offset + chunk_size]
                yield f"data: {json.dumps({'type': 'chunk', 'text': piece})}\\n\\n"

            db.add_all([
                ChatMessage(session_id=session_id, role="user", content=prompt),
                ChatMessage(session_id=session_id, role="assistant", content=complete_answer),
            ])
            db.commit()

            yield (
                f"data: {json.dumps({'type': 'done', 'session_id': session_id, 'provider': provider_name})}\\n\\n"
            )

        except Exception as exc:
            db.rollback()
            logger.exception("Chat streaming request failed.")
            # Do not expose internal exception strings, credentials, or DB details.
            yield f"data: {json.dumps({'type': 'error', 'detail': 'Chat request could not be completed.'})}\\n\\n"
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
