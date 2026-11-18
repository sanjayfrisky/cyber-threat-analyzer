"""LangChain-native provider orchestration with safe failover, retry, and token streaming."""
from __future__ import annotations

import asyncio
import logging
from typing import AsyncGenerator

import httpx
from langchain_core.prompts import ChatPromptTemplate

from app.ai.llm.providers import LLMs, llm as default_llm
from app.ai.llm.retry_manager import RETRYABLE_EXCEPTIONS as _RETRYABLE_EXCEPTIONS, MAX_ADDITIONAL_RETRIES as _MAX_RETRIES
from app.ai.prompts.gemini_prompt import KNOWLEDGE_SYSTEM_PROMPT

logger = logging.getLogger(__name__)


class AllProvidersFailed(RuntimeError):
    """Raised when no configured LLM provider can complete a response."""


def _resolve_provider_name(response_meta: dict | None, default: str = "LLM") -> str:
    """Extract human-readable provider name from LangChain metadata."""
    if not response_meta:
        return default
    provider = response_meta.get("model_provider")
    if provider:
        return str(provider).capitalize()
    model = response_meta.get("model_name") or response_meta.get("model") or ""
    model_lower = str(model).lower()
    if "groq" in model_lower or "gpt-oss" in model_lower:
        return "Groq"
    if "mistral" in model_lower:
        return "Mistral"
    if "llama" in model_lower or "nvidia" in model_lower:
        return "NVIDIA"
    if "gemini" in model_lower:
        return "Gemini"
    return default


class LangChainFallbackManager:
    """Manages LLM fallback and retries using LangChain runnable chains.

    Features:
    - ``with_retry()``: Exponential backoff with jitter on transient network / rate-limit errors.
    - ``with_fallbacks()``: Automatic ordered failover (Groq -> Mistral -> NVIDIA -> Gemini).
    - ``ChatPromptTemplate``: Centralized system prompt injection.
    - ``generate()``: Buffered response via ``.ainvoke()``.
    - ``stream_generate()``: Live token streaming via ``.astream()``.
    """

    def __init__(self, provider_engine: LLMs | None = None):
        self.provider_engine = provider_engine or default_llm

    def _is_mock_or_legacy(self) -> bool:
        """Detect mock objects in unit tests that supply get_fallback_chain."""
        return not isinstance(self.provider_engine, LLMs) and hasattr(self.provider_engine, "get_fallback_chain")

    def _build_pipeline(self):
        """Construct the LangChain runnable pipeline with retries and fallbacks."""
        models = self.provider_engine.get_models() if hasattr(self.provider_engine, "get_models") else []
        if not models:
            raise AllProvidersFailed("No LLM providers are configured.")

        # Wrap each model with LangChain's with_retry
        retryable_models = []
        for name, model in models:
            m_retry = model.with_retry(
                stop_after_attempt=_MAX_RETRIES + 1,
                wait_exponential_jitter=True,
                retry_if_exception_type=_RETRYABLE_EXCEPTIONS,
            )
            retryable_models.append((name, m_retry))

        primary_name, primary_model = retryable_models[0]
        fallbacks = [m for _, m in retryable_models[1:]]

        if fallbacks:
            chain = primary_model.with_fallbacks(
                fallbacks=fallbacks,
                exceptions_to_handle=(Exception,),
            )
        else:
            chain = primary_model

        prompt = ChatPromptTemplate.from_messages([
            ("system", KNOWLEDGE_SYSTEM_PROMPT),
            ("human", "{user_input}"),
        ])
        return prompt | chain

    async def generate(self, prompt: str) -> dict[str, str]:
        """Invoke the fallback chain (buffered). Returns {'answer': ..., 'provider': ...}."""
        # Check if caller passed a mock or custom engine with get_fallback_chain (e.g. in tests)
        if self._is_mock_or_legacy():
            chain = self.provider_engine.get_fallback_chain()
            if not chain:
                raise AllProvidersFailed("No LLM providers are configured.")
            failures: list[str] = []
            for provider_name, stream_function in chain:
                try:
                    collected: list[str] = []
                    stream = stream_function(prompt)
                    async for token in stream:
                        if token:
                            collected.append(token)
                    answer = "".join(collected).strip()
                    if not answer:
                        raise RuntimeError("Provider returned an empty response.")
                    return {"answer": answer, "provider": provider_name}
                except Exception as exc:
                    failures.append(f"{provider_name}: {exc}")
            raise AllProvidersFailed("All configured LLM providers failed. " + "; ".join(failures))

        pipeline = self._build_pipeline()
        try:
            response = await pipeline.ainvoke({"user_input": prompt})
            answer = str(response.content).strip()
            if not answer and hasattr(response, "additional_kwargs") and response.additional_kwargs.get("reasoning_content"):
                answer = str(response.additional_kwargs["reasoning_content"]).strip()

            if not answer:
                raise RuntimeError("Provider returned an empty response.")

            provider = _resolve_provider_name(getattr(response, "response_metadata", None))
            logger.info("LLM response generated by %s via LangChain", provider)
            return {
                "answer": answer,
                "provider": provider,
            }
        except Exception as exc:
            logger.exception("All configured LLM providers failed in LangChain chain: %s", exc)
            raise AllProvidersFailed(f"All configured LLM providers failed: {exc}") from exc

    async def stream_generate(
        self, prompt: str
    ) -> AsyncGenerator[tuple[str, str], None]:
        """Yield (token, provider_name) live as tokens arrive from LangChain stream."""
        # Check if caller passed a mock or custom engine with get_fallback_chain
        if self._is_mock_or_legacy():
            chain = self.provider_engine.get_fallback_chain()
            if not chain:
                raise AllProvidersFailed("No LLM providers are configured.")
            for provider_name, stream_function in chain:
                try:
                    token_emitted = False
                    stream = stream_function(prompt)
                    async for token in stream:
                        if token:
                            token_emitted = True
                            yield token, provider_name
                    if token_emitted:
                        return
                except Exception:
                    continue
            raise AllProvidersFailed("All configured LLM providers failed.")

        pipeline = self._build_pipeline()
        provider_name = "LLM"
        token_emitted = False
        reasoning_chunks: list[str] = []

        try:
            async for chunk in pipeline.astream({"user_input": prompt}):
                if chunk.response_metadata:
                    detected = _resolve_provider_name(chunk.response_metadata, default="")
                    if detected:
                        provider_name = detected

                reasoning = chunk.additional_kwargs.get("reasoning_content")
                if reasoning:
                    reasoning_chunks.append(str(reasoning))

                if chunk.content:
                    token_emitted = True
                    yield str(chunk.content), provider_name

            # If the model emitted reasoning tokens instead of direct content
            if not token_emitted and reasoning_chunks:
                fallback_text = "".join(reasoning_chunks).strip()
                if fallback_text:
                    token_emitted = True
                    yield fallback_text, provider_name

            if not token_emitted:
                raise RuntimeError("LLM stream completed without yielding any tokens.")

        except Exception as exc:
            logger.exception("LangChain streaming fallback chain failed: %s", exc)
            raise AllProvidersFailed(f"All configured LLM providers failed: {exc}") from exc


# Backward-compatible alias
LLMFallbackManager = LangChainFallbackManager
