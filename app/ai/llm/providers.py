"""LangChain chat-model provider configuration and orchestration."""
from __future__ import annotations

import json
import logging
from collections.abc import AsyncIterator

import httpx
from google import genai
from groq import AsyncGroq
try:
    from mistralai import Mistral
except ImportError:
    from mistralai.client import Mistral

from langchain_core.language_models.chat_models import BaseChatModel
from langchain_groq import ChatGroq
from langchain_google_genai import ChatGoogleGenerativeAI
from langchain_mistralai import ChatMistralAI
from langchain_openai import ChatOpenAI

from app.core.config import settings
from app.ai.prompts.gemini_prompt import KNOWLEDGE_SYSTEM_PROMPT as SYSTEM_PROMPT

logger = logging.getLogger(__name__)


def build_provider_models() -> list[tuple[str, BaseChatModel]]:
    """
    Return configured LangChain chat models in priority order:
    Groq -> Mistral -> NVIDIA NIM -> Gemini.
    """
    models: list[tuple[str, BaseChatModel]] = []

    if settings.groq_api_key:
        try:
            groq_llm = ChatGroq(
                groq_api_key=settings.groq_api_key,
                model_name=settings.groq_model,
                temperature=0.2,
            )
            models.append(("Groq", groq_llm))
        except Exception as exc:
            logger.warning("Failed to initialize ChatGroq: %s", exc)

    if settings.mistral_api_key:
        try:
            mistral_llm = ChatMistralAI(
                api_key=settings.mistral_api_key,
                model=settings.mistral_model,
                temperature=0.2,
            )
            models.append(("Mistral", mistral_llm))
        except Exception as exc:
            logger.warning("Failed to initialize ChatMistralAI: %s", exc)

    if settings.nvidia_api_key and settings.nvidia_api_key != "your_nvidia_api_key":
        try:
            nvidia_llm = ChatOpenAI(
                api_key=settings.nvidia_api_key,
                base_url="https://integrate.api.nvidia.com/v1",
                model=settings.nvidia_model,
                temperature=0.2,
            )
            models.append(("NVIDIA", nvidia_llm))
        except Exception as exc:
            logger.warning("Failed to initialize NVIDIA NIM ChatOpenAI: %s", exc)

    if settings.gemini_api_key:
        try:
            gemini_llm = ChatGoogleGenerativeAI(
                google_api_key=settings.gemini_api_key,
                model=settings.gemini_chat_model,
                temperature=0.2,
            )
            models.append(("Gemini", gemini_llm))
        except Exception as exc:
            logger.warning("Failed to initialize ChatGoogleGenerativeAI: %s", exc)

    return models


class LLMs:
    """Provides backward-compatible access to raw SDK clients and LangChain models."""

    def __init__(self):
        self.gemini_client = (
            genai.Client(api_key=settings.GEMINI_API_KEY)
            if settings.GEMINI_API_KEY
            else None
        )
        self.groq_client = (
            AsyncGroq(api_key=settings.GROQ_API_KEY)
            if settings.GROQ_API_KEY
            else None
        )
        try:
            self.mistral_client = (
                Mistral(
                    api_key=settings.MISTRAL_API_KEY,
                    client=httpx.Client(),
                    async_client=httpx.AsyncClient(),
                )
                if settings.MISTRAL_API_KEY
                else None
            )
        except Exception:
            self.mistral_client = None
        self.nvidia_api_key = settings.NVIDIA_API_KEY

    def get_models(self) -> list[tuple[str, BaseChatModel]]:
        return build_provider_models()

    async def stream_gemini(
        self, prompt: str, model_name: str | None = None
    ) -> AsyncIterator[str]:
        if not self.gemini_client:
            raise RuntimeError("Gemini API key is not configured.")
        model = model_name or settings.gemini_chat_model
        response = await self.gemini_client.aio.models.generate_content_stream(
            model=model,
            contents=prompt,
            config={"system_instruction": SYSTEM_PROMPT},
        )
        async for chunk in response:
            if chunk.text:
                yield chunk.text

    async def stream_groq(
        self, prompt: str, model_name: str | None = None
    ) -> AsyncIterator[str]:
        if not self.groq_client:
            raise RuntimeError("Groq API key is not configured.")
        model = model_name or settings.groq_model
        chat_completion = await self.groq_client.chat.completions.create(
            model=model,
            messages=[
                {"role": "system", "content": SYSTEM_PROMPT},
                {"role": "user", "content": prompt},
            ],
            stream=True,
            temperature=0.2,
        )
        async for chunk in chat_completion:
            if chunk.choices and chunk.choices[0].delta:
                content = chunk.choices[0].delta.content
                if content:
                    yield content

    async def stream_mistral(
        self, prompt: str, model_name: str | None = None
    ) -> AsyncIterator[str]:
        if not self.mistral_client:
            raise RuntimeError("Mistral API key is not configured.")
        model = model_name or settings.mistral_model
        response = await self.mistral_client.chat.stream_async(
            model=model,
            messages=[
                {"role": "system", "content": SYSTEM_PROMPT},
                {"role": "user", "content": prompt},
            ],
            temperature=0.2,
        )
        async for chunk in response:
            data = getattr(chunk, "data", chunk)
            if hasattr(data, "choices") and data.choices:
                content = data.choices[0].delta.content
                if content:
                    yield content

    async def stream_nvidia(
        self, prompt: str, model_name: str | None = None
    ) -> AsyncIterator[str]:
        if not self.nvidia_api_key:
            raise RuntimeError("NVIDIA API key is not configured.")
        model = model_name or settings.nvidia_model
        url = "https://integrate.api.nvidia.com/v1/chat/completions"
        headers = {
            "Authorization": f"Bearer {self.nvidia_api_key}",
            "Accept": "text/event-stream",
            "Content-Type": "application/json",
        }
        payload = {
            "model": model,
            "messages": [
                {"role": "system", "content": SYSTEM_PROMPT},
                {"role": "user", "content": prompt},
            ],
            "stream": True,
            "temperature": 0.2,
        }
        async with httpx.AsyncClient(timeout=60.0) as client:
            async with client.stream("POST", url, headers=headers, json=payload) as response:
                response.raise_for_status()
                async for line in response.aiter_lines():
                    if not line:
                        continue
                    if line.startswith("data: "):
                        raw_data = line[6:].strip()
                        if raw_data == "[DONE]":
                            break
                        try:
                            event = json.loads(raw_data)
                            choices = event.get("choices", [])
                            if choices:
                                delta = choices[0].get("delta", {})
                                content = delta.get("content")
                                if content:
                                    yield content
                        except json.JSONDecodeError:
                            continue

    def get_fallback_chain(self):
        chain = []
        if settings.groq_api_key:
            chain.append(("Groq", self.stream_groq))
        if settings.mistral_api_key:
            chain.append(("Mistral", self.stream_mistral))
        if settings.nvidia_api_key:
            chain.append(("NVIDIA", self.stream_nvidia))
        if settings.gemini_api_key:
            chain.append(("Gemini", self.stream_gemini))
        return chain


llm = LLMs()
