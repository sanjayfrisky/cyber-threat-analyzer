import json
import logging
from collections.abc import AsyncIterator
import httpx
from google import genai
from groq import AsyncGroq
try:
    from mistralai import Mistral
except ImportError:  # compatibility with older Mistral SDK releases
    from mistralai.client import Mistral

from app.core.config import settings
from app.ai.prompts.gemini_prompt import KNOWLEDGE_SYSTEM_PROMPT as SYSTEM_PROMPT

logger = logging.getLogger(__name__)

class LLMs:
    def __init__(self):
        # Initialize clients using API keys from configuration
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
        self.mistral_client = (
            Mistral(api_key=settings.MISTRAL_API_KEY)
            if settings.MISTRAL_API_KEY
            else None
        )
        self.nvidia_api_key = settings.NVIDIA_API_KEY

    async def stream_gemini(
        self, prompt: str, model_name: str | None = None
    ) -> AsyncIterator[str]:
        """
        Streams Google Gemini's response, yielding text pieces as they arrive.
        Any API errors are raised so that retry and fallback logic can handle them.
        """
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
        """
        Streams Groq's response, yielding text pieces as they arrive.
        Any API errors are raised so that retry and fallback logic can handle them.
        """
        if not self.groq_client:
            raise RuntimeError("Groq API key is not configured.")

        model = model_name or settings.groq_model
        chat_completion = await self.groq_client.chat.completions.create(
            model=model,
            messages=[
                {
                    "role": "system",
                    "content": SYSTEM_PROMPT,
                },
                {
                    "role": "user",
                    "content": prompt,
                },
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
        """
        Streams Mistral AI's response, yielding text pieces as they arrive.
        Any API errors are raised so that retry and fallback logic can handle them.
        """
        if not self.mistral_client:
            raise RuntimeError("Mistral API key is not configured.")

        model = model_name or settings.mistral_model
        response = await self.mistral_client.chat.stream_async(
            model=model,
            messages=[
                {
                    "role": "system",
                    "content": SYSTEM_PROMPT,
                },
                {
                    "role": "user",
                    "content": prompt,
                },
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
        """
        Streams NVIDIA NIM's response, yielding text pieces as they arrive.
        Any API errors are raised so that retry and fallback logic can handle them.
        """
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
                {
                    "role": "system",
                    "content": SYSTEM_PROMPT,
                },
                {
                    "role": "user",
                    "content": prompt,
                },
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
        """
        Return configured providers in the product's required priority order:
        Groq -> Mistral -> NVIDIA NIM -> Gemini.

        Gemini is also used by the embedding service in this project, so its
        API key is normally configured even when earlier chat providers work.
        """
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
