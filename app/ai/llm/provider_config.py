"""Pydantic-based provider configuration models for LangChain LLM management."""
from __future__ import annotations

import logging
from typing import Literal

from pydantic import BaseModel, Field, ConfigDict

from app.core.config import settings

logger = logging.getLogger(__name__)

ProviderName = Literal["Groq", "Mistral", "NVIDIA", "Gemini"]


class ProviderConfig(BaseModel):
    """Configuration for a single LLM provider."""

    model_config = ConfigDict(frozen=True)

    name: ProviderName
    api_key: str
    model: str
    temperature: float = Field(default=0.2, ge=0.0, le=2.0)
    max_tokens: int = Field(default=4096, ge=1)
    timeout_seconds: int = Field(default=30, ge=1)
    enabled: bool = True

    def is_available(self) -> bool:
        """Return True only when the API key looks like a real credential."""
        return (
            self.enabled
            and bool(self.api_key)
            and self.api_key not in {"your_nvidia_api_key", "your_groq_api_key", "your_mistral_api_key"}
        )


def _temperature() -> float:
    return getattr(settings, "llm_temperature", 0.2)


def _max_tokens() -> int:
    return getattr(settings, "llm_max_tokens", 4096)


def _timeout() -> int:
    return getattr(settings, "llm_timeout_seconds", 30)


def build_provider_configs() -> list[ProviderConfig]:
    """
    Build an ordered list of ProviderConfig from application settings.
    Priority: Groq → Mistral → NVIDIA → Gemini.
    Only includes providers whose API keys are set and appear valid.
    """
    temp = _temperature()
    max_tok = _max_tokens()
    timeout = _timeout()

    candidates: list[ProviderConfig] = []

    if settings.groq_api_key:
        candidates.append(
            ProviderConfig(
                name="Groq",
                api_key=settings.groq_api_key,
                model=settings.groq_model,
                temperature=temp,
                max_tokens=max_tok,
                timeout_seconds=timeout,
            )
        )

    if settings.mistral_api_key:
        candidates.append(
            ProviderConfig(
                name="Mistral",
                api_key=settings.mistral_api_key,
                model=settings.mistral_model,
                temperature=temp,
                max_tokens=max_tok,
                timeout_seconds=timeout,
            )
        )

    nvidia_key = settings.nvidia_api_key or ""
    if nvidia_key and nvidia_key != "your_nvidia_api_key":
        candidates.append(
            ProviderConfig(
                name="NVIDIA",
                api_key=nvidia_key,
                model=settings.nvidia_model,
                temperature=temp,
                max_tokens=max_tok,
                timeout_seconds=timeout,
            )
        )

    if settings.gemini_api_key:
        candidates.append(
            ProviderConfig(
                name="Gemini",
                api_key=settings.gemini_api_key,
                model=settings.gemini_chat_model,
                temperature=temp,
                max_tokens=max_tok,
                timeout_seconds=timeout,
            )
        )

    available = [c for c in candidates if c.is_available()]
    if not available:
        logger.warning(
            "No LLM providers have valid API keys. "
            "Set at least one of GROQ_API_KEY, MISTRAL_API_KEY, GEMINI_API_KEY in .env."
        )
    else:
        logger.info(
            "LLM providers configured: %s",
            [c.name for c in available],
        )
    return available
