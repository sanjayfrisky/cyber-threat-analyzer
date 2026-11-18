"""
Model factory: builds typed LangChain BaseChatModel instances from ProviderConfig.

This module wraps the existing providers.py without replacing it.
It is the single source of truth for constructing LangChain models in the
agent layer.  The existing LLMs class and build_provider_models() remain
untouched for backward compatibility with the streaming chat service.
"""
from __future__ import annotations

import logging

from langchain_core.language_models.chat_models import BaseChatModel

from app.ai.llm.provider_config import ProviderConfig, build_provider_configs
from app.ai.llm.retry_manager import build_retry_kwargs

logger = logging.getLogger(__name__)


def _build_single_model(config: ProviderConfig) -> BaseChatModel | None:
    """Instantiate and return a LangChain chat model for the given config."""
    try:
        if config.name == "Groq":
            from langchain_groq import ChatGroq
            return ChatGroq(
                groq_api_key=config.api_key,
                model_name=config.model,
                temperature=config.temperature,
            )

        if config.name == "Mistral":
            from langchain_mistralai import ChatMistralAI
            return ChatMistralAI(
                api_key=config.api_key,
                model=config.model,
                temperature=config.temperature,
            )

        if config.name == "NVIDIA":
            from langchain_openai import ChatOpenAI
            return ChatOpenAI(
                api_key=config.api_key,
                base_url="https://integrate.api.nvidia.com/v1",
                model=config.model,
                temperature=config.temperature,
            )

        if config.name == "Gemini":
            from langchain_google_genai import ChatGoogleGenerativeAI
            return ChatGoogleGenerativeAI(
                google_api_key=config.api_key,
                model=config.model,
                temperature=config.temperature,
            )

    except Exception as exc:
        logger.warning("Failed to build model for provider %s: %s", config.name, exc)
    return None


def build_models_from_config(
    configs: list[ProviderConfig] | None = None,
) -> list[tuple[str, BaseChatModel]]:
    """
    Build LangChain models in priority order (Groq → Mistral → NVIDIA → Gemini).

    Returns list of (provider_name, model) tuples.
    Only returns successfully initialised models.
    """
    if configs is None:
        configs = build_provider_configs()

    result: list[tuple[str, BaseChatModel]] = []
    for cfg in configs:
        if not cfg.is_available():
            logger.debug("Skipping unavailable provider: %s", cfg.name)
            continue
        model = _build_single_model(cfg)
        if model is not None:
            result.append((cfg.name, model))
            logger.debug("Registered LangChain model: %s (%s)", cfg.name, cfg.model)

    return result


def build_model_with_retry_and_fallback(
    configs: list[ProviderConfig] | None = None,
) -> BaseChatModel:
    """
    Convenience helper used by the agent layer.

    Returns a single runnable that chains: primary.with_retry().with_fallbacks([...]).
    Raises RuntimeError when no providers are available.
    """
    models = build_models_from_config(configs)
    if not models:
        raise RuntimeError(
            "No LLM providers are configured. "
            "Set at least one API key (GROQ_API_KEY, MISTRAL_API_KEY, GEMINI_API_KEY)."
        )

    retry_kwargs = build_retry_kwargs()

    retryable = [(name, m.with_retry(**retry_kwargs)) for name, m in models]
    primary_name, primary = retryable[0]
    fallbacks = [m for _, m in retryable[1:]]

    if fallbacks:
        chain = primary.with_fallbacks(
            fallbacks=fallbacks,
            exceptions_to_handle=(Exception,),
        )
    else:
        chain = primary

    logger.info(
        "Agent LLM chain: primary=%s, fallbacks=%s",
        primary_name,
        [name for name, _ in retryable[1:]],
    )
    return chain
