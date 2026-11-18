"""LLM provider package with backward-compatible exports."""
from .providers import LLMs, build_provider_models, llm
from .provider_config import ProviderConfig, build_provider_configs
from .model_factory import build_models_from_config, build_model_with_retry_and_fallback
from .retry_manager import build_retry_kwargs, RETRYABLE_EXCEPTIONS, is_retryable_error

__all__ = [
    # Existing (backward compat)
    "LLMs",
    "build_provider_models",
    "llm",
    # New
    "ProviderConfig",
    "build_provider_configs",
    "build_models_from_config",
    "build_model_with_retry_and_fallback",
    "build_retry_kwargs",
    "RETRYABLE_EXCEPTIONS",
    "is_retryable_error",
]
