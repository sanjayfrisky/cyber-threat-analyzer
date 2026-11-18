"""
Retry configuration constants and factory for LangChain with_retry().

Extracted from fallback_manager.py so both the streaming chat service and
the new agent layer share identical retry behaviour.

Usage:
    model.with_retry(**build_retry_kwargs())
"""
from __future__ import annotations

import asyncio
import logging

import httpx

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Transient exceptions that are worth retrying.
# Auth errors (401, 403) and bad requests are NOT listed here — they will
# propagate immediately without retrying (avoid wasting quota).
# ---------------------------------------------------------------------------
RETRYABLE_EXCEPTIONS: tuple[type[Exception], ...] = (
    httpx.HTTPStatusError,     # Covers 429 rate-limit and 5xx server errors
    httpx.TimeoutException,
    httpx.ConnectError,
    asyncio.TimeoutError,
    ConnectionResetError,
    TimeoutError,
)

#: Maximum number of *additional* attempts after the first one.
#: Total attempts = MAX_ADDITIONAL_RETRIES + 1
MAX_ADDITIONAL_RETRIES: int = 2


def build_retry_kwargs(max_additional: int = MAX_ADDITIONAL_RETRIES) -> dict:
    """
    Return kwargs suitable for model.with_retry(**build_retry_kwargs()).

    Args:
        max_additional: Extra retries beyond the first attempt (default 2 → 3 total).

    Returns:
        dict with stop_after_attempt, wait_exponential_jitter, retry_if_exception_type.
    """
    return {
        "stop_after_attempt": max_additional + 1,
        "wait_exponential_jitter": True,
        "retry_if_exception_type": RETRYABLE_EXCEPTIONS,
    }


def is_retryable_error(exc: Exception) -> bool:
    """
    Return True when the exception is a transient, retriable error.

    Convenience helper for custom retry loops outside LangChain (e.g., tool
    timeouts handled manually).
    """
    if isinstance(exc, RETRYABLE_EXCEPTIONS):
        return True
    # Treat HTTP 429 / 5xx status codes embedded in exception messages
    msg = str(exc).lower()
    return any(indicator in msg for indicator in ("429", "rate limit", "503", "502", "timeout"))


def is_permanent_error(exc: Exception) -> bool:
    """
    Return True for errors that should NOT be retried at any level.

    Examples: 401 Unauthorized, 403 Forbidden, unsupported model names,
    invalid API key format, Pydantic validation errors.
    """
    if isinstance(exc, (ValueError, TypeError)):
        return True
    msg = str(exc).lower()
    return any(indicator in msg for indicator in ("401", "403", "unauthorized", "forbidden", "invalid api key"))
