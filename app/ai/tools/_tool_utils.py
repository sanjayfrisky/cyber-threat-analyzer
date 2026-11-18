"""Tool shared utilities: timeouts, logging, DB session factory, safe error wrapper."""
from __future__ import annotations

import asyncio
import functools
import logging
import time
from typing import Any, Callable

from app.db.database import SessionLocal

logger = logging.getLogger(__name__)

TOOL_DEFAULT_TIMEOUT: float = 15.0  # seconds


def timed_tool(func: Callable) -> Callable:
    """
    Decorator that:
    - Logs tool entry and exit
    - Records wall-clock execution time
    - Catches and sanitises exceptions (strips API keys from messages)
    """
    @functools.wraps(func)
    def wrapper(*args, **kwargs):
        tool_name = func.__name__
        t0 = time.perf_counter()
        logger.info("[tool] %s called | args=%s kwargs=%s", tool_name, args, list(kwargs.keys()))
        try:
            result = func(*args, **kwargs)
            elapsed_ms = (time.perf_counter() - t0) * 1000
            logger.info("[tool] %s succeeded in %.1f ms", tool_name, elapsed_ms)
            return result
        except Exception as exc:
            elapsed_ms = (time.perf_counter() - t0) * 1000
            safe_msg = _sanitise_error(str(exc))
            logger.error("[tool] %s failed after %.1f ms: %s", tool_name, elapsed_ms, safe_msg)
            raise RuntimeError(safe_msg) from exc

    return wrapper


def _sanitise_error(message: str) -> str:
    """Remove any potential API keys or secrets from error messages."""
    # Heuristic: redact long alphanumeric tokens that look like keys (> 20 chars, no spaces)
    import re
    return re.sub(r"\b[A-Za-z0-9_\-]{20,}\b", "[REDACTED]", message)


def get_db_session():
    """Return a new SQLAlchemy session. Caller is responsible for closing."""
    return SessionLocal()


def run_with_timeout(func: Callable, *args, timeout: float = TOOL_DEFAULT_TIMEOUT, **kwargs) -> Any:
    """
    Run a synchronous callable with a wall-clock timeout using a thread pool.
    Raises asyncio.TimeoutError when the limit is exceeded.
    """
    import concurrent.futures
    with concurrent.futures.ThreadPoolExecutor(max_workers=1) as pool:
        future = pool.submit(func, *args, **kwargs)
        try:
            return future.result(timeout=timeout)
        except concurrent.futures.TimeoutError:
            raise asyncio.TimeoutError(f"Tool timed out after {timeout}s")
