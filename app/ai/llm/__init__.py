"""LLM provider package with backward-compatible exports."""
from .providers import LLMs

# Shared provider clients avoid recreating network clients on every request.
llm = LLMs()

__all__ = ["LLMs", "llm"]
