import pytest
from unittest.mock import MagicMock

from app.ai.llm.fallback_manager import LLMFallbackManager, AllProvidersFailed


@pytest.mark.anyio
async def test_fallback_manager_uses_first_successful_provider():
    engine = MagicMock()
    calls = []

    async def fail(_prompt):
        calls.append("Groq")
        raise RuntimeError("429 quota exceeded")
        yield ""

    async def succeed(_prompt):
        calls.append("Mistral")
        yield "Mistral answer"

    engine.get_fallback_chain.return_value = [
        ("Groq", fail),
        ("Mistral", succeed),
    ]

    result = await LLMFallbackManager(engine).generate("Explain CVE")

    assert result == {"answer": "Mistral answer", "provider": "Mistral"}
    assert calls == ["Groq", "Mistral"]


@pytest.mark.anyio
async def test_fallback_manager_does_not_return_partial_failed_answer():
    engine = MagicMock()
    calls = []

    async def partial_then_fail(_prompt):
        calls.append("Groq")
        yield "partial answer"
        raise RuntimeError("stream disconnected")

    async def succeed(_prompt):
        calls.append("NVIDIA")
        yield "complete answer"

    engine.get_fallback_chain.return_value = [
        ("Groq", partial_then_fail),
        ("NVIDIA", succeed),
    ]

    result = await LLMFallbackManager(engine).generate("Explain malware")

    assert result["answer"] == "complete answer"
    assert result["provider"] == "NVIDIA"
    assert calls == ["Groq", "NVIDIA"]


@pytest.mark.anyio
async def test_fallback_manager_reports_when_all_providers_fail():
    engine = MagicMock()

    async def fail(_prompt):
        raise RuntimeError("provider down")
        yield ""

    engine.get_fallback_chain.return_value = [("Groq", fail)]

    with pytest.raises(AllProvidersFailed):
        await LLMFallbackManager(engine).generate("test")


@pytest.mark.anyio
async def test_fallback_manager_reports_when_no_provider_is_configured():
    engine = MagicMock()
    engine.get_fallback_chain.return_value = []

    with pytest.raises(AllProvidersFailed, match="No LLM providers"):
        await LLMFallbackManager(engine).generate("test")


def test_provider_priority_is_groq_mistral_nvidia_gemini(monkeypatch):
    from app.ai.llm import LLMs
    from app.core.config import settings

    monkeypatch.setattr(settings, "groq_api_key", "groq-test")
    monkeypatch.setattr(settings, "mistral_api_key", "mistral-test")
    monkeypatch.setattr(settings, "nvidia_api_key", "nvidia-test")
    monkeypatch.setattr(settings, "gemini_api_key", "gemini-test")

    engine = LLMs()
    chain = engine.get_fallback_chain()

    assert [name for name, _ in chain] == [
        "Groq", "Mistral", "NVIDIA", "Gemini"
    ]
