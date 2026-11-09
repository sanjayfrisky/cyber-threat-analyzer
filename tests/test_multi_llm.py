import json
import pytest
from unittest.mock import AsyncMock, MagicMock, patch

from app.ai.chat import ChatService
from app.ai.llm import LLMs


@pytest.mark.anyio
async def test_retry_with_jitter_success():
    call_count = 0

    async def flaky_fn():
        nonlocal call_count
        call_count += 1
        if call_count < 3:
            raise ValueError("Temporary failure")
        return "success"

    with patch("asyncio.sleep", new_callable=AsyncMock) as mock_sleep:
        res = await ChatService.retry_with_jitter(flaky_fn, max_retries=3, base_delay=0.1)
        assert res == "success"
        assert call_count == 3
        assert mock_sleep.call_count == 2


@pytest.mark.anyio
async def test_retry_with_jitter_exceeds_max_retries():
    async def always_fails():
        raise RuntimeError("Persistent error")

    with patch("asyncio.sleep", new_callable=AsyncMock):
        with pytest.raises(RuntimeError, match="Persistent error"):
            await ChatService.retry_with_jitter(always_fails, max_retries=2, base_delay=0.1)


@pytest.mark.anyio
async def test_stream_gemini_success():
    llm = LLMs()
    mock_client = MagicMock()

    async def fake_stream():
        chunk1 = MagicMock()
        chunk1.text = "Hello "
        chunk2 = MagicMock()
        chunk2.text = "Gemini!"
        for c in [chunk1, chunk2]:
            yield c

    mock_client.aio.models.generate_content_stream = AsyncMock(return_value=fake_stream())
    llm.gemini_client = mock_client

    tokens = []
    async for token in llm.stream_gemini("test prompt"):
        tokens.append(token)

    assert "".join(tokens) == "Hello Gemini!"


@pytest.mark.anyio
async def test_stream_groq_success():
    llm = LLMs()
    mock_client = MagicMock()

    class Chunk:
        def __init__(self, content):
            delta = MagicMock()
            delta.content = content
            choice = MagicMock()
            choice.delta = delta
            self.choices = [choice]

    async def fake_groq_stream():
        for text in ["Hello ", "from ", "Groq!"]:
            yield Chunk(text)

    mock_client.chat.completions.create = AsyncMock(return_value=fake_groq_stream())
    llm.groq_client = mock_client

    tokens = []
    async for token in llm.stream_groq("test prompt"):
        tokens.append(token)

    assert "".join(tokens) == "Hello from Groq!"


@pytest.mark.anyio
async def test_stream_mistral_success():
    llm = LLMs()
    mock_client = MagicMock()

    class MistralChunk:
        def __init__(self, content):
            delta = MagicMock()
            delta.content = content
            choice = MagicMock()
            choice.delta = delta
            self.choices = [choice]

    async def fake_mistral_stream():
        for text in ["Mistral ", "threat ", "intelligence"]:
            yield MistralChunk(text)

    mock_client.chat.stream_async = AsyncMock(return_value=fake_mistral_stream())
    llm.mistral_client = mock_client

    tokens = []
    async for token in llm.stream_mistral("test prompt"):
        tokens.append(token)

    assert "".join(tokens) == "Mistral threat intelligence"


@pytest.mark.anyio
async def test_stream_nvidia_success():
    llm = LLMs()
    llm.nvidia_api_key = "fake-nv-key"

    sse_lines = [
        "",
        'data: {"choices": [{"delta": {"content": "NVIDIA "}}]}',
        'data: {"choices": [{"delta": {"content": "NIM "}}]}',
        'data: {"choices": [{"delta": {"content": "Response"}}]}',
        "data: [DONE]",
    ]

    class FakeResponse:
        def raise_for_status(self):
            pass

        async def aiter_lines(self):
            for line in sse_lines:
                yield line

    class FakeAsyncClient:
        def __init__(self, *args, **kwargs):
            pass

        async def __aenter__(self):
            return self

        async def __aexit__(self, exc_type, exc_val, exc_tb):
            pass

        def stream(self, method, url, **kwargs):
            class StreamCtx:
                async def __aenter__(self_ctx):
                    return FakeResponse()

                async def __aexit__(self_ctx, exc_type, exc_val, exc_tb):
                    pass

            return StreamCtx()

    with patch("httpx.AsyncClient", FakeAsyncClient):
        tokens = []
        async for token in llm.stream_nvidia("test prompt"):
            tokens.append(token)

        assert "".join(tokens) == "NVIDIA NIM Response"


@pytest.mark.anyio
async def test_fallback_chain_failover_in_chat():
    mock_rag = MagicMock()
    mock_rag.retrieve.return_value = [
        {
            "external_id": "CVE-2024-9999",
            "source": "NVD",
            "title": "Critical RCE",
            "content": "A remote code execution vulnerability was identified.",
            "url": "https://nvd.nist.gov/vuln/detail/CVE-2024-9999",
        }
    ]

    mock_llm = MagicMock()

    async def failing_groq(prompt):
        raise RuntimeError("Groq Rate Limited (429)")
        yield ""  # generator

    async def succeeding_gemini(prompt):
        for part in ["Patched ", "in ", "v1.2.0"]:
            yield part

    mock_llm.get_fallback_chain.return_value = [
        ("Groq (OpenAI/OSS)", failing_groq),
        ("Gemini (Google)", succeeding_gemini),
    ]

    with patch("app.ai.chat.SessionLocal"):
        chat_svc = ChatService(rag=mock_rag, llm_engine=mock_llm)
        tokens = []
        async for token in chat_svc.chat("What is CVE-2024-9999?"):
            tokens.append(token)

        assert "".join(tokens) == "Patched in v1.2.0"
        # Confirm RAG was called
        assert mock_rag.retrieve.called

