import asyncio
import json
from unittest.mock import AsyncMock, MagicMock, patch
import pytest
from pydantic import ValidationError
from fastapi.responses import StreamingResponse

from app.routes.chat import router, chat
from app.ai.models import ChatRequest
from app.ai.chat import ChatService

def test_chat_route_returns_streaming_response():
    mock_service = MagicMock()

    async def mock_stream(*args, **kwargs):
        yield 'data: {"type": "sources", "sources": []}\n\n'
        yield 'data: {"type": "chunk", "text": "Analyzing threat..."}\n\n'
        yield 'data: {"type": "done", "session_id": "test-1"}\n\n'

    mock_service.stream_answer = mock_stream

    with patch("app.routes.chat.chat_service", mock_service):
        req = ChatRequest(prompt="What is CVE-2023-34362?", session_id="test-1")
        resp = chat(req)

        assert isinstance(resp, StreamingResponse)
        assert resp.status_code == 200
        assert resp.media_type == "text/event-stream"
        assert resp.headers["Cache-Control"] == "no-cache"
        assert resp.headers["Connection"] == "keep-alive"

@pytest.mark.anyio
async def test_chat_service_stream_answer_with_retrieval():
    mock_chunks = [
        MagicMock(text="Data "),
        MagicMock(text="encrypted "),
        MagicMock(text="for impact.")
    ]

    with patch("app.ai.chat.SessionLocal") as mock_session_local, \
         patch("app.ai.chat.RAGPipeline.retrieve") as mock_retrieve:

        mock_db = MagicMock()
        mock_session_local.return_value = mock_db

        mock_retrieve.return_value = [
            {
                "source": "MITRE_ATTACK",
                "external_id": "MITRE-T1486",
                "title": "Data Encrypted for Impact",
                "url": "https://attack.mitre.org/techniques/T1486/",
                "content": "Adversaries may encrypt data on target systems..."
            }
        ]

        mock_llm = MagicMock()
        async def mock_provider_stream(prompt):
            for c in mock_chunks:
                yield c.text

        mock_llm.get_fallback_chain.return_value = [("Gemini", mock_provider_stream)]

        svc = ChatService(llm_engine=mock_llm)
        events_raw = []
        async for line in svc.stream_answer("Explain T1486", "test-session-1"):
            events_raw.append(line)

        events = [json.loads(line.replace("data: ", "")) for line in events_raw if line.startswith("data: ")]

        # Verify sources event is first
        assert events[0]["type"] == "sources"
        assert len(events[0]["sources"]) == 1
        assert events[0]["sources"][0]["id"] == "MITRE-T1486"

        # Verify chunk events
        chunk_texts = [e["text"] for e in events if e.get("type") == "chunk"]
        assert "".join(chunk_texts) == "Data encrypted for impact."

        # Verify done event
        assert events[-1]["type"] == "done"
        assert events[-1]["session_id"] == "test-session-1"

        # Verify database message persistence
        assert mock_db.add_all.called
        assert mock_db.commit.called
        assert mock_db.close.called

@pytest.mark.anyio
async def test_chat_service_stream_answer_fallback_when_empty():
    with patch("app.ai.chat.SessionLocal") as mock_session_local, \
         patch("app.ai.chat.RAGPipeline.retrieve") as mock_retrieve, \
         patch("app.ai.llm.fallback_manager.LLMFallbackManager.generate", new_callable=AsyncMock) as mock_generate:

        mock_db = MagicMock()
        mock_session_local.return_value = mock_db
        mock_retrieve.return_value = []
        mock_generate.return_value = {
            "answer": "Malware is software designed to harm or misuse systems.",
            "provider": "Groq",
        }

        svc = ChatService()
        events_raw = []
        async for line in svc.stream_answer("Unknown indicator", "session-empty"):
            events_raw.append(line)

        events = [json.loads(line.replace("data: ", "")) for line in events_raw if line.startswith("data: ")]

        assert events[0]["type"] == "sources"
        assert len(events[0]["sources"]) == 0

        # The chatbot still answers general questions when retrieval is empty.
        chunk_texts = [e["text"] for e in events if e.get("type") == "chunk"]
        assert "".join(chunk_texts).startswith("Malware is software")

        assert events[-1]["type"] == "done"
        assert events[-1]["provider"] == "Groq"
        mock_generate.assert_awaited_once()
        assert mock_db.commit.called

def test_chat_request_valid():
    req = ChatRequest(prompt="Direct prompt")
    assert req.prompt == "Direct prompt"
    assert req.session_id == "default-session"

def test_chat_request_validation():
    with pytest.raises(ValidationError):
        ChatRequest(prompt="")

def test_routes_chat_contains_only_chat_endpoint():
    # Verify routes registered on router
    route_paths = [r.path for r in router.routes]
    assert "/chat" in route_paths
    assert len(route_paths) == 1, f"Expected only 1 endpoint on routes/chat, found: {route_paths}"

    # Verify old endpoints are removed
    assert "/health" not in route_paths
    assert "/ingestion/run" not in route_paths
    assert "/ingestion/status" not in route_paths
    assert "/incident/analyze" not in route_paths
