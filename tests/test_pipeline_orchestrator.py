"""Unit tests for the PipelineOrchestrator."""
import json
import pytest
from unittest.mock import AsyncMock, MagicMock, patch

from app.ai.router.pipeline_orchestrator import PipelineOrchestrator
from app.ai.router.llm_router import LLMRouter, RoutingDecision


@pytest.mark.anyio
async def test_pipeline_orchestrator_stream_flow():
    mock_router = MagicMock()
    mock_router.route = AsyncMock(
        return_value=RoutingDecision(
            intent="cve_remediation",
            needs_rag=True,
            rewritten_rag_query="CVE-2021-44228 patch",
            candidate_tools=["cve_lookup"],
            reasoning="Test reasoning",
        )
    )

    mock_rag = MagicMock()
    mock_rag.retrieve.return_value = [
        {
            "source": "NVD",
            "external_id": "CVE-2021-44228",
            "title": "Log4Shell",
            "url": "https://nvd.nist.gov/vuln/detail/CVE-2021-44228",
            "content": "Apache Log4j2 JNDI vulnerability.",
        }
    ]

    mock_llm = MagicMock()
    mock_llm.bind_tools.return_value = mock_llm
    mock_llm.ainvoke = AsyncMock(
        return_value=MagicMock(
            content="Upgrade Log4j to version 2.17.1 to mitigate CVE-2021-44228 [S1].",
            tool_calls=[],
        )
    )

    with patch("app.ai.router.pipeline_orchestrator.SessionLocal") as mock_session_local:
        mock_db = MagicMock()
        mock_session_local.return_value = mock_db

        orchestrator = PipelineOrchestrator(
            router=mock_router,
            rag=mock_rag,
            llm=mock_llm,
        )

        events_raw = []
        async for sse in orchestrator.stream_execute("Explain CVE-2021-44228", "test-session"):
            events_raw.append(sse)

        events = [json.loads(line.replace("data: ", "")) for line in events_raw if line.startswith("data: ")]

        # Check event sequence
        types = [e["type"] for e in events]
        assert "routing" in types
        assert "sources" in types
        assert "chunk" in types
        assert "done" in types

        # Check routing event content
        routing_evt = next(e for e in events if e["type"] == "routing")
        assert routing_evt["intent"] == "cve_remediation"
        assert routing_evt["rewritten_query"] == "CVE-2021-44228 patch"

        # Check sources event content
        sources_evt = next(e for e in events if e["type"] == "sources")
        assert len(sources_evt["sources"]) == 1
        assert sources_evt["sources"][0]["id"] == "CVE-2021-44228"

        # Check chunk content
        chunks = [e["text"] for e in events if e["type"] == "chunk"]
        full_text = "".join(chunks)
        assert "2.17.1" in full_text
