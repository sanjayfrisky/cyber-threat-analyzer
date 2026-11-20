"""Unit tests for the Single-Step PipelineOrchestrator."""
import json
import pytest
from unittest.mock import AsyncMock, MagicMock, patch

from app.ai.router.pipeline_orchestrator import PipelineOrchestrator
from app.ai.router.llm_router import RoutingDecision


@pytest.mark.anyio
async def test_pipeline_orchestrator_rag_branch():
    mock_router = MagicMock()
    mock_router.route = AsyncMock(
        return_value=RoutingDecision(
            destination="rag",
            rag_query="defense in depth concepts",
            intent="general_rag",
            reasoning="Broad conceptual question",
        )
    )

    mock_rag = MagicMock()
    mock_rag.retrieve.return_value = [
        {
            "source": "NVD",
            "external_id": "CVE-2021-44228",
            "title": "Log4Shell",
            "url": "https://nvd.nist.gov/vuln/detail/CVE-2021-44228",
            "content": "Defense in depth involves layered controls.",
        }
    ]

    mock_llm = MagicMock()
    mock_llm.ainvoke = AsyncMock(
        return_value=MagicMock(content="Layered security is essential [S1].")
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
        async for sse in orchestrator.stream_execute("Explain defense in depth", "test-session"):
            events_raw.append(sse)

        events = [json.loads(line.replace("data: ", "")) for line in events_raw if line.startswith("data: ")]

        types = [e["type"] for e in events]
        assert "routing" in types
        assert "sources" in types
        assert "chunk" in types
        assert "done" in types

        routing_evt = next(e for e in events if e["type"] == "routing")
        assert routing_evt["destination"] == "rag"

        sources_evt = next(e for e in events if e["type"] == "sources")
        assert len(sources_evt["sources"]) == 1

        chunks = [e["text"] for e in events if e["type"] == "chunk"]
        assert "Layered security" in "".join(chunks)


@pytest.mark.anyio
async def test_pipeline_orchestrator_tool_branch():
    mock_router = MagicMock()
    mock_router.route = AsyncMock(
        return_value=RoutingDecision(
            destination="tool",
            selected_tool="analyze_command",
            tool_args={"command": "powershell -enc JAB3AGM="},
            intent="command_analysis",
            reasoning="Suspicious command pattern",
        )
    )

    mock_llm = MagicMock()
    mock_llm.ainvoke = AsyncMock(
        return_value=MagicMock(content="The command executes obfuscated code.")
    )

    with patch("app.ai.router.pipeline_orchestrator.SessionLocal") as mock_session_local:
        mock_db = MagicMock()
        mock_session_local.return_value = mock_db

        orchestrator = PipelineOrchestrator(
            router=mock_router,
            llm=mock_llm,
        )

        events_raw = []
        async for sse in orchestrator.stream_execute("powershell -enc JAB3AGM=", "test-session-cmd"):
            events_raw.append(sse)

        events = [json.loads(line.replace("data: ", "")) for line in events_raw if line.startswith("data: ")]

        types = [e["type"] for e in events]
        assert "routing" in types
        assert "tool_executed" in types
        assert "chunk" in types
        assert "done" in types

        tool_evt = next(e for e in events if e["type"] == "tool_executed")
        assert tool_evt["tool"] == "analyze_command"

        done_evt = next(e for e in events if e["type"] == "done")
        assert done_evt["tool_used"] == "analyze_command"
