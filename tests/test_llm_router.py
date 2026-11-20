"""Unit tests for the Single-Step LLM Router."""
import pytest
from unittest.mock import AsyncMock, MagicMock

from app.ai.router.llm_router import LLMRouter, RoutingDecision


def test_heuristic_route_cve_remediation():
    router = LLMRouter()
    decision = router.heuristic_route("How do I fix and patch CVE-2021-44228?")

    assert decision.destination == "tool"
    assert decision.selected_tool == "get_remediation"
    assert decision.intent == "cve_remediation"
    assert decision.tool_args.get("cve_id") == "CVE-2021-44228"


def test_heuristic_route_cve_exploitation():
    router = LLMRouter()
    decision = router.heuristic_route("Is CVE-2024-3400 actively exploited in the wild?")

    assert decision.destination == "tool"
    assert decision.selected_tool == "kev_lookup"
    assert decision.intent == "cve_exploitation"
    assert decision.tool_args.get("cve_id") == "CVE-2024-3400"


def test_heuristic_route_command_analysis():
    router = LLMRouter()
    decision = router.heuristic_route("Explain powershell -enc aQB3AHIAbwB1AHQA")

    assert decision.destination == "tool"
    assert decision.selected_tool == "analyze_command"
    assert decision.intent == "command_analysis"


def test_heuristic_route_mitre_analysis():
    router = LLMRouter()
    decision = router.heuristic_route("What is technique T1059.001?")

    assert decision.destination == "tool"
    assert decision.selected_tool == "mitre_lookup"
    assert decision.intent == "mitre_analysis"


def test_heuristic_route_general_rag():
    router = LLMRouter()
    decision = router.heuristic_route("What are the fundamentals of defense in depth?")

    assert decision.destination == "rag"
    assert decision.intent == "general_rag"
    assert "rag_retrieve" in decision.candidate_tools


@pytest.mark.anyio
async def test_llm_route_with_mock():
    mock_llm = MagicMock()
    mock_llm.ainvoke = AsyncMock(
        return_value=MagicMock(
            content='{"destination": "tool", "selected_tool": "get_remediation", "tool_args": {"cve_id": "CVE-2021-44228"}, "intent": "cve_remediation", "reasoning": "User asked to patch Log4Shell"}'
        )
    )

    router = LLMRouter(llm=mock_llm)
    decision = await router.route("Remediate CVE-2021-44228")

    assert decision.destination == "tool"
    assert decision.selected_tool == "get_remediation"
    assert decision.tool_args.get("cve_id") == "CVE-2021-44228"
