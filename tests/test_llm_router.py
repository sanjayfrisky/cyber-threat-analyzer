"""Unit tests for the LLM Router."""
import pytest
from unittest.mock import AsyncMock, MagicMock

from app.ai.router.llm_router import LLMRouter, RoutingDecision


def test_heuristic_route_cve_remediation():
    router = LLMRouter()
    decision = router.heuristic_route("How do I fix and patch CVE-2021-44228?")

    assert decision.intent == "cve_remediation"
    assert decision.needs_rag is True
    assert "CVE-2021-44228" in decision.rewritten_rag_query
    assert "cve_lookup" in decision.candidate_tools
    assert "get_remediation" in decision.candidate_tools


def test_heuristic_route_cve_exploitation():
    router = LLMRouter()
    decision = router.heuristic_route("Is CVE-2024-3400 actively exploited in the wild?")

    assert decision.intent == "cve_exploitation"
    assert "kev_lookup" in decision.candidate_tools
    assert "CVE-2024-3400" in decision.rewritten_rag_query


def test_heuristic_route_command_analysis():
    router = LLMRouter()
    decision = router.heuristic_route("Explain powershell -enc aQB3AHIAbwB1AHQA")

    assert decision.intent == "command_analysis"
    assert "analyze_command" in decision.candidate_tools


def test_heuristic_route_mitre_analysis():
    router = LLMRouter()
    decision = router.heuristic_route("What is technique T1059.001?")

    assert decision.intent == "mitre_analysis"
    assert "T1059.001" in decision.rewritten_rag_query
    assert "mitre_lookup" in decision.candidate_tools


def test_heuristic_route_general_rag():
    router = LLMRouter()
    decision = router.heuristic_route("What are the fundamentals of defense in depth?")

    assert decision.intent == "general_rag"
    assert decision.needs_rag is True
    assert "rag_retrieve" in decision.candidate_tools


@pytest.mark.anyio
async def test_llm_route_with_mock():
    mock_llm = MagicMock()
    mock_llm.ainvoke = AsyncMock(
        return_value=MagicMock(
            content='{"intent": "cve_remediation", "needs_rag": true, "rewritten_rag_query": "CVE-2021-44228 patch", "candidate_tools": ["cve_lookup", "get_remediation"], "reasoning": "User asked to patch Log4Shell"}'
        )
    )

    router = LLMRouter(llm=mock_llm)
    decision = await router.route("Remediate CVE-2021-44228")

    assert decision.intent == "cve_remediation"
    assert "cve_lookup" in decision.candidate_tools
    assert "get_remediation" in decision.candidate_tools
    assert "CVE-2021-44228 patch" in decision.rewritten_rag_query
