"""FastAPI router exposing all 10 cybersecurity tools via dedicated REST endpoints and dynamic dispatch."""
from __future__ import annotations

import logging
from typing import Any

from fastapi import APIRouter, HTTPException
from pydantic import BaseModel, Field

from app.ai.agent.tool_registry import registry
from app.ai.tools import (
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

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/tools", tags=["Cybersecurity Tools"])


# ---------------------------------------------------------------------------
# Request Schemas
# ---------------------------------------------------------------------------
class DynamicExecuteRequest(BaseModel):
    tool_name: str = Field(..., description="Name of the registered tool to invoke")
    arguments: dict[str, Any] = Field(default_factory=dict, description="Arguments to pass to the tool")


class CVELookupRequest(BaseModel):
    cve_id: str = Field(..., description="CVE ID, e.g. CVE-2021-44228")


class KEVLookupRequest(BaseModel):
    cve_id: str = Field(..., description="CVE ID to check in CISA KEV")


class MitreLookupRequest(BaseModel):
    query: str = Field(..., description="Technique ID (e.g. T1059.001) or search term")


class RAGRetrieveRequest(BaseModel):
    query: str = Field(..., description="Cybersecurity search query")
    top_k: int = Field(default=6, ge=1, le=20, description="Number of results to retrieve")


class CVSSAnalysisRequest(BaseModel):
    cvss_vector_or_score: str = Field(..., description="CVSS vector string or numeric score")


class IOCExtractionRequest(BaseModel):
    text: str = Field(..., description="Raw text or log excerpt to extract IOCs from")


class CommandAnalysisRequest(BaseModel):
    command: str = Field(..., description="PowerShell, Bash, or CMD command to analyze for malicious patterns")


class ScreenFileRequest(BaseModel):
    filename: str = Field(default="evidence.txt", description="Name of the file being screened")
    content: str = Field(..., description="File content to inspect for threats or embedded attacks")
    declared_type: str = Field(default="text", description="File type or MIME category")


class RemediationRequest(BaseModel):
    cve_id: str = Field(..., description="CVE identifier")
    remediation_query: str = Field(default="", description="Specific remediation context or environment")


class ThreatIntelRequest(BaseModel):
    query: str = Field(..., description="Indicator or threat query")
    ioc_type: str = Field(default="auto", description="Type of indicator: ip, domain, hash, or auto")


# ---------------------------------------------------------------------------
# Endpoints
# ---------------------------------------------------------------------------
@router.get("", summary="List all registered tools")
def list_tools() -> dict[str, Any]:
    """Return catalog of all 10 registered cybersecurity tools with parameter schemas."""
    metadata = registry.get_tool_metadata()
    return {
        "count": len(metadata),
        "tools": metadata,
    }


@router.post("/execute", summary="Dynamic tool dispatcher")
async def execute_tool(payload: DynamicExecuteRequest) -> dict[str, Any]:
    """Dynamically invoke any registered tool by name with provided arguments."""
    tool = registry.get_tool(payload.tool_name)
    if not tool:
        raise HTTPException(
            status_code=404,
            detail=f"Tool '{payload.tool_name}' not found. Available tools: {[t.name for t in registry.get_all_tools()]}",
        )
    try:
        if hasattr(tool, "ainvoke"):
            result = await tool.ainvoke(payload.arguments)
        else:
            result = tool.invoke(payload.arguments)
        return {
            "tool": payload.tool_name,
            "status": "success",
            "result": result,
        }
    except Exception as exc:
        logger.exception("Failed to execute tool '%s'", payload.tool_name)
        raise HTTPException(status_code=500, detail=f"Tool execution failed: {str(exc)}") from exc


@router.post("/cve", summary="CVE vulnerability lookup")
async def run_cve_lookup(payload: CVELookupRequest) -> dict[str, Any]:
    """Retrieve CVE details from PostgreSQL vector DB or NVD fallback."""
    try:
        return cve_lookup.invoke({"cve_id": payload.cve_id})
    except Exception as exc:
        raise HTTPException(status_code=500, detail=str(exc)) from exc


@router.post("/kev", summary="CISA KEV exploitation check")
async def run_kev_lookup(payload: KEVLookupRequest) -> dict[str, Any]:
    """Check whether a CVE is listed in CISA's Known Exploited Vulnerabilities catalog."""
    try:
        return kev_lookup.invoke({"cve_id": payload.cve_id})
    except Exception as exc:
        raise HTTPException(status_code=500, detail=str(exc)) from exc


@router.post("/mitre", summary="MITRE ATT&CK lookup")
async def run_mitre_lookup(payload: MitreLookupRequest) -> dict[str, Any]:
    """Retrieve MITRE ATT&CK tactics, description, platforms, and detections."""
    try:
        return mitre_lookup.invoke({"technique_id_or_query": payload.query})
    except Exception as exc:
        raise HTTPException(status_code=500, detail=str(exc)) from exc


@router.post("/rag", summary="Hybrid RAG retrieval")
async def run_rag_retrieve(payload: RAGRetrieveRequest) -> dict[str, Any]:
    """Execute hybrid vector + keyword retrieval using Reciprocal Rank Fusion."""
    try:
        return rag_retrieve.invoke({"query": payload.query, "top_k": payload.top_k})
    except Exception as exc:
        raise HTTPException(status_code=500, detail=str(exc)) from exc


@router.post("/cvss", summary="CVSS vector and score analysis")
async def run_cvss_analysis(payload: CVSSAnalysisRequest) -> dict[str, Any]:
    """Parse CVSS v3.x vector, calculate score, and determine qualitative severity rating."""
    try:
        return cvss_analysis.invoke({"cvss_vector_or_cve": payload.cvss_vector_or_score})
    except Exception as exc:
        raise HTTPException(status_code=500, detail=str(exc)) from exc


@router.post("/iocs", summary="Extract IOCs from text")
async def run_ioc_extraction(payload: IOCExtractionRequest) -> dict[str, Any]:
    """Extract syntactic indicators of compromise (IPv4, domains, hashes, URLs)."""
    try:
        return extract_iocs_tool.invoke({"text": payload.text})
    except Exception as exc:
        raise HTTPException(status_code=500, detail=str(exc)) from exc


@router.post("/command", summary="Suspicious command analysis")
async def run_command_analysis(payload: CommandAnalysisRequest) -> dict[str, Any]:
    """Analyze PowerShell, CMD, or Bash commands for obfuscation and MITRE ATT&CK patterns."""
    try:
        return analyze_command.invoke({"command": payload.command})
    except Exception as exc:
        raise HTTPException(status_code=500, detail=str(exc)) from exc


@router.post("/screen", summary="File security screening")
async def run_file_screening(payload: ScreenFileRequest) -> dict[str, Any]:
    """Screen file contents for prompt injection, executable stagers, and suspicious artifacts."""
    try:
        return screen_file.invoke({
            "file_content_or_text": payload.content,
            "context_note": f"Filename: {payload.filename}, Type: {payload.declared_type}",
        })
    except Exception as exc:
        raise HTTPException(status_code=500, detail=str(exc)) from exc


@router.post("/remediation", summary="Remediation guidance retrieval")
async def run_remediation(payload: RemediationRequest) -> dict[str, Any]:
    """Retrieve actionable vendor patches, workarounds, and CISA required actions for a CVE."""
    try:
        return get_remediation.invoke({
            "cve_id": payload.cve_id,
            "remediation_query": payload.remediation_query,
        })
    except Exception as exc:
        raise HTTPException(status_code=500, detail=str(exc)) from exc


@router.post("/threat-intel", summary="Threat intelligence enrichment")
async def run_threat_intel(payload: ThreatIntelRequest) -> dict[str, Any]:
    """Enrich IOCs or threat queries with indexed threat intelligence context."""
    try:
        return enrich_threat_intel.invoke({
            "query": payload.query,
            "ioc_type": payload.ioc_type,
        })
    except Exception as exc:
        raise HTTPException(status_code=500, detail=str(exc)) from exc
