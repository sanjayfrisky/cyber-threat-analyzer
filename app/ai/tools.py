"""Unified cybersecurity tools module containing all 10 LangChain tools in a single file."""
from __future__ import annotations

import logging
import re
import time
from typing import Any

import httpx
from langchain_core.tools import tool
from pydantic import BaseModel, Field
from sqlalchemy import select

from app.ai.rag.pipeline import RAGPipeline
from app.ai.schemas.cve import CVEAnalysis, CVSSAnalysis
from app.ai.schemas.remediation import RemediationResult, _DISCLAIMER
from app.ai.schemas.screening import IOCExtractionResult, SecurityScreeningResult
from app.ai.schemas.tool_result import ThreatIntelligenceResult
from app.ai.screening import (
    SUSPICIOUS_COMMAND_PATTERNS,
    ScreeningService,
    detect_heuristic_signals,
    extract_screening_iocs,
)
from app.db.database import DocumentChunk, SessionLocal, SourceDocument

logger = logging.getLogger(__name__)

# Constants
_CVE_PATTERN = re.compile(r"^CVE-\d{4}-\d{4,}$", re.IGNORECASE)
_NVD_API = "https://services.nvd.nist.gov/rest/json/cves/2.0"
_CISA_KEV_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
_MITRE_STIX_URL = (
    "https://raw.githubusercontent.com/mitre-attack/attack-stix-data/master/enterprise-attack/enterprise-attack.json"
)

# CVSS decode maps
_AV = {"N": "Network", "A": "Adjacent", "L": "Local", "P": "Physical"}
_AC = {"L": "Low", "H": "High"}
_PR = {"N": "None", "L": "Low", "H": "High"}
_UI = {"N": "None", "R": "Required"}
_SC = {"U": "Unchanged", "C": "Changed"}
_IMP = {"N": "None", "L": "Low", "H": "High"}

_screening_service = ScreeningService()
_rag = RAGPipeline()


def get_db_session():
    return SessionLocal()


def _get_db():
    return get_db_session()


# ===========================================================================
# Tool 1: CVE Lookup
# ===========================================================================
class CVELookupInput(BaseModel):
    cve_id: str = Field(description="CVE identifier, e.g. CVE-2021-44228")


def _query_db_for_cve(cve_id: str) -> dict | None:
    db = _get_db()
    try:
        doc = db.scalar(select(SourceDocument).where(SourceDocument.external_id.ilike(cve_id)))
        if not doc:
            return None
        chunks = db.scalars(
            select(DocumentChunk).where(DocumentChunk.document_id == doc.id).order_by(DocumentChunk.chunk_index).limit(5)
        ).all()
        content_snippets = [c.content for c in chunks]
        metadata = doc.raw_metadata or {}
        return {
            "cve_id": doc.external_id,
            "title": doc.title,
            "description": content_snippets[0] if content_snippets else doc.title,
            "source": doc.source,
            "url": doc.url,
            "cvss_score": metadata.get("cvss_score") or metadata.get("baseScore"),
            "severity": metadata.get("severity") or metadata.get("baseSeverity"),
            "affected_products": metadata.get("affected_products", []),
            "references": [doc.url] if doc.url else [],
            "retrieved_evidence": content_snippets,
        }
    finally:
        db.close()


def _query_nvd_api(cve_id: str) -> dict | None:
    try:
        response = httpx.get(_NVD_API, params={"cveId": cve_id}, timeout=10.0, headers={"Accept": "application/json"})
        response.raise_for_status()
        data = response.json()
        vulns = data.get("vulnerabilities", [])
        if not vulns:
            return None
        cve_data = vulns[0].get("cve", {})
        descriptions = cve_data.get("descriptions", [])
        en_desc = next((d["value"] for d in descriptions if d.get("lang") == "en"), "")
        metrics = cve_data.get("metrics", {})
        cvss_data = {}
        for key in ("cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
            if key in metrics and metrics[key]:
                cvss_data = metrics[key][0].get("cvssData", {})
                break
        references = [r["url"] for r in cve_data.get("references", []) if r.get("url")]
        return {
            "cve_id": cve_id,
            "title": cve_id,
            "description": en_desc,
            "source": "NVD",
            "url": f"https://nvd.nist.gov/vuln/detail/{cve_id}",
            "cvss_score": cvss_data.get("baseScore"),
            "severity": cvss_data.get("baseSeverity"),
            "affected_products": [],
            "references": references,
            "retrieved_evidence": [en_desc] if en_desc else [],
        }
    except Exception as exc:
        logger.warning("NVD API lookup failed for %s: %s", cve_id, exc)
        return None


@tool(args_schema=CVELookupInput)
def cve_lookup(cve_id: str) -> dict:
    """Retrieve CVE details from the local PostgreSQL database, with fallback to NVD."""
    cve_id = cve_id.strip().upper()
    if not _CVE_PATTERN.match(cve_id):
        return CVEAnalysis(
            cve_id=cve_id,
            description="",
            confirmed_source=None,
            ai_explanation="",
            missing_info=["Invalid CVE ID format. Expected format: CVE-YYYY-NNNNN"],
        ).model_dump()

    record = _query_db_for_cve(cve_id)
    source_label = "DB"
    if not record:
        record = _query_nvd_api(cve_id)
        source_label = "NVD"

    if not record:
        return CVEAnalysis(
            cve_id=cve_id,
            description="No record found in local database or NVD.",
            confirmed_source=None,
            ai_explanation="",
            missing_info=["CVE not found in local index or NVD API"],
        ).model_dump()

    severity = (record.get("severity") or "UNKNOWN").upper()
    if severity not in {"CRITICAL", "HIGH", "MEDIUM", "LOW", "NONE", "UNKNOWN"}:
        severity = "UNKNOWN"

    return CVEAnalysis(
        cve_id=cve_id,
        description=record.get("description", ""),
        cvss_score=record.get("cvss_score"),
        severity=severity,
        affected_products=record.get("affected_products", []),
        references=record.get("references", []),
        confirmed_source=source_label,
        retrieved_evidence=record.get("retrieved_evidence", []),
        ai_explanation="",
        missing_info=[],
    ).model_dump()


# ===========================================================================
# Tool 2: CISA KEV Lookup
# ===========================================================================
class KEVLookupInput(BaseModel):
    cve_id: str = Field(description="CVE ID to check in CISA KEV catalog")


@tool(args_schema=KEVLookupInput)
def kev_lookup(cve_id: str) -> dict:
    """Check whether a CVE is in the CISA Known Exploited Vulnerabilities (KEV) catalog."""
    cve_id = cve_id.strip().upper()
    db = _get_db()
    try:
        doc = db.scalar(
            select(SourceDocument).where(
                SourceDocument.source == "CISA_KEV",
                SourceDocument.external_id.ilike(f"%{cve_id}%"),
            )
        )
        if doc and doc.raw_metadata:
            meta = doc.raw_metadata
            return {
                "cve_id": cve_id,
                "is_in_kev": True,
                "is_known_exploited": True,
                "vendor_project": meta.get("vendorProject", "Unknown"),
                "product": meta.get("product", "Unknown"),
                "vulnerability_name": meta.get("vulnerabilityName", doc.title),
                "date_added": meta.get("dateAdded", "Unknown"),
                "short_description": meta.get("shortDescription", ""),
                "required_action": meta.get("requiredAction", "Apply vendor updates."),
                "due_date": meta.get("dueDate", "Unknown"),
                "known_ransomware_use": meta.get("knownRansomwareCampaignUse", "Unknown"),
                "notes": meta.get("notes", ""),
                "confirmed_source": "CISA_KEV (local DB)",
                "url": doc.url or "https://www.cisa.gov/known-exploited-vulnerabilities-catalog",
            }
    finally:
        db.close()

    # Online fallback
    try:
        resp = httpx.get(_CISA_KEV_URL, timeout=12.0)
        resp.raise_for_status()
        for v in resp.json().get("vulnerabilities", []):
            if v.get("cveID", "").upper() == cve_id:
                return {
                    "cve_id": cve_id,
                    "is_in_kev": True,
                    "is_known_exploited": True,
                    "vendor_project": v.get("vendorProject", "Unknown"),
                    "product": v.get("product", "Unknown"),
                    "vulnerability_name": v.get("vulnerabilityName", ""),
                    "date_added": v.get("dateAdded", "Unknown"),
                    "short_description": v.get("shortDescription", ""),
                    "required_action": v.get("requiredAction", "Apply vendor updates."),
                    "due_date": v.get("dueDate", "Unknown"),
                    "known_ransomware_use": v.get("knownRansomwareCampaignUse", "Unknown"),
                    "notes": v.get("notes", ""),
                    "confirmed_source": "CISA_KEV (online feed)",
                    "url": "https://www.cisa.gov/known-exploited-vulnerabilities-catalog",
                }
    except Exception as exc:
        logger.warning("CISA KEV online lookup failed for %s: %s", cve_id, exc)

    return {
        "cve_id": cve_id,
        "is_in_kev": False,
        "is_known_exploited": False,
        "vulnerability_name": "",
        "required_action": "No mandatory CISA action on record.",
        "due_date": None,
        "note": f"{cve_id} is not listed in the CISA KEV catalog as actively exploited.",
        "confirmed_source": "CISA_KEV",
        "url": "https://www.cisa.gov/known-exploited-vulnerabilities-catalog",
    }


# ===========================================================================
# Tool 3: MITRE ATT&CK Lookup
# ===========================================================================
class MitreLookupInput(BaseModel):
    technique_id: str | None = Field(default=None, description="Technique ID (e.g. T1059.001)")
    search_term: str | None = Field(default=None, description="Search term for attack techniques")


@tool(args_schema=MitreLookupInput)
def mitre_lookup(technique_id: str | None = None, search_term: str | None = None) -> dict:
    """Retrieve MITRE ATT&CK technique details from PostgreSQL or ATT&CK STIX data."""
    query = (technique_id or search_term or "").strip()
    db = _get_db()
    try:
        stmt = select(SourceDocument).where(SourceDocument.source == "MITRE_ATTACK")
        if query:
            stmt = stmt.where(SourceDocument.external_id.ilike(f"%{query}%"))
        docs = db.scalars(stmt.limit(5)).all()
        if docs:
            results = []
            for doc in docs:
                meta = doc.raw_metadata or {}
                tid = meta.get("technique_id") or doc.external_id.replace("MITRE-", "")
                results.append({
                    "technique_id": tid,
                    "name": doc.title,
                    "tactics": meta.get("tactics", ["Execution"]),
                    "platforms": meta.get("platforms", []),
                    "url": doc.url or f"https://attack.mitre.org/techniques/{tid.replace('.', '/')}/",
                })
            return {
                "query": query,
                "results": results,
                "confirmed_source": "MITRE_ATTACK (local DB)",
            }
    finally:
        db.close()

    # Fallback STIX lookup
    try:
        resp = httpx.get(_MITRE_STIX_URL, timeout=15.0)
        resp.raise_for_status()
        for obj in resp.json().get("objects", []):
            if obj.get("type") != "attack-pattern":
                continue
            for ref in obj.get("external_references", []):
                if ref.get("source_name") == "mitre-attack" and query.upper() in ref.get("external_id", "").upper():
                    tid = ref["external_id"]
                    return {
                        "query": query,
                        "results": [{
                            "technique_id": tid,
                            "name": obj.get("name", ""),
                            "tactics": [k.get("phase_name") for k in obj.get("kill_chain_phases", [])],
                            "platforms": obj.get("x_mitre_platforms", []),
                            "url": ref.get("url", f"https://attack.mitre.org/techniques/{tid.replace('.', '/')}/"),
                        }],
                        "confirmed_source": "MITRE_ATTACK (online STIX)",
                    }
    except Exception as exc:
        logger.warning("MITRE STIX lookup failed for %s: %s", query, exc)

    return {
        "query": query,
        "results": [],
        "confirmed_source": "MITRE_ATTACK",
    }


# ===========================================================================
# Tool 4: RAG Retrieval Tool
# ===========================================================================
class RAGRetrieveInput(BaseModel):
    query: str = Field(description="Search query to run against the indexed threat intelligence database")
    top_k: int = Field(default=6, description="Number of results to retrieve (1-20)")


@tool(args_schema=RAGRetrieveInput)
def rag_retrieve(query: str, top_k: int = 6) -> dict:
    """Execute hybrid vector and full-text retrieval with Reciprocal Rank Fusion against PostgreSQL."""
    db = _get_db()
    try:
        results = _rag.retrieve(db, query.strip(), top_k=min(max(top_k, 1), 20))
        return {
            "query": query,
            "retrieved_count": len(results),
            "results": results,
            "confirmed_source": "PostgreSQL pgvector + full-text hybrid index",
        }
    finally:
        db.close()


# ===========================================================================
# Tool 5: CVSS Analysis
# ===========================================================================
def _severity_from_score(score: float | None) -> str:
    if score is None:
        return "UNKNOWN"
    if score == 0.0:
        return "NONE"
    if score <= 3.9:
        return "LOW"
    if score <= 6.9:
        return "MEDIUM"
    if score <= 8.9:
        return "HIGH"
    return "CRITICAL"


class CVSSAnalysisInput(BaseModel):
    cvss_vector_or_cve: str = Field(
        description="A CVSS v3.x vector string (e.g. CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H 9.8)"
    )


@tool(args_schema=CVSSAnalysisInput)
def cvss_analysis(cvss_vector_or_cve: str) -> dict:
    """Parse and explain a CVSS v3.x vector string, decoding metrics and qualitative severity."""
    value = cvss_vector_or_cve.strip()
    if re.match(r"^CVE-\d{4}-\d{4,}$", value, re.IGNORECASE):
        return {
            "error": f"'{value}' is a CVE ID, not a CVSS vector. Use cve_lookup first to obtain the vector string.",
        }

    version = "3.1" if "3.1" in value else "3.0"
    cleaned = re.sub(r"^CVSS:[23]\.[01]/", "", value)
    metrics = dict(part.split(":") for part in cleaned.split("/") if ":" in part)

    base_score = None
    score_match = re.search(r"(?:[\s/:]|^)(\d{1,2}\.\d)\b", cleaned)
    if score_match:
        try:
            base_score = float(score_match.group(1))
        except ValueError:
            pass

    return CVSSAnalysis(
        vector_string=value,
        version=version,
        base_score=base_score,
        severity=_severity_from_score(base_score),
        attack_vector=_AV.get(metrics.get("AV", ""), "UNKNOWN"),
        attack_complexity=_AC.get(metrics.get("AC", ""), "UNKNOWN"),
        privileges_required=_PR.get(metrics.get("PR", ""), "UNKNOWN"),
        user_interaction=_UI.get(metrics.get("UI", ""), "UNKNOWN"),
        scope=_SC.get(metrics.get("S", ""), "UNKNOWN"),
        confidentiality_impact=_IMP.get(metrics.get("C", ""), "UNKNOWN"),
        integrity_impact=_IMP.get(metrics.get("I", ""), "UNKNOWN"),
        availability_impact=_IMP.get(metrics.get("A", ""), "UNKNOWN"),
        exploitability_assessment="",
        source="CVSS vector parsing (no external call)",
    ).model_dump()


# ===========================================================================
# Tool 6: IOC Extraction Tool
# ===========================================================================
class IOCExtractionInput(BaseModel):
    text: str = Field(description="Raw text, log snippet, or network artifact to extract IOCs from")


@tool(args_schema=IOCExtractionInput)
def extract_iocs_tool(text: str) -> dict:
    """Extract syntactic indicators of compromise (IPv4, domains, hashes, URLs) from text."""
    result = extract_screening_iocs(text)
    return IOCExtractionResult(
        ipv4=result.get("ipv4", []),
        domains=result.get("domains", []),
        urls=result.get("urls", []),
        md5=result.get("md5", []),
        sha1=result.get("sha1", []),
        sha256=result.get("sha256", []),
    ).model_dump()


# ===========================================================================
# Tool 7: Command Analysis Tool
# ===========================================================================
class CommandAnalysisInput(BaseModel):
    command: str = Field(description="PowerShell, Bash, or CMD command to inspect for suspicious patterns")


@tool(args_schema=CommandAnalysisInput)
def analyze_command(command: str) -> dict:
    """Analyze shell commands for suspicious patterns and MITRE ATT&CK techniques without executing them."""
    if not command or not command.strip():
        return {
            "command": command,
            "matches": [],
            "mitre_techniques": [],
            "risk_level": "BENIGN",
            "note": "Empty command provided",
        }

    heuristic_result = detect_heuristic_signals(command)
    matches = heuristic_result.get("findings", [])
    mitre_techniques = heuristic_result.get("mitre_techniques", [])
    prompt_injection = heuristic_result.get("prompt_injection_detected", False)

    pattern_details = []
    for pattern, description, technique_id in SUSPICIOUS_COMMAND_PATTERNS:
        if re.search(pattern, command, re.IGNORECASE):
            pattern_details.append({
                "description": description,
                "mitre_technique": technique_id,
            })

    risk_level = "CRITICAL" if len(pattern_details) >= 2 else ("HIGH" if len(pattern_details) == 1 or prompt_injection else "BENIGN")

    return {
        "command_preview": command[:200] + ("..." if len(command) > 200 else ""),
        "matches": pattern_details,
        "mitre_techniques": mitre_techniques,
        "risk_level": risk_level,
        "prompt_injection_detected": prompt_injection,
        "execution_note": "This command was NOT executed. Analysis is regex-based only.",
        "confirmed_source": "Heuristic pattern matching",
    }


# ===========================================================================
# Tool 8: File Screening Tool
# ===========================================================================
class FileScreeningInput(BaseModel):
    file_content_or_text: str = Field(description="Extracted plain text or script content from file")
    context_note: str = Field(default="File screening request", description="Operational context")


@tool(args_schema=FileScreeningInput)
def screen_file(file_content_or_text: str, context_note: str = "File screening request") -> dict:
    """Screen file contents for prompt injection, executable stagers, and suspicious artifacts."""
    content = file_content_or_text or ""
    db = _get_db()
    try:
        report = _screening_service.screen_text(db=db, content=content, filename="input_content.txt", context=context_note)
        threat_found = bool(report.get("findings") or report.get("prompt_injection_detected"))
        action = report.get("recommended_action") or ("BLOCK" if report.get("prompt_injection_detected") else ("FLAG_HIGH_RISK" if threat_found else "ALLOW"))
        verdict = report.get("verdict") or ("MALICIOUS" if threat_found else "BENIGN")
        risk_score = report.get("risk_score", 90 if threat_found else 0)
        confidence = report.get("confidence", 0.95 if threat_found else 1.0)
        category = report.get("threat_category", "General Threat" if threat_found else "Clean")

        return SecurityScreeningResult(
            verdict=verdict,
            risk_score=risk_score,
            confidence=confidence,
            threat_category=category,
            prompt_injection_detected=report.get("prompt_injection_detected", False),
            mitre_techniques=report.get("mitre_techniques", []),
            summary=report.get("summary", ""),
            findings=report.get("findings", []),
            recommended_action=action,
            iocs=report.get("iocs", {}),
            sources=report.get("sources", []),
        ).model_dump()
    finally:
        db.close()


# ===========================================================================
# Tool 9: Remediation Tool
# ===========================================================================
class RemediationInput(BaseModel):
    cve_id: str = Field(description="CVE identifier, e.g. CVE-2023-44487")
    affected_product: str = Field(default="", description="Product or component name")


@tool(args_schema=RemediationInput)
def get_remediation(cve_id: str, affected_product: str = "") -> dict:
    """Retrieve actionable vendor patches, workarounds, and CISA required actions for a CVE."""
    cve_clean = cve_id.strip().upper()
    cve_data = _query_db_for_cve(cve_clean) or _query_nvd_api(cve_clean) or {}
    kev_data = kev_lookup.invoke({"cve_id": cve_clean})

    db = _get_db()
    try:
        rag_hits = _rag.retrieve(db, f"{cve_clean} remediation patch", top_k=3)
    finally:
        db.close()

    refs = cve_data.get("references", [])
    vendor_advisories = [r for r in refs if any(k in r.lower() for k in ("advisory", "security", "patch", "bulletin", "support", "blog", "github"))]

    steps = [
        f"1. Audit deployment for affected versions of {affected_product or 'target component'}.",
        "2. Apply official vendor security updates and patch releases.",
        "3. Monitor network logs for unexpected inbound requests or anomalous traffic.",
    ]

    src = cve_data.get("source")
    if src is not None and not isinstance(src, str):
        src = "NVD"
    confirmed_source = src or "NVD"

    return RemediationResult(
        cve_id=cve_clean,
        affected_product=affected_product,
        vendor_advisories=vendor_advisories[:5],
        patch_references=refs[:5],
        source_urls=refs[:5],
        retrieved_evidence=[h.get("content", "") for h in rag_hits if isinstance(h, dict)],
        remediation_steps=steps,
        ai_generated_warnings=["Verify applicability in staging before applying to production."],
        disclaimer=_DISCLAIMER,
        sources_consulted=["NVD", "CISA_KEV", "RAG"],
        confirmed_source=confirmed_source,
    ).model_dump()


# ===========================================================================
# Tool 10: Threat Intelligence Enrichment Tool
# ===========================================================================
class ThreatIntelInput(BaseModel):
    indicator: str = Field(description="The IOC, CVE, or technique identifier to enrich")
    indicator_type: str = Field(default="auto", description="Type of indicator: ip, domain, hash, or auto")


@tool(args_schema=ThreatIntelInput)
def enrich_threat_intel(indicator: str, indicator_type: str = "auto") -> dict:
    """Enrich IOCs or threat actor queries with indexed threat intelligence context."""
    db = _get_db()
    try:
        results = _rag.retrieve(db, indicator.strip(), top_k=4)
        cve_data = None
        cisa_data = None
        mitre_data = []

        if _CVE_PATTERN.match(indicator.strip()):
            cve_data = _query_db_for_cve(indicator.strip())
            cisa_data = kev_lookup.invoke({"cve_id": indicator.strip()})
        elif indicator.strip().upper().startswith("T"):
            mitre_res = mitre_lookup.invoke({"technique_id": indicator.strip()})
            mitre_data = mitre_res.get("results", [])

        source_urls = []
        for r in results:
            if isinstance(r, dict) and r.get("url"):
                source_urls.append(r["url"])

        return ThreatIntelligenceResult(
            indicator=indicator,
            nvd_data=cve_data,
            cisa_kev_data=cisa_data,
            mitre_data=mitre_data,
            retrieved_docs=results,
            combined_assessment=f"Enrichment completed for indicator: {indicator}. Consulted indexed feeds and knowledge base.",
            source_urls=source_urls,
            sources_consulted=["DB", "RAG", "MITRE", "CISA_KEV"],
            missing_info=[],
        ).model_dump()
    finally:
        db.close()


# ===========================================================================
# Master List of Tools
# ===========================================================================
ALL_TOOLS = [
    cve_lookup,
    kev_lookup,
    mitre_lookup,
    rag_retrieve,
    cvss_analysis,
    extract_iocs_tool,
    analyze_command,
    screen_file,
    get_remediation,
    enrich_threat_intel,
]

# Backward-compatible submodule aliases for existing tests
import sys
_current_module = sys.modules[__name__]
sys.modules["app.ai.tools.cve_tool"] = _current_module
sys.modules["app.ai.tools.kev_tool"] = _current_module
sys.modules["app.ai.tools.mitre_tool"] = _current_module
sys.modules["app.ai.tools.rag_tool"] = _current_module
sys.modules["app.ai.tools.cvss_tool"] = _current_module
sys.modules["app.ai.tools.ioc_tool"] = _current_module
sys.modules["app.ai.tools.command_analysis_tool"] = _current_module
sys.modules["app.ai.tools.file_screening_tool"] = _current_module
sys.modules["app.ai.tools.remediation_tool"] = _current_module
sys.modules["app.ai.tools.threat_intelligence_tool"] = _current_module
sys.modules["app.ai.tools._tool_utils"] = _current_module
