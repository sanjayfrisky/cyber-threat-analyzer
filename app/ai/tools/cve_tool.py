"""Tool 1: CVE Lookup — retrieves CVE details from PostgreSQL and optionally NVD."""
from __future__ import annotations

import logging
import re
import time

import httpx
from langchain_core.tools import tool
from pydantic import BaseModel, Field
from sqlalchemy import select

from app.ai.schemas.cve import CVEAnalysis
from app.ai.tools._tool_utils import get_db_session, timed_tool
from app.db.database import DocumentChunk, SourceDocument

logger = logging.getLogger(__name__)

_CVE_PATTERN = re.compile(r"^CVE-\d{4}-\d{4,}$", re.IGNORECASE)
_NVD_API = "https://services.nvd.nist.gov/rest/json/cves/2.0"


class CVELookupInput(BaseModel):
    cve_id: str = Field(description="CVE identifier, e.g. CVE-2024-12345")


def _query_db_for_cve(cve_id: str) -> dict | None:
    """Query the local vector DB for an indexed CVE record."""
    db = get_db_session()
    try:
        doc = db.scalar(
            select(SourceDocument).where(
                SourceDocument.external_id.ilike(cve_id)
            )
        )
        if not doc:
            return None

        chunks = db.scalars(
            select(DocumentChunk)
            .where(DocumentChunk.document_id == doc.id)
            .order_by(DocumentChunk.chunk_index)
            .limit(5)
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
    """Fetch CVE data from the NVD REST API (optional fallback)."""
    try:
        response = httpx.get(
            _NVD_API,
            params={"cveId": cve_id},
            timeout=10.0,
            headers={"Accept": "application/json"},
        )
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
    """
    Retrieve CVE vulnerability details from the local PostgreSQL database.
    Falls back to the NVD REST API when the CVE is not indexed locally.

    Returns a structured dict matching CVEAnalysis schema.
    Do NOT use this tool for general security questions — only for specific CVE IDs.
    """
    t0 = time.perf_counter()
    cve_id = cve_id.strip().upper()
    logger.info("[tool] cve_lookup | cve_id=%s", cve_id)

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

    elapsed_ms = (time.perf_counter() - t0) * 1000

    if not record:
        logger.info("[tool] cve_lookup | no record found for %s (%.1f ms)", cve_id, elapsed_ms)
        return CVEAnalysis(
            cve_id=cve_id,
            description="No record found in local database or NVD.",
            confirmed_source=None,
            ai_explanation="",
            missing_info=["CVE not found in local index or NVD API"],
        ).model_dump()

    # Normalise severity
    severity = (record.get("severity") or "UNKNOWN").upper()
    if severity not in {"CRITICAL", "HIGH", "MEDIUM", "LOW", "NONE", "UNKNOWN"}:
        severity = "UNKNOWN"

    logger.info("[tool] cve_lookup | found %s from %s in %.1f ms", cve_id, source_label, elapsed_ms)
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
