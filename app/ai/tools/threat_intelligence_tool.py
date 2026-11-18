"""Tool 10: Threat Intelligence Enrichment — combines NVD, CISA KEV, MITRE, and RAG records."""
from __future__ import annotations

import logging
import re
import time

from langchain_core.tools import tool
from pydantic import BaseModel, Field
from sqlalchemy import or_, select

from app.ai.rag.pipeline import RAGPipeline
from app.ai.schemas.tool_result import ThreatIntelligenceResult
from app.ai.tools._tool_utils import get_db_session
from app.db.database import DocumentChunk, SourceDocument

logger = logging.getLogger(__name__)

_rag = RAGPipeline()
_CVE_PATTERN = re.compile(r"^CVE-\d{4}-\d{4,}$", re.IGNORECASE)
_MITRE_PATTERN = re.compile(r"^T\d{4}(?:\.\d{3})?$", re.IGNORECASE)


class ThreatIntelInput(BaseModel):
    indicator: str = Field(
        description="A CVE identifier (e.g. CVE-2023-44487), MITRE technique (e.g. T1059.001), IP, domain, URL, or hash"
    )


@tool(args_schema=ThreatIntelInput)
def enrich_threat_intel(indicator: str) -> dict:
    """
    Enrich an indicator or vulnerability identifier across all threat intelligence sources.

    Synthesizes:
    - NVD / local CVE records
    - CISA Known Exploited Vulnerabilities catalog
    - MITRE ATT&CK technique records
    - Hybrid vector DB retrieved document chunks

    Every returned field is strictly tagged with its data origin.
    Returns a structured ThreatIntelligenceResult.
    """
    t0 = time.perf_counter()
    target = indicator.strip()
    logger.info("[tool] enrich_threat_intel | indicator=%s", target)

    nvd_data: dict | None = None
    cisa_kev_data: dict | None = None
    mitre_data: list[dict] = []
    retrieved_docs: list[dict] = []
    source_urls: list[str] = []
    sources_consulted: list[str] = []
    missing_info: list[str] = []

    db = get_db_session()
    try:
        # 1. If indicator is a CVE
        if _CVE_PATTERN.match(target):
            sources_consulted.extend(["NVD/Local CVE", "CISA KEV"])
            cve_doc = db.scalar(
                select(SourceDocument).where(SourceDocument.external_id.ilike(target))
            )
            if cve_doc:
                nvd_data = {
                    "cve_id": cve_doc.external_id,
                    "title": cve_doc.title,
                    "url": cve_doc.url,
                    "metadata": cve_doc.raw_metadata or {},
                }
                if cve_doc.url:
                    source_urls.append(cve_doc.url)
            else:
                missing_info.append("CVE not found in local index")

            # CISA KEV
            cisa_doc = db.scalar(
                select(SourceDocument).where(
                    SourceDocument.source == "cisa",
                    SourceDocument.external_id.ilike(target),
                )
            )
            if cisa_doc:
                cisa_kev_data = {
                    "cve_id": cisa_doc.external_id,
                    "title": cisa_doc.title,
                    "url": cisa_doc.url,
                    "metadata": cisa_doc.raw_metadata or {},
                    "is_exploited": True,
                }
                if cisa_doc.url:
                    source_urls.append(cisa_doc.url)
            else:
                cisa_kev_data = {"is_exploited": False}

        # 2. If indicator is a MITRE technique or search term
        if _MITRE_PATTERN.match(target) or not _CVE_PATTERN.match(target):
            sources_consulted.append("MITRE ATT&CK")
            mitre_docs = db.scalars(
                select(SourceDocument).where(
                    SourceDocument.source == "mitre",
                    or_(
                        SourceDocument.external_id.ilike(f"%{target}%"),
                        SourceDocument.title.ilike(f"%{target}%"),
                    ),
                ).limit(3)
            ).all()
            for md in mitre_docs:
                mitre_data.append({
                    "technique_id": md.external_id,
                    "name": md.title,
                    "url": md.url,
                    "metadata": md.raw_metadata or {},
                })
                if md.url:
                    source_urls.append(md.url)

        # 3. Hybrid RAG retrieval for relevant context
        sources_consulted.append("Vector DB Hybrid Search")
        rag_hits = _rag.retrieve(db, target, top_k=4)
        for h in rag_hits:
            retrieved_docs.append(h)
            if h.get("url"):
                source_urls.append(h["url"])

    finally:
        db.close()

    # Deduplicate URLs
    source_urls = list(dict.fromkeys(source_urls))

    assessment_parts = [f"Enrichment completed for indicator '{target}' across {len(sources_consulted)} sources."]
    if cisa_kev_data and cisa_kev_data.get("is_exploited"):
        assessment_parts.append("WARNING: Vulnerability is listed in CISA KEV as known to be actively exploited.")
    if mitre_data:
        t_ids = [m["technique_id"] for m in mitre_data]
        assessment_parts.append(f"Mapped to MITRE ATT&CK techniques: {', '.join(t_ids)}.")
    if not nvd_data and not mitre_data and not retrieved_docs:
        assessment_parts.append("No authoritative threat intelligence records were located for this indicator.")

    elapsed_ms = (time.perf_counter() - t0) * 1000
    logger.info(
        "[tool] enrich_threat_intel | indicator=%s docs=%d in %.1f ms",
        target, len(retrieved_docs), elapsed_ms
    )

    result = ThreatIntelligenceResult(
        indicator=target,
        nvd_data=nvd_data,
        cisa_kev_data=cisa_kev_data,
        mitre_data=mitre_data,
        retrieved_docs=retrieved_docs,
        combined_assessment=" ".join(assessment_parts),
        source_urls=source_urls,
        sources_consulted=sources_consulted,
        missing_info=missing_info,
    )
    return result.model_dump()
