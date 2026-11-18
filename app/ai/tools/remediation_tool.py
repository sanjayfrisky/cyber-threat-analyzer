"""Tool 9: Remediation Recommendation — retrieves authoritative patches and produces actionable guidance."""
from __future__ import annotations

import logging
import re
import time

from langchain_core.tools import tool
from pydantic import BaseModel, Field
from sqlalchemy import select

from app.ai.rag.pipeline import RAGPipeline
from app.ai.schemas.remediation import RemediationResult
from app.ai.tools._tool_utils import get_db_session
from app.db.database import DocumentChunk, SourceDocument

logger = logging.getLogger(__name__)

_rag = RAGPipeline()
_CVE_PATTERN = re.compile(r"^CVE-\d{4}-\d{4,}$", re.IGNORECASE)


class RemediationInput(BaseModel):
    cve_id: str = Field(description="CVE identifier, e.g. CVE-2023-44487")
    affected_product: str = Field(
        default="",
        description="Name of the affected software or vendor, e.g. 'Nginx', 'Apache HTTP Server', 'OpenSSL'",
    )


@tool(args_schema=RemediationInput)
def get_remediation(cve_id: str, affected_product: str = "") -> dict:
    """
    Retrieve authoritative vendor advisories, patches, and remediation steps for a CVE.

    Queries:
    - Local indexed CVE records and CISA KEV required actions
    - Relevant patch and vendor advisory references
    - Custom hybrid RAG retrieval for remediation context

    STRICT DEFENSIVE RULES:
    - Authoritative vendor advisories and patch links are ONLY drawn from indexed ground-truth records.
    - AI-generated remediation guidance is explicitly separated and marked with disclaimers.
    - Never invents patch numbers or vendor URLs.

    Returns a structured RemediationResult.
    """
    t0 = time.perf_counter()
    cve_id = cve_id.strip().upper()
    product = (affected_product or "").strip()
    logger.info("[tool] get_remediation | cve_id=%s product=%s", cve_id, product)

    vendor_advisories: list[str] = []
    patch_references: list[str] = []
    source_urls: list[str] = []
    retrieved_evidence: list[str] = []
    missing_info: list[str] = []
    confirmed_source: str | None = None

    db = get_db_session()
    try:
        # 1. Lookup CVE record in local DB
        cve_doc = db.scalar(
            select(SourceDocument).where(
                SourceDocument.external_id.ilike(cve_id)
            )
        )
        if cve_doc:
            confirmed_source = "Local DB"
            if cve_doc.url:
                source_urls.append(cve_doc.url)
            raw_meta = cve_doc.raw_metadata or {}
            refs = raw_meta.get("references") or []
            for ref in refs:
                url_str = ref if isinstance(ref, str) else ref.get("url", "")
                if not url_str:
                    continue
                source_urls.append(url_str)
                lower_url = url_str.lower()
                if any(k in lower_url for k in ["advisory", "security", "bulletin", "cert"]):
                    vendor_advisories.append(url_str)
                elif any(k in lower_url for k in ["patch", "commit", "release", "update"]):
                    patch_references.append(url_str)

        # 2. Check CISA KEV for mandatory action / due dates
        cisa_doc = db.scalar(
            select(SourceDocument).where(
                SourceDocument.source == "cisa",
                SourceDocument.external_id.ilike(cve_id),
            )
        )
        if cisa_doc:
            confirmed_source = (confirmed_source + " + CISA KEV") if confirmed_source else "CISA KEV"
            if cisa_doc.url:
                source_urls.append(cisa_doc.url)
            cisa_meta = cisa_doc.raw_metadata or {}
            action = cisa_meta.get("requiredAction") or cisa_meta.get("required_action")
            if action:
                retrieved_evidence.append(f"CISA KEV Required Action: {action}")
            due_date = cisa_meta.get("dueDate") or cisa_meta.get("due_date")
            if due_date:
                retrieved_evidence.append(f"CISA KEV Remediation Due Date: {due_date}")

        # 3. Hybrid RAG retrieval for additional remediation intelligence
        rag_query = f"{cve_id} {product} patch remediation fix upgrade advisory".strip()
        rag_results = _rag.retrieve(db, rag_query, top_k=3)
        for r in rag_results:
            if r.get("url"):
                source_urls.append(r["url"])
            retrieved_evidence.append(f"[{r.get('source', 'RAG')}] {r.get('title', '')}: {r.get('content', '')[:300]}")

    finally:
        db.close()

    if not vendor_advisories and not patch_references:
        missing_info.append("No authoritative vendor patch URLs indexed for this CVE.")

    # Deduplicate URLs preserving order
    vendor_advisories = list(dict.fromkeys(vendor_advisories))
    patch_references = list(dict.fromkeys(patch_references))
    source_urls = list(dict.fromkeys(source_urls))

    # Standard general remediation steps based on evidence presence
    remediation_steps = [
        f"Identify all assets running {product or 'the affected software'} and inventory current versions.",
        "Verify whether vendor security updates or official workarounds have been published.",
        "Apply vendor-approved patches or hotfixes in a staging environment prior to production deployment.",
        "If immediate patching is not possible, restrict network access to affected endpoints or disable vulnerable components.",
        "Monitor system logs and network telemetry for indicators of active exploitation.",
    ]

    ai_generated_warnings = [
        "Do not apply unverified third-party scripts or binary patches.",
        "Review changelogs for breaking configuration changes before updating in production.",
    ]

    elapsed_ms = (time.perf_counter() - t0) * 1000
    logger.info(
        "[tool] get_remediation | cve_id=%s advisories=%d patches=%d in %.1f ms",
        cve_id, len(vendor_advisories), len(patch_references), elapsed_ms
    )

    result = RemediationResult(
        cve_id=cve_id,
        affected_product=product or "Unspecified Product",
        vendor_advisories=vendor_advisories,
        patch_references=patch_references,
        source_urls=source_urls,
        retrieved_evidence=retrieved_evidence,
        remediation_steps=remediation_steps,
        ai_generated_warnings=ai_generated_warnings,
        confirmed_source=confirmed_source,
        missing_info=missing_info,
    )
    return result.model_dump()
