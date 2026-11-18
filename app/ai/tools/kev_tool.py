"""Tool 2: CISA KEV Lookup — checks if a CVE is in the CISA Known Exploited Vulnerabilities catalog."""
from __future__ import annotations

import logging
import re
import time

from langchain_core.tools import tool
from pydantic import BaseModel, Field
from sqlalchemy import and_, select

from app.db.database import DocumentChunk, SourceDocument
from app.ai.tools._tool_utils import get_db_session

logger = logging.getLogger(__name__)

_CVE_PATTERN = re.compile(r"^CVE-\d{4}-\d{4,}$", re.IGNORECASE)


class KEVLookupInput(BaseModel):
    cve_id: str = Field(description="CVE identifier to check in CISA KEV, e.g. CVE-2023-44487")


@tool(args_schema=KEVLookupInput)
def kev_lookup(cve_id: str) -> dict:
    """
    Check whether a CVE appears in the CISA Known Exploited Vulnerabilities (KEV) catalog.

    Returns known-exploited status, remediation due date, and available notes
    sourced from the local PostgreSQL database (CISA records ingested at startup).

    Use this tool when the user asks whether a vulnerability is actively exploited
    or has a CISA remediation deadline.
    """
    t0 = time.perf_counter()
    cve_id = cve_id.strip().upper()
    logger.info("[tool] kev_lookup | cve_id=%s", cve_id)

    if not _CVE_PATTERN.match(cve_id):
        return {
            "cve_id": cve_id,
            "is_in_kev": False,
            "source": None,
            "error": "Invalid CVE ID format",
        }

    db = get_db_session()
    try:
        doc = db.scalar(
            select(SourceDocument).where(
                and_(
                    SourceDocument.source == "cisa",
                    SourceDocument.external_id.ilike(cve_id),
                )
            )
        )

        if not doc:
            elapsed_ms = (time.perf_counter() - t0) * 1000
            logger.info("[tool] kev_lookup | %s NOT in KEV (%.1f ms)", cve_id, elapsed_ms)
            return {
                "cve_id": cve_id,
                "is_in_kev": False,
                "confirmed_source": "CISA KEV (local index)",
                "note": "This CVE is not listed in the CISA Known Exploited Vulnerabilities catalog.",
            }

        metadata = doc.raw_metadata or {}
        chunks = db.scalars(
            select(DocumentChunk)
            .where(DocumentChunk.document_id == doc.id)
            .order_by(DocumentChunk.chunk_index)
            .limit(3)
        ).all()
        notes = [c.content for c in chunks]

        elapsed_ms = (time.perf_counter() - t0) * 1000
        logger.info("[tool] kev_lookup | %s IS in KEV (%.1f ms)", cve_id, elapsed_ms)

        return {
            "cve_id": cve_id,
            "is_in_kev": True,
            "confirmed_source": "CISA KEV (local index)",
            "title": doc.title,
            "url": doc.url,
            "due_date": metadata.get("dueDate") or metadata.get("due_date"),
            "vendor": metadata.get("vendorProject") or metadata.get("vendor"),
            "product": metadata.get("product"),
            "required_action": metadata.get("requiredAction") or metadata.get("required_action"),
            "notes": notes,
        }
    finally:
        db.close()
