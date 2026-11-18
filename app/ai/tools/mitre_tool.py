"""Tool 3: MITRE ATT&CK Lookup — retrieves attack technique information."""
from __future__ import annotations

import logging
import time

from langchain_core.tools import tool
from pydantic import BaseModel, Field
from sqlalchemy import and_, or_, select

from app.db.database import DocumentChunk, SourceDocument
from app.ai.tools._tool_utils import get_db_session

logger = logging.getLogger(__name__)


class MITRELookupInput(BaseModel):
    technique_id: str = Field(
        description=(
            "MITRE ATT&CK technique ID (e.g. T1059, T1059.001) or a plain-text "
            "search term (e.g. 'credential dumping', 'lateral movement')"
        )
    )


@tool(args_schema=MITRELookupInput)
def mitre_lookup(technique_id: str) -> dict:
    """
    Retrieve MITRE ATT&CK technique information from the local database.

    Accepts either a technique ID (T1059, T1059.001) or a descriptive search term.
    Returns tactic name, technique description, and reference URLs sourced from
    the local PostgreSQL index (MITRE records ingested at startup).

    Use this tool for questions about attack techniques, tactics, threat actor TTPs,
    or when a command analysis suggests a MITRE technique.
    """
    t0 = time.perf_counter()
    query = technique_id.strip()
    logger.info("[tool] mitre_lookup | query=%s", query)

    db = get_db_session()
    try:
        # Try exact external_id match first (e.g. "T1059.001")
        docs = db.scalars(
            select(SourceDocument).where(
                and_(
                    SourceDocument.source == "mitre",
                    SourceDocument.external_id.ilike(f"%{query}%"),
                )
            ).limit(5)
        ).all()

        # Fallback: title/text search
        if not docs:
            docs = db.scalars(
                select(SourceDocument).where(
                    and_(
                        SourceDocument.source == "mitre",
                        SourceDocument.title.ilike(f"%{query}%"),
                    )
                ).limit(5)
            ).all()

        elapsed_ms = (time.perf_counter() - t0) * 1000

        if not docs:
            logger.info("[tool] mitre_lookup | no results for '%s' (%.1f ms)", query, elapsed_ms)
            return {
                "query": query,
                "results": [],
                "confirmed_source": "MITRE ATT&CK (local index)",
                "note": f"No MITRE ATT&CK techniques found matching '{query}' in the local index.",
            }

        results = []
        for doc in docs:
            metadata = doc.raw_metadata or {}
            chunks = db.scalars(
                select(DocumentChunk)
                .where(DocumentChunk.document_id == doc.id)
                .order_by(DocumentChunk.chunk_index)
                .limit(3)
            ).all()

            results.append({
                "technique_id": doc.external_id,
                "name": doc.title,
                "tactics": metadata.get("tactics", []),
                "description": chunks[0].content if chunks else doc.title,
                "references": [doc.url] if doc.url else [],
                "url": doc.url,
            })

        logger.info(
            "[tool] mitre_lookup | found %d results for '%s' (%.1f ms)",
            len(results), query, elapsed_ms,
        )
        return {
            "query": query,
            "results": results,
            "confirmed_source": "MITRE ATT&CK (local index)",
        }
    finally:
        db.close()
