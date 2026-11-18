"""Tool 6: IOC Extraction — extracts Indicators of Compromise from text using regex."""
from __future__ import annotations

import logging
import time

from langchain_core.tools import tool
from pydantic import BaseModel, Field

from app.ai.screening import extract_screening_iocs
from app.ai.schemas.screening import IOCExtractionResult

logger = logging.getLogger(__name__)


class IOCExtractionInput(BaseModel):
    text: str = Field(
        description=(
            "Raw text, log output, or security event content to extract "
            "IP addresses, domains, URLs, and file hashes from"
        )
    )


@tool(args_schema=IOCExtractionInput)
def extract_iocs_tool(text: str) -> dict:
    """
    Extract Indicators of Compromise (IOCs) from arbitrary text using regex patterns.

    Extracts:
    - IPv4 addresses (validated octet ranges)
    - HTTP/HTTPS URLs
    - Domain names
    - MD5, SHA-1, SHA-256 file hashes

    All extraction is performed by deterministic regex — no LLM inference.
    Results are confirmed source data, not AI-generated.

    Use this tool when the user provides logs, security events, or raw text
    that may contain suspicious indicators.
    """
    t0 = time.perf_counter()
    logger.info("[tool] extract_iocs_tool | text_len=%d", len(text))

    if not text or not text.strip():
        return IOCExtractionResult(extraction_source="regex").model_dump()

    # Reuse existing extract_screening_iocs from app/ai/screening.py
    raw = extract_screening_iocs(text[:50_000])  # hard cap at 50 KB

    result = IOCExtractionResult(
        ipv4=raw.get("ipv4", []),
        urls=raw.get("urls", []),
        domains=raw.get("domains", []),
        md5=raw.get("md5", []),
        sha1=raw.get("sha1", []),
        sha256=raw.get("sha256", []),
        extraction_source="regex (extract_screening_iocs)",
    )

    elapsed_ms = (time.perf_counter() - t0) * 1000
    logger.info(
        "[tool] extract_iocs_tool | found %d IOCs total in %.1f ms",
        result.total_count, elapsed_ms,
    )
    return result.model_dump()
