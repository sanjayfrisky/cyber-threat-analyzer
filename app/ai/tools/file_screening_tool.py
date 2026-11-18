"""Tool 8: File Screening — screens file content or metadata using the existing ScreeningService."""
from __future__ import annotations

import logging
import time

from langchain_core.tools import tool
from pydantic import BaseModel, Field

from app.ai.schemas.screening import IOCExtractionResult, SecurityScreeningResult
from app.ai.screening import ScreeningService
from app.ai.tools._tool_utils import get_db_session

logger = logging.getLogger(__name__)

_screening_service = ScreeningService()


class FileScreeningInput(BaseModel):
    file_content_or_text: str = Field(
        description=(
            "Extracted plain text, logs, configuration, script, or metadata from an uploaded file "
            "to screen for malicious tokens, prompt injections, suspicious commands, and IOCs. "
            "THE FILE IS NEVER EXECUTED."
        )
    )
    context_note: str = Field(
        default="File screening request",
        description="Optional operational context (e.g. filename, origin, suspected issue)",
    )


@tool(args_schema=FileScreeningInput)
def screen_file(file_content_or_text: str, context_note: str = "File screening request") -> dict:
    """
    Screen extracted text or metadata from an uploaded file for security threats.

    Integrates with the existing ScreeningService to detect:
    - Potential prompt-injection / jailbreak payloads
    - Suspicious shell commands and MITRE ATT&CK techniques
    - Indicators of compromise (IPs, URLs, domains, hashes)
    - Ground-truth threat intelligence correlations from the vector DB

    NEVER EXECUTES THE FILE OR ANY SCRIPT CONTENT.
    Returns a structured SecurityScreeningResult.
    """
    t0 = time.perf_counter()
    content = file_content_or_text or ""
    logger.info("[tool] screen_file | content_len=%d context=%s", len(content), context_note)

    if not content.strip():
        empty_iocs = IOCExtractionResult(extraction_source="regex")
        return SecurityScreeningResult(
            verdict="BENIGN",
            risk_score=0,
            confidence=1.0,
            threat_category="Empty Content",
            prompt_injection_detected=False,
            mitre_techniques=[],
            summary="No content provided to screen.",
            findings=["Empty file or content."],
            recommended_action="PASS",
            iocs=empty_iocs,
            sources=[],
        ).model_dump()

    db = get_db_session()
    try:
        raw_result = _screening_service.screen_text(db, content, context=context_note)
        elapsed_ms = (time.perf_counter() - t0) * 1000
        logger.info(
            "[tool] screen_file | verdict=%s risk=%d in %.1f ms",
            raw_result.get("verdict"), raw_result.get("risk_score", 0), elapsed_ms
        )

        iocs_data = raw_result.get("iocs", {})
        iocs_model = IOCExtractionResult(
            ipv4=iocs_data.get("ipv4", []),
            urls=iocs_data.get("urls", []),
            domains=iocs_data.get("domains", []),
            md5=iocs_data.get("md5", []),
            sha1=iocs_data.get("sha1", []),
            sha256=iocs_data.get("sha256", []),
            extraction_source="regex",
        )

        verdict_str = raw_result.get("verdict", "INCONCLUSIVE")
        if verdict_str not in {"BENIGN", "SUSPICIOUS", "MALICIOUS", "INCONCLUSIVE"}:
            verdict_str = "INCONCLUSIVE"

        action_str = raw_result.get("recommended_action", "REVIEW")
        if action_str not in {"PASS", "QUARANTINE", "BLOCK", "REVIEW"}:
            action_str = "REVIEW"

        result = SecurityScreeningResult(
            verdict=verdict_str,
            risk_score=int(raw_result.get("risk_score", 0)),
            confidence=float(raw_result.get("confidence", 0.5)),
            threat_category=str(raw_result.get("threat_category", "Unknown")),
            prompt_injection_detected=bool(raw_result.get("prompt_injection_detected", False)),
            mitre_techniques=list(raw_result.get("mitre_techniques", [])),
            summary=str(raw_result.get("summary", "")),
            findings=list(raw_result.get("findings", [])),
            recommended_action=action_str,
            iocs=iocs_model,
            sources=list(raw_result.get("sources", [])),
        )
        return result.model_dump()
    finally:
        db.close()
