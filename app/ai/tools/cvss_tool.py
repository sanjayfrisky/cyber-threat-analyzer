"""Tool 5: CVSS Analysis — parses and explains a CVSS v3.x vector string."""
from __future__ import annotations

import logging
import re
import time

from langchain_core.tools import tool
from pydantic import BaseModel, Field

from app.ai.schemas.cve import CVSSAnalysis

logger = logging.getLogger(__name__)

# CVSS v3.x metric decode maps
_AV = {"N": "Network", "A": "Adjacent", "L": "Local", "P": "Physical"}
_AC = {"L": "Low", "H": "High"}
_PR = {"N": "None", "L": "Low", "H": "High"}
_UI = {"N": "None", "R": "Required"}
_SC = {"U": "Unchanged", "C": "Changed"}
_IMP = {"N": "None", "L": "Low", "H": "High"}


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


def _parse_cvss_vector(vector: str) -> CVSSAnalysis:
    """
    Parse a CVSS v3.x vector string and return a CVSSAnalysis.
    Example: CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H
    """
    vector = vector.strip()
    # Determine version
    version = "3.1"
    if vector.startswith("CVSS:3.0"):
        version = "3.0"
    elif vector.startswith("CVSS:3.1"):
        version = "3.1"

    # Strip prefix
    cleaned = re.sub(r"^CVSS:[23]\.[01]/", "", vector)
    metrics = dict(part.split(":") for part in cleaned.split("/") if ":" in part)

    base_score = None
    # Try to extract base score if present in the cleaned vector (e.g. appended after space or slash)
    score_match = re.search(r"(?:[\s/:]|^)(\d{1,2}\.\d)\b", cleaned)
    if score_match:
        try:
            base_score = float(score_match.group(1))
        except ValueError:
            pass

    return CVSSAnalysis(
        vector_string=vector,
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
        exploitability_assessment="",   # Filled by agent LLM after tool call
        source="CVSS vector parsing (no external call)",
    )


class CVSSAnalysisInput(BaseModel):
    cvss_vector_or_cve: str = Field(
        description=(
            "A CVSS v3.x vector string (e.g. CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H) "
            "or a CVE ID whose CVSS vector you want explained."
        )
    )


@tool(args_schema=CVSSAnalysisInput)
def cvss_analysis(cvss_vector_or_cve: str) -> dict:
    """
    Parse and explain a CVSS v3.x vector string.

    Decodes Attack Vector, Attack Complexity, Privileges Required, Scope,
    and impact metrics from the vector — no external API calls.

    If a CVE ID is provided instead of a vector string, use cve_lookup first
    to retrieve the vector, then call this tool with the vector.

    Returns a structured CVSSAnalysis dict with all metrics decoded.
    """
    t0 = time.perf_counter()
    value = cvss_vector_or_cve.strip()
    logger.info("[tool] cvss_analysis | input='%s'", value[:80])

    # Detect if it looks like a CVE ID rather than a vector
    if re.match(r"^CVE-\d{4}-\d{4,}$", value, re.IGNORECASE):
        elapsed_ms = (time.perf_counter() - t0) * 1000
        logger.info("[tool] cvss_analysis | received CVE ID, not a vector (%.1f ms)", elapsed_ms)
        return {
            "error": (
                f"'{value}' is a CVE ID, not a CVSS vector. "
                "Please use cve_lookup first to retrieve the CVSS vector, "
                "then call cvss_analysis with the vector string."
            ),
            "suggestion": "Use cve_lookup to get the CVSS vector for this CVE.",
        }

    if "AV:" not in value.upper():
        elapsed_ms = (time.perf_counter() - t0) * 1000
        logger.warning("[tool] cvss_analysis | unrecognised input format (%.1f ms)", elapsed_ms)
        return {
            "error": f"Input does not appear to be a valid CVSS v3.x vector: '{value[:80]}'",
            "hint": "Expected format: CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
        }

    result = _parse_cvss_vector(value)
    elapsed_ms = (time.perf_counter() - t0) * 1000
    logger.info("[tool] cvss_analysis | parsed in %.1f ms", elapsed_ms)
    return result.model_dump()
