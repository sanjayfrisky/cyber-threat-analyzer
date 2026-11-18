"""Pydantic schemas for CVE and CVSS analysis results."""
from __future__ import annotations

from typing import Literal

from pydantic import BaseModel, Field


class CVEAnalysis(BaseModel):
    """
    Structured result for a CVE lookup.

    Fields are separated by traceability category so callers can distinguish
    confirmed source data from AI-generated explanation.
    """

    cve_id: str = Field(description="The CVE identifier, e.g. CVE-2024-12345")
    description: str = Field(description="Official CVE description from NVD or DB")
    cvss_score: float | None = Field(default=None, description="CVSS base score (0.0–10.0)")
    severity: Literal["CRITICAL", "HIGH", "MEDIUM", "LOW", "NONE", "UNKNOWN"] | None = Field(
        default=None, description="CVSS severity label"
    )
    affected_products: list[str] = Field(
        default_factory=list,
        description="CPE or product strings from the indexed record",
    )
    references: list[str] = Field(
        default_factory=list,
        description="Source URLs from NVD or indexed record",
    )

    # --- Traceability ---
    confirmed_source: str | None = Field(
        default=None,
        description="Data origin: 'NVD', 'CISA', 'MITRE', or 'DB'",
    )
    retrieved_evidence: list[str] = Field(
        default_factory=list,
        description="Raw content snippets from the vector DB used to populate this record",
    )
    ai_explanation: str = Field(
        default="",
        description="[AI-GENERATED] Plain-language explanation of the vulnerability",
    )
    missing_info: list[str] = Field(
        default_factory=list,
        description="Fields that could not be populated from available sources",
    )


class CVSSAnalysis(BaseModel):
    """
    Structured breakdown of a CVSS v3.x vector string.

    All metric values are decoded from the vector string; they are NOT
    AI-generated.  Only 'exploitability_assessment' is LLM-produced.
    """

    vector_string: str = Field(description="Original CVSS vector, e.g. CVSS:3.1/AV:N/AC:L/...")
    version: str = Field(default="3.1", description="CVSS version parsed from vector")
    base_score: float | None = Field(default=None, description="Numeric base score if available")
    severity: str = Field(default="UNKNOWN", description="Severity label derived from base score")

    # Individual metric decoded values (confirmed from vector)
    attack_vector: str = Field(default="UNKNOWN")
    attack_complexity: str = Field(default="UNKNOWN")
    privileges_required: str = Field(default="UNKNOWN")
    user_interaction: str = Field(default="UNKNOWN")
    scope: str = Field(default="UNKNOWN")
    confidentiality_impact: str = Field(default="UNKNOWN")
    integrity_impact: str = Field(default="UNKNOWN")
    availability_impact: str = Field(default="UNKNOWN")

    # AI-generated field — clearly labeled
    exploitability_assessment: str = Field(
        default="",
        description="[AI-GENERATED] Explanation of real-world exploitability vs CVSS score",
    )

    source: str = Field(
        default="CVSS vector parsing",
        description="How the analysis was produced",
    )
