"""Pydantic schema for remediation recommendation results."""
from __future__ import annotations

from pydantic import BaseModel, Field

_DISCLAIMER = (
    "AI-generated remediation suggestions are provided for guidance only. "
    "Always verify patch availability and applicability with the official vendor "
    "advisory before deploying any fix in a production environment."
)


class RemediationResult(BaseModel):
    """
    Structured remediation recommendation for a CVE + affected product pair.

    Clearly separates:
    - Verified source information (vendor advisories, NVD references)
    - AI-generated remediation steps
    """

    cve_id: str = Field(description="The CVE identifier this remediation applies to")
    affected_product: str = Field(description="Product or component name provided by caller")

    # Confirmed source information — only populated from indexed records
    vendor_advisories: list[str] = Field(
        default_factory=list,
        description="[CONFIRMED SOURCE] Vendor advisory URLs from NVD references or indexed records",
    )
    patch_references: list[str] = Field(
        default_factory=list,
        description="[CONFIRMED SOURCE] Patch download or changelog URLs from NVD/vendor data",
    )
    source_urls: list[str] = Field(
        default_factory=list,
        description="All source URLs used to build this result",
    )

    # Retrieved evidence
    retrieved_evidence: list[str] = Field(
        default_factory=list,
        description="Content snippets from the vector DB relevant to this CVE",
    )

    # AI-generated content — explicitly labeled
    remediation_steps: list[str] = Field(
        default_factory=list,
        description="[AI-GENERATED] Step-by-step remediation suggestions — verify before applying",
    )
    ai_generated_warnings: list[str] = Field(
        default_factory=list,
        description="[AI-GENERATED] Caveats and warnings about the remediation",
    )

    # Disclaimer always included
    disclaimer: str = Field(
        default=_DISCLAIMER,
        description="Mandatory disclaimer about AI-generated remediation content",
    )

    confirmed_source: str | None = Field(
        default=None,
        description="Data origin: 'NVD', 'DB', or None if not found",
    )
    missing_info: list[str] = Field(
        default_factory=list,
        description="Information that could not be sourced from indexed records",
    )
