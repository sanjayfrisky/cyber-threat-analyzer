"""Pydantic schemas for generic tool execution results and threat intelligence enrichment."""
from __future__ import annotations

from pydantic import BaseModel, Field


class ToolExecutionResult(BaseModel):
    """
    Wrapper for any tool call result.

    Provides a consistent envelope: success/failure, timing, and source attribution.
    """

    tool_name: str = Field(description="Name of the tool that produced this result")
    success: bool = Field(description="Whether the tool completed without error")
    result: dict | None = Field(
        default=None,
        description="Serialisable tool output — None on failure",
    )
    error: str | None = Field(
        default=None,
        description="Sanitised error message — API keys and internals are stripped",
    )
    execution_time_ms: float = Field(
        default=0.0,
        description="Wall-clock execution time in milliseconds",
    )
    source_attribution: list[str] = Field(
        default_factory=list,
        description="Data sources consulted: 'NVD', 'CISA', 'MITRE', 'DB', 'regex'",
    )


class ThreatIntelligenceResult(BaseModel):
    """
    Enriched threat intelligence result combining all available data sources.

    Every field is tagged by its data origin so the caller knows what is
    confirmed vs AI-generated.
    """

    indicator: str = Field(
        description="The IOC or CVE identifier that was enriched"
    )

    # Source-confirmed data blocks
    nvd_data: dict | None = Field(
        default=None,
        description="[CONFIRMED SOURCE] NVD or DB record for this indicator (if CVE)",
    )
    cisa_kev_data: dict | None = Field(
        default=None,
        description="[CONFIRMED SOURCE] CISA KEV record if the indicator is a known-exploited CVE",
    )
    mitre_data: list[dict] = Field(
        default_factory=list,
        description="[CONFIRMED SOURCE] Matching MITRE ATT&CK technique records",
    )
    retrieved_docs: list[dict] = Field(
        default_factory=list,
        description="[CONFIRMED SOURCE] Relevant document chunks from the vector DB",
    )

    # AI-generated
    combined_assessment: str = Field(
        default="",
        description="[AI-GENERATED] Synthesised assessment across all sources",
    )

    # Traceability
    source_urls: list[str] = Field(
        default_factory=list,
        description="All source URLs referenced in this result",
    )
    sources_consulted: list[str] = Field(
        default_factory=list,
        description="Data sources checked: 'NVD', 'CISA', 'MITRE', 'DB', 'RAG'",
    )
    missing_info: list[str] = Field(
        default_factory=list,
        description="Information that could not be found in any configured source",
    )
