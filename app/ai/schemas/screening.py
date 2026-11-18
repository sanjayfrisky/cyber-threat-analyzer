"""Pydantic schemas for IOC extraction and security screening results."""
from __future__ import annotations

from typing import Literal

from pydantic import BaseModel, Field


class IOCExtractionResult(BaseModel):
    """Indicators of Compromise extracted via regex from text."""

    ipv4: list[str] = Field(default_factory=list, description="Valid IPv4 addresses found in text")
    urls: list[str] = Field(default_factory=list, description="HTTP/HTTPS URLs found in text")
    domains: list[str] = Field(default_factory=list, description="Domain names found in text")
    md5: list[str] = Field(default_factory=list, description="MD5 hashes (32 hex chars)")
    sha1: list[str] = Field(default_factory=list, description="SHA-1 hashes (40 hex chars)")
    sha256: list[str] = Field(default_factory=list, description="SHA-256 hashes (64 hex chars)")

    extraction_source: str = Field(
        default="regex",
        description="Method used for extraction — always 'regex', never LLM-generated",
    )

    @property
    def has_iocs(self) -> bool:
        """Return True if any IOC category is non-empty."""
        return any([self.ipv4, self.urls, self.domains, self.md5, self.sha1, self.sha256])

    @property
    def total_count(self) -> int:
        return sum(len(x) for x in [self.ipv4, self.urls, self.domains, self.md5, self.sha1, self.sha256])


class SecurityScreeningResult(BaseModel):
    """
    Result of a security screening operation.

    Separates:
    - Heuristic/regex findings (confirmed source)
    - AI-generated triage verdict (labeled)
    - Retrieved threat intelligence evidence
    """

    verdict: Literal["BENIGN", "SUSPICIOUS", "MALICIOUS", "INCONCLUSIVE"] = Field(
        description="[AI-ASSISTED] Overall verdict — may be heuristic fallback"
    )
    risk_score: int = Field(ge=0, le=100, description="Numeric risk score 0–100")
    confidence: float = Field(ge=0.0, le=1.0, description="Model confidence 0.0–1.0")
    threat_category: str = Field(description="Broad threat category or 'Unknown'")

    # Confirmed source findings
    prompt_injection_detected: bool = Field(
        description="[CONFIRMED] Whether a prompt-injection/jailbreak pattern was found by regex"
    )
    mitre_techniques: list[str] = Field(
        default_factory=list,
        description="[CONFIRMED] MITRE ATT&CK technique IDs matched by heuristic patterns",
    )

    # AI-generated
    summary: str = Field(description="[AI-GENERATED] One-paragraph triage summary")
    findings: list[str] = Field(
        default_factory=list,
        description="[AI-GENERATED/HEURISTIC] Specific findings from the screening",
    )
    recommended_action: Literal["PASS", "QUARANTINE", "BLOCK", "REVIEW"] = Field(
        description="Recommended disposition"
    )

    # Extracted IOCs (confirmed by regex)
    iocs: IOCExtractionResult = Field(description="[CONFIRMED] Indicators extracted by regex")

    # Retrieved intelligence
    sources: list[dict] = Field(
        default_factory=list,
        description="Threat intelligence sources retrieved from the vector DB",
    )
