"""Tool registry with conditional tool selection and execution safety controls."""
from __future__ import annotations

import logging
import re
from typing import Any, Callable

from langchain_core.tools import BaseTool

from app.ai.tools import (
    ALL_TOOLS,
    analyze_command,
    cve_lookup,
    cvss_analysis,
    enrich_threat_intel,
    extract_iocs_tool,
    get_remediation,
    kev_lookup,
    mitre_lookup,
    rag_retrieve,
    screen_file,
)
from app.core.config import settings

logger = logging.getLogger(__name__)

# Registry mapping tool name -> BaseTool instance
TOOL_MAP: dict[str, BaseTool] = {tool.name: tool for tool in ALL_TOOLS}

# Regex patterns for fast intent identification
_CVE_REGEX = re.compile(r"\bCVE-\d{4}-\d{4,}\b", re.IGNORECASE)
_MITRE_REGEX = re.compile(r"\bT\d{4}(?:\.\d{3})?\b", re.IGNORECASE)
_SHELL_CMD_REGEX = re.compile(
    r"\b(powershell|pwsh|cmd\.exe|bash|sh|wget|curl|certutil|mimikatz|vssadmin|net\s+user)\b",
    re.IGNORECASE,
)
_IOC_REGEX = re.compile(
    r"\b(?:\d{1,3}\.){3}\d{1,3}\b|https?://[^\s]+|\b[a-fA-F0-9]{32,64}\b",
    re.IGNORECASE,
)
_FIX_KEYWORDS = re.compile(
    r"\b(fix|patch|remediate|remediation|mitigate|mitigation|update|upgrade|solution|workaround)\b",
    re.IGNORECASE,
)
_EXPLOIT_KEYWORDS = re.compile(
    r"\b(exploit|exploited|in the wild|active exploitation|kev|cisa|weaponized|poc|proof of concept)\b",
    re.IGNORECASE,
)
_CVSS_KEYWORDS = re.compile(
    r"\b(cvss|vector|score|severity|attack vector|complexity|privileges)\b",
    re.IGNORECASE,
)
_SCREENING_KEYWORDS = re.compile(
    r"\b(screen|screening|quarantine|malicious file|inspect file|attachment|payload|yara)\b",
    re.IGNORECASE,
)


class ToolRegistry:
    """Manages cybersecurity tools, safety boundaries, and conditional tool selection."""

    def __init__(self, tools: list[BaseTool] | None = None):
        self._tools = {t.name: t for t in (tools or ALL_TOOLS)}

    def get_all_tools(self) -> list[BaseTool]:
        """Return all 10 registered tools."""
        return list(self._tools.values())

    def get_tool(self, name: str) -> BaseTool | None:
        """Retrieve a registered tool by its name."""
        return self._tools.get(name)

    def identify_intent(self, query: str) -> str:
        """Classify user query into an operational intent category."""
        text = query.strip()
        has_cve = bool(_CVE_REGEX.search(text))
        has_cmd = bool(_SHELL_CMD_REGEX.search(text))
        has_mitre = bool(_MITRE_REGEX.search(text))
        has_fix = bool(_FIX_KEYWORDS.search(text))
        has_exploit = bool(_EXPLOIT_KEYWORDS.search(text))
        has_cvss = bool(_CVSS_KEYWORDS.search(text))
        has_screening = bool(_SCREENING_KEYWORDS.search(text))

        if has_screening:
            return "screening"
        if has_cve and has_fix:
            return "cve_remediation"
        if has_cve and has_exploit:
            return "cve_exploitation"
        if has_cve and has_cvss:
            return "cve_cvss"
        if has_cve:
            return "cve_general"
        if has_cmd:
            return "command_analysis"
        if has_mitre:
            return "mitre_analysis"
        if _IOC_REGEX.search(text):
            return "ioc_analysis"
        return "general_rag"

    def select_tools_for_query(self, query: str) -> list[BaseTool]:
        """
        Conditionally select only the relevant tools for a given user query.
        Guarantees the agent does NOT bind or call unnecessary tools.
        """
        intent = self.identify_intent(query)
        logger.info("[tool_registry] query intent identified: '%s'", intent)

        selected_names: list[str] = []

        if intent == "cve_exploitation":
            # Example: Is CVE-2025-XXXX actively exploited?
            selected_names = ["cve_lookup", "kev_lookup"]
        elif intent == "cve_remediation":
            # Example: How can I fix this CVE?
            selected_names = ["cve_lookup", "cvss_analysis", "get_remediation", "rag_retrieve"]
        elif intent == "cve_cvss":
            selected_names = ["cve_lookup", "cvss_analysis"]
        elif intent == "cve_general":
            selected_names = ["cve_lookup", "kev_lookup", "rag_retrieve"]
        elif intent == "command_analysis":
            # Example: Explain this suspicious PowerShell command.
            selected_names = ["analyze_command", "mitre_lookup", "rag_retrieve"]
        elif intent == "mitre_analysis":
            selected_names = ["mitre_lookup", "rag_retrieve"]
        elif intent == "ioc_analysis":
            selected_names = ["extract_iocs_tool", "enrich_threat_intel", "rag_retrieve"]
        elif intent == "screening":
            selected_names = ["screen_file", "extract_iocs_tool", "rag_retrieve"]
        else:
            # Default / general threat intelligence query
            selected_names = ["rag_retrieve", "cve_lookup", "mitre_lookup"]

        tools = [self._tools[name] for name in selected_names if name in self._tools]
        logger.info(
            "[tool_registry] bound %d tools: %s",
            len(tools), [t.name for t in tools]
        )
        return tools

    def get_tool_metadata(self) -> list[dict[str, Any]]:
        """Return descriptors and schemas for all registered tools."""
        descriptors = []
        for tool in self._tools.values():
            schema = tool.args_schema.model_json_schema() if tool.args_schema else {}
            descriptors.append({
                "name": tool.name,
                "description": tool.description.strip(),
                "parameters": schema.get("properties", {}),
                "required": schema.get("required", []),
            })
        return descriptors


# Global shared instance
registry = ToolRegistry()
