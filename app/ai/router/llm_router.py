"""LLM Router: Analyzes incoming user prompts and performs single-step distribution:
- If RAG: RAG alone answers
- If Tool: Only the single needed tool is executed and answers
- If General: Direct conversational response
No multi-tool looping.
"""
from __future__ import annotations

import json
import logging
import re
from typing import Any, Literal

from pydantic import BaseModel, Field

from app.ai.agent.tool_registry import (
    _CVE_REGEX,
    _CVSS_KEYWORDS,
    _EXPLOIT_KEYWORDS,
    _FIX_KEYWORDS,
    _IOC_REGEX,
    _MITRE_REGEX,
    _SCREENING_KEYWORDS,
    _SHELL_CMD_REGEX,
)
from app.ai.llm.model_factory import build_model_with_retry_and_fallback

logger = logging.getLogger(__name__)


class RoutingDecision(BaseModel):
    """Structured decision produced by the LLM Router for single-step distribution."""

    destination: Literal["rag", "tool", "general"] = Field(
        default="rag",
        description="Single-step destination: 'rag' for knowledge retrieval, 'tool' for specific tool execution, or 'general'",
    )
    selected_tool: str | None = Field(
        default=None,
        description="Name of the exact tool needed if destination is 'tool'",
    )
    tool_args: dict[str, Any] = Field(
        default_factory=dict,
        description="Arguments to pass to the selected tool",
    )
    rag_query: str = Field(
        default="",
        description="Search query for RAG when destination is 'rag'",
    )
    intent: str = Field(
        default="general_rag",
        description="Detailed intent identifier",
    )
    rewritten_rag_query: str = Field(
        default="",
        description="Backwards-compatible alias for rag_query",
    )
    candidate_tools: list[str] = Field(
        default_factory=list,
        description="Backwards-compatible list containing the selected tool",
    )
    reasoning: str = Field(
        default="",
        description="1-sentence explanation of routing choice",
    )


ROUTER_SYSTEM_PROMPT = """You are a cybersecurity query classification router.
Analyze the user's prompt and choose EXACTLY ONE destination from:
1. "rag": For general cybersecurity concepts, architectural defense, threat landscape overviews, or broad conceptual questions. RAG alone will retrieve knowledge and answer.
2. "tool": When a SINGLE specific cybersecurity tool is needed to answer:
   - "cve_lookup": when asking for specific CVE vulnerability details (arg: cve_id)
   - "kev_lookup": when explicitly asking if a CVE is actively exploited in CISA KEV (arg: cve_id)
   - "mitre_lookup": when asking about a specific MITRE ATT&CK technique (e.g. T1059) (arg: technique_id_or_query)
   - "cvss_analysis": when asking to decode or parse a CVSS vector (arg: cvss_vector_or_cve)
   - "analyze_command": when inspecting a suspicious PowerShell, CMD, or Bash command (arg: command)
   - "extract_iocs_tool": when extracting IOCs (IPs, hashes, domains, URLs) from text (arg: text)
   - "screen_file": when screening file content for prompt injection or stagers (arg: file_content_or_text)
   - "get_remediation": when asking for specific remediation or patch guidance for a CVE (arg: cve_id)
   - "enrich_threat_intel": when enriching a specific threat actor or indicator (arg: query)
3. "general": For greetings or generic conversational messages that require no security retrieval.

Respond with pure JSON only:
{
  "destination": "rag" | "tool" | "general",
  "selected_tool": "<tool_name or null>",
  "tool_args": {"<arg_name>": "<arg_value>"},
  "rag_query": "<search keywords if destination is rag>",
  "intent": "<intent_name>",
  "reasoning": "<brief explanation>"
}
No markdown code fences or extra text. Pure JSON only.
"""


class LLMRouter:
    """Intelligent query router with single-step distribution and robust heuristic fallback."""

    def __init__(self, llm=None):
        self._llm = llm

    def _get_llm(self):
        if self._llm is None:
            self._llm = build_model_with_retry_and_fallback()
        return self._llm

    def heuristic_route(self, query: str) -> RoutingDecision:
        """Fast regex-based heuristic single-step distribution."""
        text = query.strip()
        cve_match = _CVE_REGEX.search(text)
        cve_id = cve_match.group(0).upper() if cve_match else ""

        mitre_match = _MITRE_REGEX.search(text)
        mitre_id = mitre_match.group(0).upper() if mitre_match else ""

        has_cmd = bool(_SHELL_CMD_REGEX.search(text))
        has_fix = bool(_FIX_KEYWORDS.search(text))
        has_exploit = bool(_EXPLOIT_KEYWORDS.search(text))
        has_cvss = bool(_CVSS_KEYWORDS.search(text))
        has_screening = bool(_SCREENING_KEYWORDS.search(text))

        # Check CVSS vector string specifically
        if "CVSS:" in text.upper() or (has_cvss and not cve_id):
            return RoutingDecision(
                destination="tool",
                selected_tool="cvss_analysis",
                tool_args={"cvss_vector_or_cve": text},
                intent="cve_cvss",
                candidate_tools=["cvss_analysis"],
                reasoning="Heuristic routed to cvss_analysis tool",
            )

        # Check File Screening
        if has_screening:
            return RoutingDecision(
                destination="tool",
                selected_tool="screen_file",
                tool_args={"file_content_or_text": text},
                intent="screening",
                candidate_tools=["screen_file"],
                reasoning="Heuristic routed to screen_file tool",
            )

        # Check Suspicious Shell Command
        if has_cmd:
            return RoutingDecision(
                destination="tool",
                selected_tool="analyze_command",
                tool_args={"command": text},
                intent="command_analysis",
                candidate_tools=["analyze_command"],
                reasoning="Heuristic routed to analyze_command tool",
            )

        # Check MITRE technique ID
        if mitre_id:
            return RoutingDecision(
                destination="tool",
                selected_tool="mitre_lookup",
                tool_args={"technique_id": mitre_id},
                intent="mitre_analysis",
                candidate_tools=["mitre_lookup"],
                reasoning=f"Heuristic routed to mitre_lookup for technique {mitre_id}",
            )

        # Check CVE-specific queries
        if cve_id:
            if has_fix:
                return RoutingDecision(
                    destination="tool",
                    selected_tool="get_remediation",
                    tool_args={"cve_id": cve_id, "remediation_query": text},
                    intent="cve_remediation",
                    candidate_tools=["get_remediation"],
                    rag_query=f"{cve_id} patch remediation",
                    rewritten_rag_query=f"{cve_id} patch remediation",
                    reasoning=f"Heuristic routed to get_remediation tool for {cve_id}",
                )
            if has_exploit:
                return RoutingDecision(
                    destination="tool",
                    selected_tool="kev_lookup",
                    tool_args={"cve_id": cve_id},
                    intent="cve_exploitation",
                    candidate_tools=["kev_lookup"],
                    reasoning=f"Heuristic routed to kev_lookup tool for {cve_id}",
                )
            # Default CVE lookup
            return RoutingDecision(
                destination="tool",
                selected_tool="cve_lookup",
                tool_args={"cve_id": cve_id},
                intent="cve_general",
                candidate_tools=["cve_lookup"],
                reasoning=f"Heuristic routed to cve_lookup tool for {cve_id}",
            )

        # Check IOC patterns
        if _IOC_REGEX.search(text) and len(text.split()) < 15:
            return RoutingDecision(
                destination="tool",
                selected_tool="extract_iocs_tool",
                tool_args={"text": text},
                intent="ioc_analysis",
                candidate_tools=["extract_iocs_tool"],
                reasoning="Heuristic routed to extract_iocs_tool",
            )

        # Default: RAG knowledge retrieval
        return RoutingDecision(
            destination="rag",
            selected_tool=None,
            tool_args={},
            rag_query=text,
            rewritten_rag_query=text,
            intent="general_rag",
            candidate_tools=["rag_retrieve"],
            reasoning="Defaulted to RAG knowledge base retrieval",
        )

    async def route(self, query: str) -> RoutingDecision:
        """Route the user query to a single destination using the configured LLM with heuristic fallback."""
        if not query or not query.strip():
            return self.heuristic_route(query)

        try:
            model = self._get_llm()
            from langchain_core.messages import HumanMessage, SystemMessage

            response = await model.ainvoke([
                SystemMessage(content=ROUTER_SYSTEM_PROMPT),
                HumanMessage(content=f"User Query:\n{query}"),
            ])

            raw_text = str(response.content).strip()
            if raw_text.startswith("```"):
                lines = raw_text.split("\n")
                if lines[0].startswith("```"):
                    lines = lines[1:]
                if lines and lines[-1].startswith("```"):
                    lines = lines[:-1]
                raw_text = "\n".join(lines).strip()

            data = json.loads(raw_text)
            dest = data.get("destination", "rag")
            selected_tool = data.get("selected_tool")
            tool_args = data.get("tool_args", {})
            rag_query = data.get("rag_query") or query

            decision = RoutingDecision(
                destination=dest if dest in ("rag", "tool", "general") else "rag",
                selected_tool=selected_tool,
                tool_args=tool_args,
                rag_query=rag_query,
                rewritten_rag_query=rag_query,
                intent=data.get("intent", "general_rag"),
                candidate_tools=[selected_tool] if selected_tool else ["rag_retrieve"],
                reasoning=data.get("reasoning", "LLM classified single-step route"),
            )
            logger.info(
                "[llm_router] Single-step route: destination=%s, tool=%s, args=%s",
                decision.destination,
                decision.selected_tool,
                decision.tool_args,
            )
            return decision

        except Exception as exc:
            logger.warning("[llm_router] LLM classification error: %s; using heuristic fallback", exc)
            return self.heuristic_route(query)


# Global shared router
default_router = LLMRouter()
