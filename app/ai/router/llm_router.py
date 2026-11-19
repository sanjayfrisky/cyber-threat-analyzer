"""LLM Router: Analyzes incoming user prompts, classifies intent, rewrites search query, and identifies candidate tools."""
from __future__ import annotations

import json
import logging
import re
from typing import Any

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
    registry as default_registry,
)
from app.ai.llm.model_factory import build_model_with_retry_and_fallback

logger = logging.getLogger(__name__)


class RoutingDecision(BaseModel):
    """Structured decision produced by the LLM Router."""

    intent: str = Field(
        default="general_rag",
        description="Query intent category: cve_remediation, cve_exploitation, cve_cvss, cve_general, command_analysis, mitre_analysis, ioc_analysis, screening, or general_rag",
    )
    needs_rag: bool = Field(
        default=True,
        description="Whether to query the indexed cybersecurity knowledge base (pgvector + full-text)",
    )
    rewritten_rag_query: str = Field(
        default="",
        description="Optimized query keywords formulated specifically for vector and keyword search",
    )
    candidate_tools: list[str] = Field(
        default_factory=list,
        description="Names of candidate tools that may be called if RAG evidence needs verification",
    )
    reasoning: str = Field(
        default="",
        description="Brief explanation of the routing classification",
    )


ROUTER_SYSTEM_PROMPT = """You are a cybersecurity query classification router.
Analyze the user's prompt and output a JSON object with:
1. "intent": one of ["cve_remediation", "cve_exploitation", "cve_cvss", "cve_general", "command_analysis", "mitre_analysis", "ioc_analysis", "screening", "general_rag"]
2. "needs_rag": boolean (almost always true unless it is purely conversational like 'hello')
3. "rewritten_rag_query": a clean, keyword-dense search query (extract CVE IDs, attack technique IDs, product names, or threat keywords)
4. "candidate_tools": list of tool names selected from:
   - "cve_lookup": for CVE vulnerability details
   - "kev_lookup": for CISA Known Exploited Vulnerabilities status
   - "mitre_lookup": for MITRE ATT&CK technique details
   - "cvss_analysis": for CVSS score, vector, and severity breakdown
   - "extract_iocs_tool": for extracting IP, domain, hash, URL indicators
   - "analyze_command": for suspicious PowerShell, bash, or CMD commands
   - "screen_file": for file screening and quarantine triage
   - "get_remediation": for mitigation and remediation steps
   - "enrich_threat_intel": for threat actor and IOC enrichment
   - "rag_retrieve": for general cybersecurity knowledge retrieval
5. "reasoning": 1-sentence justification

Respond with pure JSON only, matching this structure. Do not include markdown code fences or explanatory text.
"""


class LLMRouter:
    """Intelligent query router with LLM classification and robust heuristic fallback."""

    def __init__(self, llm=None):
        self._llm = llm

    def _get_llm(self):
        if self._llm is None:
            self._llm = build_model_with_retry_and_fallback()
        return self._llm

    def heuristic_route(self, query: str) -> RoutingDecision:
        """Fast regex-based fallback routing if LLM routing fails or times out."""
        text = query.strip()
        has_cve = bool(_CVE_REGEX.search(text))
        has_cmd = bool(_SHELL_CMD_REGEX.search(text))
        has_mitre = bool(_MITRE_REGEX.search(text))
        has_fix = bool(_FIX_KEYWORDS.search(text))
        has_exploit = bool(_EXPLOIT_KEYWORDS.search(text))
        has_cvss = bool(_CVSS_KEYWORDS.search(text))
        has_screening = bool(_SCREENING_KEYWORDS.search(text))

        cve_match = _CVE_REGEX.search(text)
        cve_id = cve_match.group(0).upper() if cve_match else ""

        mitre_match = _MITRE_REGEX.search(text)
        mitre_id = mitre_match.group(0).upper() if mitre_match else ""

        if has_screening:
            return RoutingDecision(
                intent="screening",
                needs_rag=True,
                rewritten_rag_query=text,
                candidate_tools=["screen_file", "extract_iocs_tool", "rag_retrieve"],
                reasoning="Heuristic matched file screening keywords",
            )
        if has_cve and has_fix:
            return RoutingDecision(
                intent="cve_remediation",
                needs_rag=True,
                rewritten_rag_query=f"{cve_id} patch remediation fix workaround",
                candidate_tools=["cve_lookup", "kev_lookup", "get_remediation", "cvss_analysis"],
                reasoning=f"Heuristic detected CVE ({cve_id}) with remediation request",
            )
        if has_cve and has_exploit:
            return RoutingDecision(
                intent="cve_exploitation",
                needs_rag=True,
                rewritten_rag_query=f"{cve_id} exploit active exploitation CISA KEV",
                candidate_tools=["cve_lookup", "kev_lookup"],
                reasoning=f"Heuristic detected CVE ({cve_id}) with exploitation check",
            )
        if has_cve and has_cvss:
            return RoutingDecision(
                intent="cve_cvss",
                needs_rag=True,
                rewritten_rag_query=f"{cve_id} cvss score base score severity",
                candidate_tools=["cve_lookup", "cvss_analysis"],
                reasoning=f"Heuristic detected CVE ({cve_id}) with CVSS inquiry",
            )
        if has_cve:
            return RoutingDecision(
                intent="cve_general",
                needs_rag=True,
                rewritten_rag_query=f"{cve_id} vulnerability overview",
                candidate_tools=["cve_lookup", "kev_lookup", "rag_retrieve"],
                reasoning=f"Heuristic detected CVE ({cve_id})",
            )
        if has_cmd:
            return RoutingDecision(
                intent="command_analysis",
                needs_rag=True,
                rewritten_rag_query=f"suspicious command analysis {text[:100]}",
                candidate_tools=["analyze_command", "mitre_lookup", "rag_retrieve"],
                reasoning="Heuristic detected suspicious shell/system command tokens",
            )
        if has_mitre:
            return RoutingDecision(
                intent="mitre_analysis",
                needs_rag=True,
                rewritten_rag_query=f"MITRE ATT&CK {mitre_id} technique",
                candidate_tools=["mitre_lookup", "rag_retrieve"],
                reasoning=f"Heuristic detected MITRE technique ID ({mitre_id})",
            )
        if _IOC_REGEX.search(text):
            return RoutingDecision(
                intent="ioc_analysis",
                needs_rag=True,
                rewritten_rag_query=f"indicators of compromise {text[:120]}",
                candidate_tools=["extract_iocs_tool", "enrich_threat_intel", "rag_retrieve"],
                reasoning="Heuristic detected IP/domain/hash IOC patterns",
            )

        return RoutingDecision(
            intent="general_rag",
            needs_rag=True,
            rewritten_rag_query=text,
            candidate_tools=["rag_retrieve", "cve_lookup", "mitre_lookup"],
            reasoning="General threat intelligence query",
        )

    async def route(self, query: str) -> RoutingDecision:
        """Route the user query using the configured LLM with heuristic fallback."""
        if not query or not query.strip():
            return self.heuristic_route(query)

        try:
            model = self._get_llm()
            # Try structured output if supported by model
            if hasattr(model, "with_structured_output"):
                try:
                    structured_llm = model.with_structured_output(RoutingDecision)
                    decision = await structured_llm.ainvoke(
                        f"{ROUTER_SYSTEM_PROMPT}\n\nUser Query: {query}"
                    )
                    if isinstance(decision, RoutingDecision):
                        if not decision.rewritten_rag_query:
                            decision.rewritten_rag_query = query
                        logger.info(
                            "[llm_router] routed via structured output: intent=%s, tools=%s",
                            decision.intent,
                            decision.candidate_tools,
                        )
                        return decision
                except Exception as structured_err:
                    logger.debug(
                        "[llm_router] with_structured_output failed: %s; falling back to direct prompt",
                        structured_err,
                    )

            # Direct prompt approach
            from langchain_core.messages import HumanMessage, SystemMessage

            response = await model.ainvoke([
                SystemMessage(content=ROUTER_SYSTEM_PROMPT),
                HumanMessage(content=f"User Query:\n{query}"),
            ])

            raw_text = str(response.content).strip()
            # Clean possible markdown formatting
            if raw_text.startswith("```"):
                lines = raw_text.split("\n")
                if lines[0].startswith("```"):
                    lines = lines[1:]
                if lines and lines[-1].startswith("```"):
                    lines = lines[:-1]
                raw_text = "\n".join(lines).strip()

            data = json.loads(raw_text)
            decision = RoutingDecision(
                intent=data.get("intent", "general_rag"),
                needs_rag=data.get("needs_rag", True),
                rewritten_rag_query=data.get("rewritten_rag_query") or query,
                candidate_tools=data.get("candidate_tools", []),
                reasoning=data.get("reasoning", "LLM classified query"),
            )
            logger.info(
                "[llm_router] routed: intent=%s, candidate_tools=%s, reasoning=%s",
                decision.intent,
                decision.candidate_tools,
                decision.reasoning,
            )
            return decision

        except Exception as exc:
            logger.warning("[llm_router] LLM classification error: %s; using heuristic fallback", exc)
            return self.heuristic_route(query)


# Global shared router
default_router = LLMRouter()
