"""End-to-end agent workflow orchestrator: Intent -> Conditional Tools -> Execution -> Validation -> Response."""
from __future__ import annotations

import logging
import time
from typing import Any

from app.ai.agent.agent_factory import create_cybersecurity_agent
from app.ai.agent.tool_registry import ToolRegistry, registry as default_registry
from app.ai.llm.model_factory import build_model_with_retry_and_fallback
from app.ai.schemas.tool_result import ToolExecutionResult

logger = logging.getLogger(__name__)


class AgentWorkflow:
    """Orchestrates intent classification, conditional tool binding, execution, and output validation."""

    def __init__(self, registry: ToolRegistry | None = None):
        self.registry = registry or default_registry

    async def execute(self, query: str, session_id: str = "default-session") -> dict[str, Any]:
        """
        Run the complete pipeline:
        1. Identify intent
        2. Filter and select relevant tools
        3. Instantiate agent with selected tools
        4. Execute bounded agent loop
        5. Extract sources and format final structured response
        """
        t0 = time.perf_counter()
        logger.info("[workflow] starting analysis for session='%s' query='%s'", session_id, query[:80])

        # Step 1: Identify intent
        intent = self.registry.identify_intent(query)

        # Step 2: Select relevant tools
        selected_tools = self.registry.select_tools_for_query(query)

        # Step 3: Build agent with chosen tools & resilient multi-provider fallback
        agent = create_cybersecurity_agent(tools=selected_tools)

        # Step 4: Execute agent
        agent_result = await agent.run(query)

        # Step 5: Extract and validate source citations from tool outputs
        sources = self._extract_sources_from_tool_results(agent_result.get("tool_results", []))

        elapsed_ms = (time.perf_counter() - t0) * 1000
        logger.info(
            "[workflow] finished for session='%s' in %.1f ms with %d sources",
            session_id, elapsed_ms, len(sources)
        )

        return {
            "session_id": session_id,
            "query": query,
            "intent": intent,
            "answer": agent_result["answer"],
            "tools_used": agent_result["tools_executed"],
            "tool_details": agent_result["tool_results"],
            "sources": sources,
            "iterations": agent_result["iterations"],
            "execution_time_ms": elapsed_ms,
        }

    def _extract_sources_from_tool_results(self, tool_results: list[dict[str, Any]]) -> list[dict[str, Any]]:
        """Harvest ground-truth citations and URLs returned by tools without inventing citations."""
        sources: list[dict[str, Any]] = []
        seen_urls: set[str] = set()

        for idx, tr in enumerate(tool_results, 1):
            out = tr.get("output", {})
            if not isinstance(out, dict):
                continue

            # RAG tool results
            if "results" in out and isinstance(out["results"], list):
                for r in out["results"]:
                    if isinstance(r, dict):
                        url = r.get("url") or ""
                        if url and url in seen_urls:
                            continue
                        if url:
                            seen_urls.add(url)
                        sources.append({
                            "citation": f"S{len(sources) + 1}",
                            "source": r.get("source", "vector_db"),
                            "id": r.get("external_id", "doc"),
                            "title": r.get("title", "Threat Intelligence Record"),
                            "url": url or None,
                        })

            # CVE / KEV / MITRE tool direct results
            url = out.get("url")
            if url and url not in seen_urls:
                seen_urls.add(url)
                sources.append({
                    "citation": f"S{len(sources) + 1}",
                    "source": out.get("confirmed_source") or tr.get("tool_name"),
                    "id": out.get("cve_id") or out.get("technique_id") or "ref",
                    "title": out.get("title") or out.get("name") or tr.get("tool_name"),
                    "url": url,
                })

            # Check for source_urls array
            for u in out.get("source_urls", []):
                if u and u not in seen_urls:
                    seen_urls.add(u)
                    sources.append({
                        "citation": f"S{len(sources) + 1}",
                        "source": out.get("confirmed_source", "tool_reference"),
                        "id": "url_ref",
                        "title": "Authoritative Reference",
                        "url": u,
                    })

        return sources


# Global workflow instance
default_workflow = AgentWorkflow()
