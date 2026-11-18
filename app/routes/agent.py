"""API routes for the LangChain cybersecurity agent."""
from __future__ import annotations

import logging
from typing import Any

from fastapi import APIRouter, HTTPException
from pydantic import BaseModel, Field

from app.ai.agent.tool_registry import registry
from app.ai.agent.workflow import default_workflow
from app.ai.llm.provider_config import build_provider_configs

logger = logging.getLogger(__name__)

router = APIRouter(tags=["Agent"])


class AgentAnalyzeRequest(BaseModel):
    query: str = Field(..., min_length=1, max_length=10000, description="Cybersecurity query or security prompt")
    session_id: str = Field(default="default-session", description="Session identifier for thread continuity")


class AgentAnalyzeResponse(BaseModel):
    session_id: str
    query: str
    intent: str
    answer: str
    tools_used: list[str]
    tool_details: list[dict[str, Any]]
    sources: list[dict[str, Any]]
    iterations: int
    execution_time_ms: float


@router.post("/agent/analyze", response_model=AgentAnalyzeResponse)
async def analyze_with_agent(payload: AgentAnalyzeRequest) -> AgentAnalyzeResponse:
    """
    Intelligent cybersecurity agent analysis endpoint.

    Executes intent identification, conditional tool calling (CVE, KEV, MITRE, RAG, etc.),
    evidence verification, and returns a structured defense analysis.
    """
    try:
        result = await default_workflow.execute(
            query=payload.query,
            session_id=payload.session_id,
        )
        return AgentAnalyzeResponse(**result)
    except Exception as exc:
        logger.exception("Agent analysis failed for query: %s", payload.query[:80])
        raise HTTPException(
            status_code=500,
            detail=f"Agent analysis failed: {str(exc)}",
        ) from exc


@router.post("/agent/tools")
def list_agent_tools() -> dict[str, Any]:
    """Return all registered cybersecurity tools and their parameter schemas."""
    tools_meta = registry.get_tool_metadata()
    return {
        "count": len(tools_meta),
        "tools": tools_meta,
    }


@router.get("/agent/health")
def agent_health_check() -> dict[str, Any]:
    """Check availability of configured LLM providers and tool registry health."""
    configs = build_provider_configs()
    provider_status = {
        cfg.name: ("available" if cfg.is_available() else "not_configured")
        for cfg in configs
    }
    all_tools = registry.get_all_tools()
    is_healthy = any(status == "available" for status in provider_status.values())

    return {
        "status": "ok" if is_healthy else "degraded",
        "providers": provider_status,
        "tools_registered": len(all_tools),
        "tool_names": [t.name for t in all_tools],
    }
