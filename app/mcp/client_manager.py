"""Dynamic MCP tool wrapper: exposes connected OAuth plugin tools to the existing LangChain Agent."""
from __future__ import annotations

import asyncio
from typing import Any, Type
from langchain_core.tools import BaseTool
from pydantic import BaseModel, Field

from app.integrations.base import ToolDefinition
from app.integrations.manager import manager
from app.db.database import SessionLocal


class DynamicPluginTool(BaseTool):
    """LangChain tool wrapper for an authenticated OAuth plugin tool."""

    name: str
    description: str
    provider_id: str
    tool_def: ToolDefinition
    user_id: int

    def _run(self, **kwargs: Any) -> Any:
        """Synchronous run fallback: runs async execute in event loop."""
        try:
            loop = asyncio.get_event_loop()
        except RuntimeError:
            loop = asyncio.new_event_loop()
            asyncio.set_event_loop(loop)
        return loop.run_until_complete(self._arun(**kwargs))

    async def _arun(self, **kwargs: Any) -> Any:
        """Executes tool through centralized manager using user's encrypted credentials."""
        db = SessionLocal()
        try:
            confirmed = kwargs.pop("confirmed", False)
            res = await manager.execute_tool(
                user_id=self.user_id,
                provider_id=self.provider_id,
                tool_name=self.name,
                arguments=kwargs,
                confirmed=confirmed,
                db=db,
            )
            if res.requires_confirmation:
                return {
                    "status": "requires_analyst_confirmation",
                    "prompt": res.confirmation_prompt,
                    "action": self.tool_def.action_type,
                    "tool": self.name,
                    "arguments": kwargs,
                }
            if not res.success:
                return {"error": res.error}
            return res.result
        finally:
            db.close()


def get_user_plugin_tools(user_id: int) -> list[BaseTool]:
    """
    Dynamically loads MCP tools ONLY for plugins the user has connected and authorized.
    """
    db = SessionLocal()
    try:
        statuses = manager.get_user_statuses(user_id, db)
        tools: list[BaseTool] = []
        for s in statuses:
            if s.is_connected:
                provider = manager.get_provider(s.provider)
                if provider:
                    for tdef in provider.get_tools():
                        tools.append(
                            DynamicPluginTool(
                                name=tdef.name,
                                description=tdef.description,
                                provider_id=s.provider,
                                tool_def=tdef,
                                user_id=user_id,
                            )
                        )
        return tools
    finally:
        db.close()
