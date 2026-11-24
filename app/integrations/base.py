"""Base classes and schemas for OAuth providers and MCP plugin tools."""
from __future__ import annotations

from abc import ABC, abstractmethod
from typing import Any
from pydantic import BaseModel, Field


class ToolDefinition(BaseModel):
    name: str = Field(..., description="Fully qualified tool name, e.g., github.list_repositories")
    description: str = Field(..., description="Description for LLM router and analyst")
    parameters: dict[str, Any] = Field(default_factory=dict, description="JSON Schema of parameters")
    requires_confirmation: bool = Field(default=False, description="Whether tool requires explicit analyst approval")
    action_type: str = Field(default="read", description="'read', 'write', 'send', 'create_pr'")


class IntegrationStatus(BaseModel):
    provider: str
    name: str
    description: str
    icon: str
    is_connected: bool
    account_info: dict[str, Any] = Field(default_factory=dict)
    scopes: list[str] = Field(default_factory=list)
    available_tools: list[str] = Field(default_factory=list)


class ToolExecutionRequest(BaseModel):
    tool_name: str = Field(..., description="MCP tool to execute")
    arguments: dict[str, Any] = Field(default_factory=dict, description="Arguments conforming to tool schema")
    confirmed: bool = Field(default=False, description="Analyst explicit confirmation for write/send actions")


class ToolExecutionResponse(BaseModel):
    success: bool
    tool_name: str
    result: Any = None
    requires_confirmation: bool = False
    confirmation_prompt: str | None = None
    error: str | None = None


class BaseIntegrationProvider(ABC):
    """Abstract base class for all 4 OAuth providers (GitHub, Gmail, Google Drive, Slack)."""

    provider_id: str
    display_name: str
    description: str
    icon: str
    default_scopes: list[str]

    @abstractmethod
    def get_authorization_url(self, state: str, redirect_uri: str) -> str:
        """Construct the OAuth 2.0 authorization URL."""
        pass

    @abstractmethod
    async def exchange_code_for_token(self, code: str, redirect_uri: str) -> dict[str, Any]:
        """Exchange authorization code for access_token, refresh_token, and account metadata."""
        pass

    @abstractmethod
    async def refresh_access_token(self, refresh_token: str) -> dict[str, Any]:
        """Refresh expired access token if supported by provider."""
        pass

    @abstractmethod
    async def revoke_token(self, access_token: str) -> bool:
        """Revoke token with provider on disconnect."""
        pass

    @abstractmethod
    def get_tools(self) -> list[ToolDefinition]:
        """List all MCP tools exposed by this plugin."""
        pass

    @abstractmethod
    async def execute_tool(
        self,
        tool_name: str,
        arguments: dict[str, Any],
        access_token: str,
        confirmed: bool = False,
    ) -> ToolExecutionResponse:
        """Execute a tool using the decrypted access token."""
        pass
