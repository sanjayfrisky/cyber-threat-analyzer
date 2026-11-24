"""Slack OAuth 2.0 Integration Provider & MCP Tools."""
from __future__ import annotations

import logging
from typing import Any
from urllib.parse import urlencode

import httpx
from app.core.config import settings
from app.integrations.base import BaseIntegrationProvider, ToolDefinition, ToolExecutionResponse

logger = logging.getLogger(__name__)


class SlackProvider(BaseIntegrationProvider):
    provider_id = "slack"
    display_name = "Slack"
    description = "Send critical vulnerability alerts, triage summaries, and scan notifications to security channels."
    icon = "slack"
    default_scopes = [
        "channels:read",
        "chat:write",
        "chat:write.public",
        "groups:read",
    ]

    def __init__(self):
        self.client_id = getattr(settings, "slack_client_id", None) or ""
        self.client_secret = getattr(settings, "slack_client_secret", None) or ""

    def get_authorization_url(self, state: str, redirect_uri: str) -> str:
        params = {
            "client_id": self.client_id,
            "redirect_uri": redirect_uri,
            "scope": ",".join(self.default_scopes),
            "state": state,
        }
        return f"https://slack.com/oauth/v2/authorize?{urlencode(params)}"

    async def exchange_code_for_token(self, code: str, redirect_uri: str) -> dict[str, Any]:
        async with httpx.AsyncClient(timeout=15.0) as client:
            resp = await client.post(
                "https://slack.com/api/oauth.v2.access",
                data={
                    "client_id": self.client_id,
                    "client_secret": self.client_secret,
                    "code": code,
                    "redirect_uri": redirect_uri,
                },
            )
            data = resp.json()
            if not data.get("ok"):
                raise ValueError(f"Slack OAuth error: {data.get('error', 'Authentication failed')}")

            access_token = data.get("access_token")
            team = data.get("team", {})

            return {
                "access_token": access_token,
                "refresh_token": data.get("refresh_token"),
                "token_expires_at": None,
                "scopes": data.get("scope", "").split(","),
                "account_info": {
                    "team_name": team.get("name"),
                    "team_id": team.get("id"),
                    "app_id": data.get("app_id"),
                },
            }

    async def refresh_access_token(self, refresh_token: str) -> dict[str, Any]:
        async with httpx.AsyncClient(timeout=15.0) as client:
            resp = await client.post(
                "https://slack.com/api/oauth.v2.access",
                data={
                    "client_id": self.client_id,
                    "client_secret": self.client_secret,
                    "grant_type": "refresh_token",
                    "refresh_token": refresh_token,
                },
            )
            data = resp.json()
            if not data.get("ok"):
                raise ValueError(f"Slack token refresh failed: {data.get('error')}")
            return {"access_token": data.get("access_token")}

    async def revoke_token(self, access_token: str) -> bool:
        try:
            async with httpx.AsyncClient(timeout=10.0) as client:
                await client.post("https://slack.com/api/auth.revoke", headers={"Authorization": f"Bearer {access_token}"})
            return True
        except Exception as exc:
            logger.warning("Slack revoke error: %s", exc)
            return False

    def get_tools(self) -> list[ToolDefinition]:
        return [
            ToolDefinition(
                name="slack.list_channels",
                description="List public/security Slack channels in the connected workspace.",
                parameters={"type": "object", "properties": {"types": {"type": "string", "default": "public_channel"}}},
                requires_confirmation=False,
                action_type="read",
            ),
            ToolDefinition(
                name="slack.send_message",
                description="Post a message to a Slack channel. ALWAYS requires explicit analyst approval.",
                parameters={
                    "type": "object",
                    "properties": {
                        "channel": {"type": "string", "description": "Channel ID (e.g. C12345678) or channel name"},
                        "message": {"type": "string", "description": "Notification content"},
                    },
                    "required": ["channel", "message"],
                },
                requires_confirmation=True,
                action_type="send",
            ),
            ToolDefinition(
                name="slack.send_cve_alert",
                description="Send a high-priority CVE security alert with CVSS score and remediation to a channel.",
                parameters={
                    "type": "object",
                    "properties": {
                        "channel": {"type": "string", "description": "Target Slack channel"},
                        "cve_id": {"type": "string", "description": "CVE identifier"},
                        "severity": {"type": "string", "description": "CRITICAL, HIGH, MEDIUM, LOW"},
                        "summary": {"type": "string", "description": "Actionable vulnerability summary"},
                    },
                    "required": ["channel", "cve_id", "severity", "summary"],
                },
                requires_confirmation=True,
                action_type="send",
            ),
            ToolDefinition(
                name="slack.send_remediation_notification",
                description="Notify the engineering/SOC team that a patch or remediation workaround has been validated.",
                parameters={
                    "type": "object",
                    "properties": {
                        "channel": {"type": "string", "description": "Target Slack channel"},
                        "cve_id": {"type": "string", "description": "CVE ID"},
                        "patch_version": {"type": "string", "description": "Recommended patched package or version"},
                    },
                    "required": ["channel", "cve_id", "patch_version"],
                },
                requires_confirmation=True,
                action_type="send",
            ),
        ]

    async def execute_tool(
        self,
        tool_name: str,
        arguments: dict[str, Any],
        access_token: str,
        confirmed: bool = False,
    ) -> ToolExecutionResponse:
        headers = {
            "Authorization": f"Bearer {access_token}",
            "Content-Type": "application/json",
        }

        async with httpx.AsyncClient(headers=headers, timeout=20.0) as client:
            try:
                if tool_name == "slack.list_channels":
                    types = arguments.get("types", "public_channel")
                    r = await client.get(
                        "https://slack.com/api/conversations.list",
                        params={"types": types, "exclude_archived": "true", "limit": 30},
                    )
                    data = r.json()
                    if not data.get("ok"):
                        return ToolExecutionResponse(success=False, tool_name=tool_name, error=data.get("error"))
                    channels = [
                        {"id": c["id"], "name": f"#{c['name']}", "topic": c.get("topic", {}).get("value", "")}
                        for c in data.get("channels", [])
                    ]
                    return ToolExecutionResponse(success=True, tool_name=tool_name, result={"channels": channels, "count": len(channels)})

                elif tool_name in ("slack.send_message", "slack.send_cve_alert", "slack.send_remediation_notification"):
                    channel = arguments["channel"]
                    if tool_name == "slack.send_cve_alert":
                        text = (
                            f":rotating_light: *[CRITICAL CYBERINTEL ALERT]* {arguments['cve_id']}\n"
                            f"*Severity:* {arguments.get('severity', 'HIGH')}\n"
                            f"*Summary:* {arguments.get('summary')}"
                        )
                    elif tool_name == "slack.send_remediation_notification":
                        text = (
                            f":shield: *[Remediation Verified]* {arguments['cve_id']}\n"
                            f"*Action:* Upgrade to `{arguments.get('patch_version')}`"
                        )
                    else:
                        text = arguments["message"]

                    if not confirmed:
                        return ToolExecutionResponse(
                            success=False,
                            tool_name=tool_name,
                            requires_confirmation=True,
                            confirmation_prompt=(
                                f"Are you sure you want to send this Slack notification to {channel}?\n"
                                f"Message Preview:\n{text[:180]}..."
                            ),
                        )

                    r = await client.post(
                        "https://slack.com/api/chat.postMessage",
                        json={"channel": channel, "text": text},
                    )
                    data = r.json()
                    if not data.get("ok"):
                        return ToolExecutionResponse(success=False, tool_name=tool_name, error=data.get("error"))
                    return ToolExecutionResponse(
                        success=True,
                        tool_name=tool_name,
                        result={"channel": channel, "ts": data.get("ts"), "status": "sent"},
                    )

                else:
                    return ToolExecutionResponse(success=False, tool_name=tool_name, error=f"Unknown tool '{tool_name}'")

            except Exception as exc:
                logger.exception("Slack tool execution error for %s", tool_name)
                return ToolExecutionResponse(success=False, tool_name=tool_name, error=str(exc))
