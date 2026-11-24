"""Gmail OAuth Integration Provider & MCP Tools."""
from __future__ import annotations

import base64
import email
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from email.mime.application import MIMEApplication
import logging
from typing import Any

import httpx
from app.integrations.base import BaseIntegrationProvider, ToolDefinition, ToolExecutionResponse
from app.integrations.oauth.google import GoogleOAuthBase

logger = logging.getLogger(__name__)


class GmailProvider(BaseIntegrationProvider):
    provider_id = "gmail"
    display_name = "Gmail"
    description = "Send vulnerability reports, triage notifications, and create security drafts."
    icon = "mail"
    default_scopes = [
        "https://www.googleapis.com/auth/gmail.send",
        "https://www.googleapis.com/auth/gmail.compose",
        "https://www.googleapis.com/auth/gmail.readonly",
        "https://www.googleapis.com/auth/userinfo.email",
    ]

    def __init__(self):
        self.oauth = GoogleOAuthBase()

    def get_authorization_url(self, state: str, redirect_uri: str) -> str:
        return self.oauth.build_auth_url(self.default_scopes, state, redirect_uri)

    async def exchange_code_for_token(self, code: str, redirect_uri: str) -> dict[str, Any]:
        return await self.oauth.exchange_code(code, redirect_uri)

    async def refresh_access_token(self, refresh_token: str) -> dict[str, Any]:
        return await self.oauth.refresh_token(refresh_token)

    async def revoke_token(self, access_token: str) -> bool:
        return await self.oauth.revoke(access_token)

    def get_tools(self) -> list[ToolDefinition]:
        return [
            ToolDefinition(
                name="gmail.search_emails",
                description="Search authorized analyst emails by query keyword (e.g. 'CVE', 'security alert').",
                parameters={
                    "type": "object",
                    "properties": {
                        "query": {"type": "string", "description": "Search query like 'subject:CVE-2024-3094'"},
                        "max_results": {"type": "integer", "default": 10},
                    },
                    "required": ["query"],
                },
                requires_confirmation=False,
                action_type="read",
            ),
            ToolDefinition(
                name="gmail.read_email",
                description="Read full details and snippet of a specific email message by message_id.",
                parameters={
                    "type": "object",
                    "properties": {"message_id": {"type": "string", "description": "Gmail message ID"}},
                    "required": ["message_id"],
                },
                requires_confirmation=False,
                action_type="read",
            ),
            ToolDefinition(
                name="gmail.create_draft",
                description="Create a draft email containing a vulnerability report or remediation guidance without sending.",
                parameters={
                    "type": "object",
                    "properties": {
                        "to": {"type": "string", "description": "Recipient email address"},
                        "subject": {"type": "string", "description": "Email subject"},
                        "body": {"type": "string", "description": "Email body content (markdown or text)"},
                    },
                    "required": ["to", "subject", "body"],
                },
                requires_confirmation=False,
                action_type="write",
            ),
            ToolDefinition(
                name="gmail.send_email",
                description="Send an email to a recipient. ALWAYS requires explicit analyst confirmation.",
                parameters={
                    "type": "object",
                    "properties": {
                        "to": {"type": "string", "description": "Recipient email address"},
                        "subject": {"type": "string", "description": "Email subject"},
                        "body": {"type": "string", "description": "Email message body"},
                    },
                    "required": ["to", "subject", "body"],
                },
                requires_confirmation=True,
                action_type="send",
            ),
            ToolDefinition(
                name="gmail.send_security_report",
                description="Send a formatted security assessment / CVE triage report to an analyst or SOC mailbox.",
                parameters={
                    "type": "object",
                    "properties": {
                        "to": {"type": "string", "description": "Recipient email address"},
                        "cve_id": {"type": "string", "description": "CVE identifier, e.g., CVE-2024-3094"},
                        "report_summary": {"type": "string", "description": "Executive summary and remediation steps"},
                    },
                    "required": ["to", "cve_id", "report_summary"],
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
                if tool_name == "gmail.search_emails":
                    q = arguments["query"]
                    max_results = arguments.get("max_results", 10)
                    r = await client.get(
                        f"https://gmail.googleapis.com/gmail/v1/users/me/messages",
                        params={"q": q, "maxResults": max_results},
                    )
                    if not r.is_success:
                        return ToolExecutionResponse(success=False, tool_name=tool_name, error=r.text)
                    data = r.json()
                    messages = data.get("messages", [])
                    return ToolExecutionResponse(success=True, tool_name=tool_name, result={"query": q, "count": len(messages), "messages": messages})

                elif tool_name == "gmail.read_email":
                    msg_id = arguments["message_id"]
                    r = await client.get(f"https://gmail.googleapis.com/gmail/v1/users/me/messages/{msg_id}?format=full")
                    if not r.is_success:
                        return ToolExecutionResponse(success=False, tool_name=tool_name, error=r.text)
                    data = r.json()
                    snippet = data.get("snippet", "")
                    headers_list = data.get("payload", {}).get("headers", [])
                    headers_dict = {h["name"]: h["value"] for h in headers_list if h["name"] in ("Subject", "From", "To", "Date")}
                    return ToolExecutionResponse(success=True, tool_name=tool_name, result={"id": msg_id, "snippet": snippet, "headers": headers_dict})

                elif tool_name == "gmail.create_draft":
                    msg = MIMEText(arguments["body"])
                    msg["to"] = arguments["to"]
                    msg["subject"] = arguments["subject"]
                    raw_b64 = base64.urlsafe_b64encode(msg.as_bytes()).decode("utf-8")

                    r = await client.post(
                        "https://gmail.googleapis.com/gmail/v1/users/me/drafts",
                        json={"message": {"raw": raw_b64}},
                    )
                    if not r.is_success:
                        return ToolExecutionResponse(success=False, tool_name=tool_name, error=r.text)
                    data = r.json()
                    return ToolExecutionResponse(success=True, tool_name=tool_name, result={"draft_id": data.get("id"), "status": "draft_created"})

                elif tool_name in ("gmail.send_email", "gmail.send_security_report"):
                    to = arguments["to"]
                    if tool_name == "gmail.send_security_report":
                        subject = f"[CyberIntel Alert] Triage Report for {arguments['cve_id']}"
                        body = arguments["report_summary"]
                    else:
                        subject = arguments["subject"]
                        body = arguments["body"]

                    if not confirmed:
                        return ToolExecutionResponse(
                            success=False,
                            tool_name=tool_name,
                            requires_confirmation=True,
                            confirmation_prompt=(
                                f"Are you sure you want to send this email via Gmail?\n"
                                f"To: {to}\n"
                                f"Subject: {subject}\n"
                                f"Body preview: {body[:150]}..."
                            ),
                        )

                    msg = MIMEText(body)
                    msg["to"] = to
                    msg["subject"] = subject
                    raw_b64 = base64.urlsafe_b64encode(msg.as_bytes()).decode("utf-8")

                    r = await client.post(
                        "https://gmail.googleapis.com/gmail/v1/users/me/messages/send",
                        json={"raw": raw_b64},
                    )
                    if not r.is_success:
                        return ToolExecutionResponse(success=False, tool_name=tool_name, error=r.text)
                    data = r.json()
                    return ToolExecutionResponse(success=True, tool_name=tool_name, result={"message_id": data.get("id"), "to": to, "status": "sent"})

                else:
                    return ToolExecutionResponse(success=False, tool_name=tool_name, error=f"Unknown tool '{tool_name}'")

            except Exception as exc:
                logger.exception("Gmail tool execution error for %s", tool_name)
                return ToolExecutionResponse(success=False, tool_name=tool_name, error=str(exc))
