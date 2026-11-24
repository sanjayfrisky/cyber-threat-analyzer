"""Google Drive OAuth Integration Provider & MCP Tools."""
from __future__ import annotations

import logging
from typing import Any

import httpx
from app.integrations.base import BaseIntegrationProvider, ToolDefinition, ToolExecutionResponse
from app.integrations.oauth.google import GoogleOAuthBase

logger = logging.getLogger(__name__)


class GoogleDriveProvider(BaseIntegrationProvider):
    provider_id = "google_drive"
    display_name = "Google Drive"
    description = "Store, organize, and archive PDF vulnerability reports and incident assessments."
    icon = "hard-drive"
    default_scopes = [
        "https://www.googleapis.com/auth/drive.file",  # Minimal per-file scope
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
                name="drive.list_files",
                description="List files and vulnerability reports stored in Google Drive.",
                parameters={
                    "type": "object",
                    "properties": {
                        "folder_id": {"type": "string", "description": "Optional parent folder ID to list inside"},
                        "page_size": {"type": "integer", "default": 15},
                    },
                },
                requires_confirmation=False,
                action_type="read",
            ),
            ToolDefinition(
                name="drive.get_file",
                description="Retrieve file metadata and download link from Google Drive by file_id.",
                parameters={
                    "type": "object",
                    "properties": {"file_id": {"type": "string", "description": "Google Drive file ID"}},
                    "required": ["file_id"],
                },
                requires_confirmation=False,
                action_type="read",
            ),
            ToolDefinition(
                name="drive.create_folder",
                description="Create a dedicated cybersecurity report folder in Google Drive.",
                parameters={
                    "type": "object",
                    "properties": {
                        "folder_name": {"type": "string", "description": "Name for folder (e.g. 'CyberIntel Reports')"},
                        "parent_id": {"type": "string", "description": "Optional parent folder ID"},
                    },
                    "required": ["folder_name"],
                },
                requires_confirmation=False,
                action_type="write",
            ),
            ToolDefinition(
                name="drive.upload_report",
                description="Upload a cybersecurity report or incident summary into Google Drive.",
                parameters={
                    "type": "object",
                    "properties": {
                        "title": {"type": "string", "description": "File name (e.g. 'CVE-2024-3094_Assessment.txt')"},
                        "content": {"type": "string", "description": "Text or markdown content of the report"},
                        "folder_id": {"type": "string", "description": "Optional destination folder ID"},
                    },
                    "required": ["title", "content"],
                },
                requires_confirmation=False,
                action_type="write",
            ),
        ]

    async def execute_tool(
        self,
        tool_name: str,
        arguments: dict[str, Any],
        access_token: str,
        confirmed: bool = False,
    ) -> ToolExecutionResponse:
        headers = {"Authorization": f"Bearer {access_token}"}

        async with httpx.AsyncClient(headers=headers, timeout=25.0) as client:
            try:
                if tool_name == "drive.list_files":
                    folder_id = arguments.get("folder_id")
                    q = f"'{folder_id}' in parents and trashed = false" if folder_id else "trashed = false"
                    r = await client.get(
                        "https://www.googleapis.com/drive/v3/files",
                        params={"q": q, "pageSize": arguments.get("page_size", 15), "fields": "files(id, name, mimeType, webViewLink, createdTime)"},
                    )
                    if not r.is_success:
                        return ToolExecutionResponse(success=False, tool_name=tool_name, error=r.text)
                    files = r.json().get("files", [])
                    return ToolExecutionResponse(success=True, tool_name=tool_name, result={"files": files, "count": len(files)})

                elif tool_name == "drive.get_file":
                    file_id = arguments["file_id"]
                    r = await client.get(
                        f"https://www.googleapis.com/drive/v3/files/{file_id}",
                        params={"fields": "id, name, mimeType, size, webViewLink, createdTime"},
                    )
                    if not r.is_success:
                        return ToolExecutionResponse(success=False, tool_name=tool_name, error=r.text)
                    return ToolExecutionResponse(success=True, tool_name=tool_name, result=r.json())

                elif tool_name == "drive.create_folder":
                    folder_name = arguments["folder_name"]
                    metadata: dict[str, Any] = {
                        "name": folder_name,
                        "mimeType": "application/vnd.google-apps.folder",
                    }
                    if arguments.get("parent_id"):
                        metadata["parents"] = [arguments["parent_id"]]
                    r = await client.post("https://www.googleapis.com/drive/v3/files", json=metadata)
                    if not r.is_success:
                        return ToolExecutionResponse(success=False, tool_name=tool_name, error=r.text)
                    data = r.json()
                    return ToolExecutionResponse(success=True, tool_name=tool_name, result={"folder_id": data.get("id"), "name": folder_name, "status": "created"})

                elif tool_name == "drive.upload_report":
                    title = arguments["title"]
                    content = arguments["content"]
                    folder_id = arguments.get("folder_id")

                    # Multipart upload metadata + content
                    metadata: dict[str, Any] = {"name": title}
                    if folder_id:
                        metadata["parents"] = [folder_id]

                    import json
                    files = {
                        "data": ("metadata", json.dumps(metadata), "application/json; charset=UTF-8"),
                        "file": (title, content.encode("utf-8"), "text/plain"),
                    }
                    r = await client.post(
                        "https://www.googleapis.com/upload/drive/v3/files?uploadType=multipart&fields=id,name,webViewLink",
                        files=files,
                    )
                    if not r.is_success:
                        return ToolExecutionResponse(success=False, tool_name=tool_name, error=r.text)
                    data = r.json()
                    return ToolExecutionResponse(
                        success=True,
                        tool_name=tool_name,
                        result={"file_id": data.get("id"), "name": data.get("name"), "web_view_link": data.get("webViewLink"), "status": "uploaded"},
                    )

                else:
                    return ToolExecutionResponse(success=False, tool_name=tool_name, error=f"Unknown tool '{tool_name}'")

            except Exception as exc:
                logger.exception("Google Drive tool execution error for %s", tool_name)
                return ToolExecutionResponse(success=False, tool_name=tool_name, error=str(exc))
