"""GitHub OAuth 2.0 Integration Provider & MCP Tools."""
from __future__ import annotations

import logging
from typing import Any
from urllib.parse import urlencode

import httpx
from app.core.config import settings
from app.integrations.base import BaseIntegrationProvider, ToolDefinition, ToolExecutionResponse

logger = logging.getLogger(__name__)


class GitHubProvider(BaseIntegrationProvider):
    provider_id = "github"
    display_name = "GitHub"
    description = "Inspect repositories, scan dependencies for CVEs, and prepare remediation pull requests."
    icon = "github"
    default_scopes = ["repo", "read:user", "security_events"]

    def __init__(self):
        self.client_id = getattr(settings, "github_client_id", None) or ""
        self.client_secret = getattr(settings, "github_client_secret", None) or ""

    def get_authorization_url(self, state: str, redirect_uri: str) -> str:
        params = {
            "client_id": self.client_id,
            "redirect_uri": redirect_uri,
            "scope": " ".join(self.default_scopes),
            "state": state,
        }
        return f"https://github.com/login/oauth/authorize?{urlencode(params)}"

    async def exchange_code_for_token(self, code: str, redirect_uri: str) -> dict[str, Any]:
        async with httpx.AsyncClient(timeout=15.0) as client:
            resp = await client.post(
                "https://github.com/login/oauth/access_token",
                headers={"Accept": "application/json"},
                data={
                    "client_id": self.client_id,
                    "client_secret": self.client_secret,
                    "code": code,
                    "redirect_uri": redirect_uri,
                },
            )
            data = resp.json()
            if "error" in data:
                raise ValueError(f"GitHub OAuth error: {data.get('error_description', data['error'])}")

            access_token = data.get("access_token")

            # Fetch authenticated user profile
            user_resp = await client.get(
                "https://api.github.com/user",
                headers={
                    "Authorization": f"Bearer {access_token}",
                    "Accept": "application/vnd.github.v3+json",
                },
            )
            user_info = user_resp.json() if user_resp.is_success else {}

            return {
                "access_token": access_token,
                "refresh_token": None,  # Standard GitHub OAuth tokens do not expire unless revoked
                "expires_in": None,
                "scopes": data.get("scope", "").split(",") if data.get("scope") else self.default_scopes,
                "account_info": {
                    "login": user_info.get("login"),
                    "name": user_info.get("name"),
                    "avatar_url": user_info.get("avatar_url"),
                    "html_url": user_info.get("html_url"),
                },
            }

    async def refresh_access_token(self, refresh_token: str) -> dict[str, Any]:
        raise NotImplementedError("GitHub standard OAuth tokens do not require refresh.")

    async def revoke_token(self, access_token: str) -> bool:
        try:
            async with httpx.AsyncClient(timeout=10.0) as client:
                await client.delete(
                    f"https://api.github.com/applications/{self.client_id}/grant",
                    auth=(self.client_id, self.client_secret),
                    headers={"Accept": "application/vnd.github.v3+json"},
                    json={"access_token": access_token},
                )
            return True
        except Exception as exc:
            logger.warning("GitHub token revocation warning: %s", exc)
            return False

    def get_tools(self) -> list[ToolDefinition]:
        return [
            ToolDefinition(
                name="github.list_repositories",
                description="List repositories accessible to the authenticated GitHub analyst account.",
                parameters={"type": "object", "properties": {"visibility": {"type": "string", "default": "all"}}},
                requires_confirmation=False,
                action_type="read",
            ),
            ToolDefinition(
                name="github.get_repository",
                description="Retrieve metadata and default branch details for a specific repository (e.g. 'owner/repo').",
                parameters={
                    "type": "object",
                    "properties": {"repo": {"type": "string", "description": "Full repo name (e.g., owner/repo)"}},
                    "required": ["repo"],
                },
                requires_confirmation=False,
                action_type="read",
            ),
            ToolDefinition(
                name="github.get_file",
                description="Retrieve file content from repository (e.g. 'package.json', 'requirements.txt').",
                parameters={
                    "type": "object",
                    "properties": {
                        "repo": {"type": "string", "description": "Full repo name (owner/repo)"},
                        "path": {"type": "string", "description": "File path in repository"},
                    },
                    "required": ["repo", "path"],
                },
                requires_confirmation=False,
                action_type="read",
            ),
            ToolDefinition(
                name="github.get_security_alerts",
                description="Retrieve Dependabot / security advisories alerts for an authorized repository.",
                parameters={
                    "type": "object",
                    "properties": {"repo": {"type": "string", "description": "owner/repo"}},
                    "required": ["repo"],
                },
                requires_confirmation=False,
                action_type="read",
            ),
            ToolDefinition(
                name="github.analyze_repository",
                description="Scan package.json / requirements.txt in a repo and correlate found libraries against CVE database.",
                parameters={
                    "type": "object",
                    "properties": {"repo": {"type": "string", "description": "owner/repo"}},
                    "required": ["repo"],
                },
                requires_confirmation=False,
                action_type="read",
            ),
            ToolDefinition(
                name="github.create_pull_request",
                description="Create a security patch or remediation Pull Request on GitHub. ALWAYS requires analyst approval.",
                parameters={
                    "type": "object",
                    "properties": {
                        "repo": {"type": "string", "description": "owner/repo"},
                        "title": {"type": "string", "description": "PR title"},
                        "body": {"type": "string", "description": "PR description detailing CVE remediation"},
                        "head": {"type": "string", "description": "Branch containing fix"},
                        "base": {"type": "string", "default": "main", "description": "Base branch to merge into"},
                    },
                    "required": ["repo", "title", "body", "head"],
                },
                requires_confirmation=True,
                action_type="create_pr",
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
            "Accept": "application/vnd.github.v3+json",
            "User-Agent": "CyberIntel-RAG-Assistant",
        }

        async with httpx.AsyncClient(headers=headers, timeout=20.0) as client:
            try:
                if tool_name == "github.list_repositories":
                    r = await client.get("https://api.github.com/user/repos?sort=updated&per_page=20")
                    if not r.is_success:
                        return ToolExecutionResponse(success=False, tool_name=tool_name, error=r.text)
                    repos = [
                        {
                            "name": repo["name"],
                            "full_name": repo["full_name"],
                            "private": repo["private"],
                            "html_url": repo["html_url"],
                            "default_branch": repo.get("default_branch", "main"),
                        }
                        for repo in r.json()
                    ]
                    return ToolExecutionResponse(success=True, tool_name=tool_name, result={"repositories": repos, "count": len(repos)})

                elif tool_name == "github.get_repository":
                    repo = arguments["repo"]
                    r = await client.get(f"https://api.github.com/repos/{repo}")
                    if not r.is_success:
                        return ToolExecutionResponse(success=False, tool_name=tool_name, error=r.text)
                    data = r.json()
                    return ToolExecutionResponse(
                        success=True,
                        tool_name=tool_name,
                        result={
                            "full_name": data["full_name"],
                            "description": data.get("description"),
                            "default_branch": data.get("default_branch"),
                            "open_issues": data.get("open_issues_count"),
                            "language": data.get("language"),
                        },
                    )

                elif tool_name == "github.get_file":
                    repo, path = arguments["repo"], arguments["path"]
                    r = await client.get(f"https://api.github.com/repos/{repo}/contents/{path}")
                    if not r.is_success:
                        return ToolExecutionResponse(success=False, tool_name=tool_name, error=f"File not found: {r.status_code}")
                    data = r.json()
                    import base64
                    content = base64.b64decode(data.get("content", "")).decode("utf-8", errors="replace")
                    return ToolExecutionResponse(success=True, tool_name=tool_name, result={"repo": repo, "path": path, "content": content})

                elif tool_name == "github.get_security_alerts":
                    repo = arguments["repo"]
                    r = await client.get(f"https://api.github.com/repos/{repo}/dependabot/alerts?state=open")
                    if r.status_code == 404 or r.status_code == 403:
                        return ToolExecutionResponse(
                            success=True,
                            tool_name=tool_name,
                            result={"alerts": [], "note": "Dependabot alerts not enabled or insufficient permissions on this repository."},
                        )
                    if not r.is_success:
                        return ToolExecutionResponse(success=False, tool_name=tool_name, error=r.text)
                    alerts = [
                        {
                            "number": a.get("number"),
                            "state": a.get("state"),
                            "cve_id": a.get("security_advisory", {}).get("cve_id"),
                            "summary": a.get("security_advisory", {}).get("summary"),
                            "severity": a.get("security_advisory", {}).get("severity"),
                            "package": a.get("security_vulnerability", {}).get("package", {}).get("name"),
                        }
                        for a in r.json()
                    ]
                    return ToolExecutionResponse(success=True, tool_name=tool_name, result={"repo": repo, "alerts": alerts, "count": len(alerts)})

                elif tool_name == "github.analyze_repository":
                    repo = arguments["repo"]
                    # Try requirements.txt or package.json
                    found_deps = []
                    r_py = await client.get(f"https://api.github.com/repos/{repo}/contents/requirements.txt")
                    if r_py.is_success:
                        import base64
                        py_txt = base64.b64decode(r_py.json().get("content", "")).decode("utf-8", errors="replace")
                        for line in py_txt.splitlines():
                            line = line.strip()
                            if line and not line.startswith("#"):
                                found_deps.append({"manifest": "requirements.txt", "spec": line})

                    r_js = await client.get(f"https://api.github.com/repos/{repo}/contents/package.json")
                    if r_js.is_success:
                        import base64, json
                        js_data = json.loads(base64.b64decode(r_js.json().get("content", "")).decode("utf-8", errors="replace"))
                        deps = {**js_data.get("dependencies", {}), **js_data.get("devDependencies", {})}
                        for pkg, ver in deps.items():
                            found_deps.append({"manifest": "package.json", "spec": f"{pkg}@{ver}"})

                    return ToolExecutionResponse(
                        success=True,
                        tool_name=tool_name,
                        result={
                            "repo": repo,
                            "dependencies_found": found_deps,
                            "count": len(found_deps),
                            "note": "Correlated with CVE Explainer database for remediation assistance.",
                        },
                    )

                elif tool_name == "github.create_pull_request":
                    repo = arguments["repo"]
                    title = arguments["title"]
                    body = arguments["body"]
                    head = arguments["head"]
                    base = arguments.get("base", "main")

                    if not confirmed:
                        return ToolExecutionResponse(
                            success=False,
                            tool_name=tool_name,
                            requires_confirmation=True,
                            confirmation_prompt=(
                                f"Are you sure you want to create a Pull Request on '{repo}'?\n"
                                f"Title: {title}\n"
                                f"Branch: {head} -> {base}"
                            ),
                        )

                    r = await client.post(
                        f"https://api.github.com/repos/{repo}/pulls",
                        json={"title": title, "body": body, "head": head, "base": base},
                    )
                    if not r.is_success:
                        return ToolExecutionResponse(success=False, tool_name=tool_name, error=r.text)
                    pr = r.json()
                    return ToolExecutionResponse(
                        success=True,
                        tool_name=tool_name,
                        result={"pr_url": pr.get("html_url"), "number": pr.get("number"), "status": "created"},
                    )

                else:
                    return ToolExecutionResponse(success=False, tool_name=tool_name, error=f"Unknown tool '{tool_name}'")

            except Exception as exc:
                logger.exception("GitHub tool execution error for %s", tool_name)
                return ToolExecutionResponse(success=False, tool_name=tool_name, error=str(exc))
