"""Centralized Integration Manager: manages registration, OAuth flow, tokens, and execution."""
from __future__ import annotations

import logging
import secrets
from datetime import datetime, timezone
from typing import Any

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.db.database import UserIntegration, IntegrationAuditLog
from app.integrations.base import BaseIntegrationProvider, IntegrationStatus, ToolExecutionResponse
from app.integrations.providers.github import GitHubProvider
from app.integrations.providers.gmail import GmailProvider
from app.integrations.providers.google_drive import GoogleDriveProvider
from app.integrations.providers.slack import SlackProvider
from app.services.token_service import encrypt_token, decrypt_token

logger = logging.getLogger(__name__)


class IntegrationManager:
    """Singleton manager for all 4 external OAuth plugins."""

    def __init__(self):
        self._providers: dict[str, BaseIntegrationProvider] = {
            "github": GitHubProvider(),
            "gmail": GmailProvider(),
            "google_drive": GoogleDriveProvider(),
            "slack": SlackProvider(),
        }

    def get_provider(self, provider_id: str) -> BaseIntegrationProvider | None:
        return self._providers.get(provider_id.lower())

    def list_all_providers(self) -> list[BaseIntegrationProvider]:
        return list(self._providers.values())

    def get_user_statuses(self, user_id: int, db: Session) -> list[IntegrationStatus]:
        """Fetch connection statuses for all 4 plugins for a specific user."""
        integrations = db.scalars(
            select(UserIntegration).where(UserIntegration.user_id == user_id)
        ).all()
        by_provider = {i.provider: i for i in integrations}

        statuses = []
        for pid, provider in self._providers.items():
            record = by_provider.get(pid)
            is_conn = bool(record and record.is_connected and record.encrypted_access_token)
            statuses.append(
                IntegrationStatus(
                    provider=pid,
                    name=provider.display_name,
                    description=provider.description,
                    icon=provider.icon,
                    is_connected=is_conn,
                    account_info=record.account_info if (record and is_conn) else {},
                    scopes=record.scopes if (record and is_conn) else provider.default_scopes,
                    available_tools=[t.name for t in provider.get_tools()],
                )
            )
        return statuses

    def create_oauth_state(self, user_id: int, provider_id: str) -> str:
        """Create secure random state token encoding user_id and provider."""
        random_part = secrets.token_urlsafe(24)
        return f"{user_id}:{provider_id}:{random_part}"

    def parse_and_validate_state(self, state: str, expected_provider: str) -> int:
        """Validate state format and match provider; returns user_id."""
        parts = state.split(":")
        if len(parts) != 3 or parts[1] != expected_provider:
            raise ValueError("Invalid or corrupted OAuth state token.")
        try:
            return int(parts[0])
        except ValueError:
            raise ValueError("Invalid user identifier in state token.")

    async def handle_callback(
        self,
        provider_id: str,
        code: str,
        state: str,
        redirect_uri: str,
        db: Session,
    ) -> UserIntegration:
        """Exchange OAuth code and persist encrypted tokens in Supabase."""
        provider = self.get_provider(provider_id)
        if not provider:
            raise ValueError(f"Unknown provider '{provider_id}'")

        user_id = self.parse_and_validate_state(state, provider_id)
        token_data = await provider.exchange_code_for_token(code, redirect_uri)

        enc_access = encrypt_token(token_data.get("access_token"))
        enc_refresh = encrypt_token(token_data.get("refresh_token"))

        record = db.scalar(
            select(UserIntegration).where(
                UserIntegration.user_id == user_id,
                UserIntegration.provider == provider_id,
            )
        )

        if not record:
            record = UserIntegration(
                user_id=user_id,
                provider=provider_id,
                is_connected=True,
                scopes=token_data.get("scopes", []),
                encrypted_access_token=enc_access,
                encrypted_refresh_token=enc_refresh,
                token_expires_at=token_data.get("token_expires_at"),
                account_info=token_data.get("account_info", {}),
            )
            db.add(record)
        else:
            record.is_connected = True
            record.scopes = token_data.get("scopes", [])
            record.encrypted_access_token = enc_access
            if enc_refresh:
                record.encrypted_refresh_token = enc_refresh
            record.token_expires_at = token_data.get("token_expires_at")
            record.account_info = token_data.get("account_info", {})
            record.updated_at = datetime.now(timezone.utc)

        db.commit()
        db.refresh(record)
        logger.info("Successfully connected provider '%s' for user_id=%s", provider_id, user_id)
        return record

    async def disconnect(self, user_id: int, provider_id: str, db: Session) -> bool:
        """Revoke token and mark disconnected."""
        provider = self.get_provider(provider_id)
        record = db.scalar(
            select(UserIntegration).where(
                UserIntegration.user_id == user_id,
                UserIntegration.provider == provider_id,
            )
        )
        if not record or not record.is_connected:
            return True

        # Attempt remote revocation
        if record.encrypted_access_token and provider:
            raw_token = decrypt_token(record.encrypted_access_token)
            if raw_token:
                try:
                    await provider.revoke_token(raw_token)
                except Exception as e:
                    logger.debug("Remote revocation note: %s", e)

        record.is_connected = False
        record.encrypted_access_token = None
        record.encrypted_refresh_token = None
        record.updated_at = datetime.now(timezone.utc)
        db.commit()
        logger.info("Disconnected provider '%s' for user_id=%s", provider_id, user_id)
        return True

    async def execute_tool(
        self,
        user_id: int,
        provider_id: str,
        tool_name: str,
        arguments: dict[str, Any],
        confirmed: bool,
        db: Session,
    ) -> ToolExecutionResponse:
        """Validate permissions, decrypt token, handle refresh, and execute tool with audit logging."""
        provider = self.get_provider(provider_id)
        if not provider:
            return ToolExecutionResponse(success=False, tool_name=tool_name, error=f"Unknown provider '{provider_id}'")

        record = db.scalar(
            select(UserIntegration).where(
                UserIntegration.user_id == user_id,
                UserIntegration.provider == provider_id,
            )
        )
        if not record or not record.is_connected or not record.encrypted_access_token:
            return ToolExecutionResponse(
                success=False,
                tool_name=tool_name,
                error=f"Plugin '{provider.display_name}' is not connected. Connect it in Settings -> Plugins first.",
            )

        access_token = decrypt_token(record.encrypted_access_token)
        if not access_token:
            return ToolExecutionResponse(success=False, tool_name=tool_name, error="Stored token could not be decrypted.")

        # Check expiration and attempt refresh if needed
        if record.token_expires_at and record.token_expires_at < datetime.now(timezone.utc):
            if record.encrypted_refresh_token:
                refresh_token = decrypt_token(record.encrypted_refresh_token)
                try:
                    refreshed = await provider.refresh_access_token(refresh_token)
                    access_token = refreshed["access_token"]
                    record.encrypted_access_token = encrypt_token(access_token)
                    if "token_expires_at" in refreshed:
                        record.token_expires_at = refreshed["token_expires_at"]
                    db.commit()
                except Exception as refr_err:
                    logger.warning("Token auto-refresh failed: %s", refr_err)
                    return ToolExecutionResponse(success=False, tool_name=tool_name, error="Token expired and refresh failed. Please reconnect.")

        # Execute
        res = await provider.execute_tool(tool_name, arguments, access_token, confirmed=confirmed)

        # Audit log
        audit = IntegrationAuditLog(
            user_id=user_id,
            provider=provider_id,
            tool_name=tool_name,
            action=tool_name.split(".")[-1],
            parameters_sanitized={k: v for k, v in arguments.items() if "secret" not in k.lower() and "token" not in k.lower()},
            status="success" if res.success else ("pending_approval" if res.requires_confirmation else "error"),
            user_approved=confirmed,
            error_message=res.error,
        )
        db.add(audit)
        db.commit()

        return res


manager = IntegrationManager()
