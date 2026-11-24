"""Centralized integrations API router: exactly 5 endpoints for the 4 OAuth plugins."""
from __future__ import annotations

import logging
from typing import Any
from fastapi import APIRouter, Depends, HTTPException, Query, Request, status
from fastapi.responses import RedirectResponse
from sqlalchemy.orm import Session

from app.core.auth import get_current_user
from app.db.database import User, get_db
from app.integrations.base import IntegrationStatus, ToolExecutionRequest, ToolExecutionResponse
from app.integrations.manager import manager
from app.core.config import settings

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/v1/integrations", tags=["Integrations"])


@router.get("", response_model=list[IntegrationStatus])
def list_integrations(
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
) -> list[IntegrationStatus]:
    """1. Returns the four plugin configurations and live connection statuses."""
    return manager.get_user_statuses(current_user.id, db)


@router.post("/{provider}/connect")
def start_oauth(
    provider: str,
    request: Request,
    redirect_uri: str | None = None,
    current_user: User = Depends(get_current_user),
) -> dict[str, str]:
    """2. Starts OAuth authorization for the selected provider."""
    prov = manager.get_provider(provider)
    if not prov:
        raise HTTPException(status_code=404, detail=f"Unsupported provider '{provider}'")

    # Default to current backend callback URL if not passed
    cb_url = redirect_uri or str(request.url_for("oauth_callback", provider=provider))
    # Replace internal host if needed
    if "localhost:8000" in cb_url and request.headers.get("x-forwarded-host"):
        cb_url = f"https://{request.headers.get('x-forwarded-host')}/api/v1/integrations/{provider}/callback"

    state = manager.create_oauth_state(current_user.id, provider)
    auth_url = prov.get_authorization_url(state=state, redirect_uri=cb_url)
    return {"authorization_url": auth_url, "state": state}


@router.get("/{provider}/callback")
async def oauth_callback(
    provider: str,
    request: Request,
    code: str | None = None,
    state: str | None = None,
    error: str | None = None,
    db: Session = Depends(get_db),
):
    """3. Handles OAuth callbacks and redirects back to the frontend."""
    frontend_base = (settings.cors_origin_list[0] if settings.cors_origin_list else "http://localhost:3000").rstrip("/")

    if error or not code or not state:
        err_msg = error or "Missing authorization code or state"
        logger.warning("OAuth callback rejected for %s: %s", provider, err_msg)
        return RedirectResponse(url=f"{frontend_base}/?plugin_status=error&provider={provider}&error={err_msg}")

    prov = manager.get_provider(provider)
    if not prov:
        return RedirectResponse(url=f"{frontend_base}/?plugin_status=error&provider={provider}&error=Invalid+provider")

    cb_url = str(request.url_for("oauth_callback", provider=provider))
    if "localhost:8000" in cb_url and request.headers.get("x-forwarded-host"):
        cb_url = f"https://{request.headers.get('x-forwarded-host')}/api/v1/integrations/{provider}/callback"

    try:
        await manager.handle_callback(
            provider_id=provider,
            code=code,
            state=state,
            redirect_uri=cb_url,
            db=db,
        )
        return RedirectResponse(url=f"{frontend_base}/?plugin_status=connected&provider={provider}")
    except Exception as exc:
        logger.exception("OAuth exchange failed for provider %s", provider)
        return RedirectResponse(url=f"{frontend_base}/?plugin_status=error&provider={provider}&error={str(exc)}")


@router.post("/{provider}/disconnect")
async def disconnect_integration(
    provider: str,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
) -> dict[str, Any]:
    """4. Disconnects the selected provider and revokes credentials."""
    prov = manager.get_provider(provider)
    if not prov:
        raise HTTPException(status_code=404, detail=f"Unsupported provider '{provider}'")

    success = await manager.disconnect(current_user.id, provider, db)
    return {"success": success, "provider": provider, "status": "disconnected"}


@router.post("/{provider}/execute", response_model=ToolExecutionResponse)
async def execute_plugin_tool(
    provider: str,
    payload: ToolExecutionRequest,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
) -> ToolExecutionResponse:
    """5. Executes an approved tool belonging to the selected provider."""
    return await manager.execute_tool(
        user_id=current_user.id,
        provider_id=provider,
        tool_name=payload.tool_name,
        arguments=payload.arguments,
        confirmed=payload.confirmed,
        db=db,
    )
