"""Google Shared OAuth Infrastructure for Gmail and Google Drive."""
from __future__ import annotations

import logging
from typing import Any
from urllib.parse import urlencode
from datetime import datetime, timezone, timedelta

import httpx
from app.core.config import settings

logger = logging.getLogger(__name__)


class GoogleOAuthBase:
    """Handles shared Google authorization code exchange, profile retrieval, and token refresh."""

    TOKEN_URL = "https://oauth2.googleapis.com/token"
    AUTH_URL = "https://accounts.google.com/o/oauth2/v2/auth"
    REVOKE_URL = "https://oauth2.googleapis.com/revoke"

    def __init__(self):
        self.client_id = getattr(settings, "google_client_id", None) or ""
        self.client_secret = getattr(settings, "google_client_secret", None) or ""

    def build_auth_url(self, scopes: list[str], state: str, redirect_uri: str) -> str:
        params = {
            "client_id": self.client_id,
            "redirect_uri": redirect_uri,
            "response_type": "code",
            "scope": " ".join(scopes),
            "access_type": "offline",  # Crucial: requests refresh_token
            "prompt": "consent",       # Ensures refresh_token is returned
            "state": state,
        }
        return f"{self.AUTH_URL}?{urlencode(params)}"

    async def exchange_code(self, code: str, redirect_uri: str) -> dict[str, Any]:
        async with httpx.AsyncClient(timeout=15.0) as client:
            resp = await client.post(
                self.TOKEN_URL,
                data={
                    "client_id": self.client_id,
                    "client_secret": self.client_secret,
                    "code": code,
                    "grant_type": "authorization_code",
                    "redirect_uri": redirect_uri,
                },
            )
            data = resp.json()
            if "error" in data:
                raise ValueError(f"Google OAuth error: {data.get('error_description', data['error'])}")

            access_token = data.get("access_token")
            refresh_token = data.get("refresh_token")
            expires_in = data.get("expires_in", 3600)
            token_expires_at = datetime.now(timezone.utc) + timedelta(seconds=expires_in)

            # Retrieve user profile
            account_info = {}
            try:
                prof_resp = await client.get(
                    "https://www.googleapis.com/oauth2/v2/userinfo",
                    headers={"Authorization": f"Bearer {access_token}"},
                )
                if prof_resp.is_success:
                    prof = prof_resp.json()
                    account_info = {
                        "email": prof.get("email"),
                        "name": prof.get("name"),
                        "picture": prof.get("picture"),
                    }
            except Exception as e:
                logger.debug("Google userinfo fetch note: %s", e)

            return {
                "access_token": access_token,
                "refresh_token": refresh_token,
                "token_expires_at": token_expires_at,
                "scopes": data.get("scope", "").split(" "),
                "account_info": account_info,
            }

    async def refresh_token(self, refresh_token: str) -> dict[str, Any]:
        async with httpx.AsyncClient(timeout=15.0) as client:
            resp = await client.post(
                self.TOKEN_URL,
                data={
                    "client_id": self.client_id,
                    "client_secret": self.client_secret,
                    "refresh_token": refresh_token,
                    "grant_type": "refresh_token",
                },
            )
            data = resp.json()
            if "error" in data:
                raise ValueError(f"Google token refresh failed: {data.get('error_description', data['error'])}")

            expires_in = data.get("expires_in", 3600)
            token_expires_at = datetime.now(timezone.utc) + timedelta(seconds=expires_in)

            return {
                "access_token": data.get("access_token"),
                "token_expires_at": token_expires_at,
            }

    async def revoke(self, token: str) -> bool:
        try:
            async with httpx.AsyncClient(timeout=10.0) as client:
                await client.post(self.REVOKE_URL, params={"token": token})
            return True
        except Exception as exc:
            logger.warning("Google revoke error: %s", exc)
            return False
