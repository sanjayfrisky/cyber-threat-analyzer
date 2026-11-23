"""Authentication core: password hashing, HMAC-SHA256 stateless tokens, and user session management."""
from __future__ import annotations

import base64
import hashlib
import hmac
import json
import logging
import secrets
import time
from typing import Any

from fastapi import Depends, HTTPException, Request, status
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.core.config import settings
from app.db.database import User, get_db

logger = logging.getLogger(__name__)

# Secret key for HMAC token signing (falls back to a stable secret or generates one)
_AUTH_SECRET = getattr(settings, "secret_key", None) or "cyber-threat-rag-auth-secret-key-32b-min!!"
TOKEN_EXPIRY_HOURS = 24
TOKEN_EXPIRY_REMEMBER_DAYS = 30


def hash_password(password: str) -> tuple[str, str]:
    """
    Hash a password using PBKDF2-HMAC-SHA256 with a unique random salt.
    Returns (hex_hash, hex_salt).
    """
    salt = secrets.token_hex(16)
    key = hashlib.pbkdf2_hmac(
        "sha256",
        password.encode("utf-8"),
        salt.encode("utf-8"),
        iterations=100_000,
    )
    return key.hex(), salt


def verify_password(password: str, password_hash: str | None, salt: str | None) -> bool:
    """Verify password against stored hash using constant-time comparison."""
    if not password_hash or not salt:
        return False
    key = hashlib.pbkdf2_hmac(
        "sha256",
        password.encode("utf-8"),
        salt.encode("utf-8"),
        iterations=100_000,
    )
    return hmac.compare_digest(key.hex(), password_hash)


def verify_google_id_token(id_token_str: str) -> dict[str, Any]:
    """
    Verify a Google ID Token (JWT) issued by Google Identity Services.
    Validates token signature against Google certs, expiration, and issuer.
    Returns verified payload dict containing sub, email, full_name, avatar_url.
    """
    try:
        from google.oauth2 import id_token
        from google.auth.transport import requests as google_requests

        request = google_requests.Request()
        client_id = settings.google_client_id if settings.google_client_id else None

        # verify_oauth2_token verifies signature, expiration, and audience (if client_id is set)
        id_info = id_token.verify_oauth2_token(id_token_str, request, audience=client_id)

        # Confirm valid Google issuer
        issuer = id_info.get("iss", "")
        if issuer not in ["accounts.google.com", "https://accounts.google.com"]:
            raise ValueError(f"Untrusted token issuer: {issuer}")

        email = id_info.get("email")
        if not email:
            raise ValueError("Google token does not contain an email address.")

        return {
            "sub": id_info.get("sub"),
            "email": email,
            "full_name": id_info.get("name") or email.split("@")[0],
            "avatar_url": id_info.get("picture"),
            "email_verified": id_info.get("email_verified", True),
        }
    except Exception as exc:
        logger.warning("Google ID token validation failed: %s", exc)
        raise ValueError(f"Google token validation failed: {str(exc)}") from exc


def _b64url_encode(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).decode("utf-8").rstrip("=")


def _b64url_decode(s: str) -> bytes:
    padding = 4 - (len(s) % 4)
    if padding and padding < 4:
        s += "=" * padding
    return base64.urlsafe_b64decode(s.encode("utf-8"))


def create_access_token(user_id: int, email: str, full_name: str, remember_me: bool = False) -> str:
    """Create a tamper-proof HMAC-SHA256 signed bearer token."""
    now = int(time.time())
    if remember_me:
        exp = now + (TOKEN_EXPIRY_REMEMBER_DAYS * 86400)
    else:
        exp = now + (TOKEN_EXPIRY_HOURS * 3600)

    payload = {
        "sub": user_id,
        "email": email,
        "name": full_name,
        "iat": now,
        "exp": exp,
    }

    payload_bytes = json.dumps(payload, separators=(",", ":")).encode("utf-8")
    payload_b64 = _b64url_encode(payload_bytes)

    sig = hmac.new(
        _AUTH_SECRET.encode("utf-8"),
        payload_b64.encode("utf-8"),
        hashlib.sha256,
    ).digest()
    sig_b64 = _b64url_encode(sig)

    return f"{payload_b64}.{sig_b64}"


def verify_access_token(token: str) -> dict[str, Any] | None:
    """
    Validate HMAC token signature and expiration.
    Returns decoded payload dict if valid, else None.
    """
    try:
        parts = token.strip().split(".")
        if len(parts) != 2:
            return None

        payload_b64, sig_b64 = parts
        expected_sig = hmac.new(
            _AUTH_SECRET.encode("utf-8"),
            payload_b64.encode("utf-8"),
            hashlib.sha256,
        ).digest()

        actual_sig = _b64url_decode(sig_b64)
        if not hmac.compare_digest(expected_sig, actual_sig):
            return None

        payload = json.loads(_b64url_decode(payload_b64).decode("utf-8"))
        exp = payload.get("exp", 0)
        if int(time.time()) > exp:
            return None  # Expired

        return payload
    except Exception as exc:
        logger.debug("Token verification failed: %s", exc)
        return None


def get_token_from_request(request: Request) -> str | None:
    """Extract auth token from HttpOnly cookie first, then Authorization header."""
    # 1. HttpOnly Cookie
    cookie_token = request.cookies.get("access_token")
    if cookie_token:
        return cookie_token

    # 2. Authorization Header
    auth_header = request.headers.get("Authorization")
    if auth_header and auth_header.startswith("Bearer "):
        return auth_header[7:].strip()

    return None


async def get_current_user(
    request: Request,
    db: Session = Depends(get_db),
) -> User:
    """FastAPI dependency: extracts and validates authenticated User."""
    token = get_token_from_request(request)
    if not token:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Authentication required. Please sign in.",
            headers={"WWW-Authenticate": "Bearer"},
        )

    payload = verify_access_token(token)
    if not payload:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Session has expired or is invalid. Please sign in again.",
            headers={"WWW-Authenticate": "Bearer"},
        )

    user_id = payload.get("sub")
    user = db.scalar(select(User).where(User.id == user_id))
    if not user or not user.is_active:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="User account is inactive or not found.",
            headers={"WWW-Authenticate": "Bearer"},
        )

    return user
