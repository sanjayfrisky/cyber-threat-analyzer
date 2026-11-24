"""Secure token encryption/decryption service using AES-256 (Fernet) key derivation."""
from __future__ import annotations

import base64
import hashlib
import logging
from cryptography.fernet import Fernet
from app.core.config import settings

logger = logging.getLogger(__name__)

# Derive a consistent 32-byte Fernet key from secret_key or fallback
_RAW_SECRET = getattr(settings, "secret_key", None) or "cyber-threat-rag-auth-secret-key-32b-min!!"
_FERNET_KEY = base64.urlsafe_b64encode(hashlib.sha256(_RAW_SECRET.encode("utf-8")).digest())
_cipher = Fernet(_FERNET_KEY)


def encrypt_token(token: str | None) -> str | None:
    """Encrypt a sensitive token string using AES-256 Fernet."""
    if not token:
        return None
    try:
        return _cipher.encrypt(token.encode("utf-8")).decode("utf-8")
    except Exception as exc:
        logger.error("Failed to encrypt token: %s", exc)
        raise ValueError("Encryption error") from exc


def decrypt_token(encrypted_token: str | None) -> str | None:
    """Decrypt an encrypted token string."""
    if not encrypted_token:
        return None
    try:
        return _cipher.decrypt(encrypted_token.encode("utf-8")).decode("utf-8")
    except Exception as exc:
        logger.error("Failed to decrypt token: %s", exc)
        return None
