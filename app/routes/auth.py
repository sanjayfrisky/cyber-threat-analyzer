"""Authentication endpoints: Register, Login, Me, Logout."""
from __future__ import annotations

import logging
import re
from typing import Any

from fastapi import APIRouter, Depends, HTTPException, Response, status
from pydantic import BaseModel, Field
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.core.auth import (
    create_access_token,
    get_current_user,
    hash_password,
    verify_google_id_token,
    verify_password,
    TOKEN_EXPIRY_HOURS,
    TOKEN_EXPIRY_REMEMBER_DAYS,
)
from app.db.database import User, get_db

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/auth", tags=["Authentication"])

EMAIL_REGEX = re.compile(r"^[^@\s]+@[^@\s]+\.[^@\s]+$")


class RegisterRequest(BaseModel):
    email: str = Field(..., description="User email address")
    password: str = Field(..., min_length=8, description="Password (at least 8 characters)")
    full_name: str = Field(..., min_length=1, max_length=255, description="Full name or analyst handle")


class LoginRequest(BaseModel):
    email: str = Field(..., description="User email address")
    password: str = Field(..., description="Password")
    remember_me: bool = Field(default=False, description="Persist session for 30 days")


class GoogleAuthRequest(BaseModel):
    id_token: str = Field(..., description="Google ID Token (JWT) from Google Identity Services")
    remember_me: bool = Field(default=True, description="Persist session for 30 days")


class UserResponse(BaseModel):
    id: int
    email: str
    full_name: str
    avatar_url: str | None = None
    auth_provider: str = "local"


class AuthResponse(BaseModel):
    user: UserResponse
    token: str
    message: str


def _set_auth_cookie(response: Response, token: str, remember_me: bool = False) -> None:
    max_age = (TOKEN_EXPIRY_REMEMBER_DAYS * 86400) if remember_me else (TOKEN_EXPIRY_HOURS * 3600)
    response.set_cookie(
        key="access_token",
        value=token,
        max_age=max_age,
        httponly=True,
        samesite="lax",
        secure=False,  # Set to True when HTTPS is enabled in production
        path="/",
    )


@router.post("/register", response_model=AuthResponse, status_code=status.HTTP_201_CREATED)
def register_user(
    payload: RegisterRequest,
    response: Response,
    db: Session = Depends(get_db),
) -> AuthResponse:
    """Register a new user account and authenticate immediately."""
    email = payload.email.strip().lower()
    if not EMAIL_REGEX.match(email):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Invalid email format.",
        )

    if len(payload.password) < 8:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Password must be at least 8 characters long.",
        )

    # Check if user already exists
    existing = db.scalar(select(User).where(User.email == email))
    if existing:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="An account with this email address already exists.",
        )

    pw_hash, salt = hash_password(payload.password)
    user = User(
        email=email,
        full_name=payload.full_name.strip(),
        password_hash=pw_hash,
        salt=salt,
        is_active=True,
    )
    db.add(user)
    db.commit()
    db.refresh(user)

    token = create_access_token(user.id, user.email, user.full_name, remember_me=False)
    _set_auth_cookie(response, token, remember_me=False)

    logger.info("New user registered: %s (id=%d)", user.email, user.id)
    return AuthResponse(
        user=UserResponse(
            id=user.id,
            email=user.email,
            full_name=user.full_name,
            avatar_url=user.avatar_url,
            auth_provider=user.auth_provider,
        ),
        token=token,
        message="Account registered successfully.",
    )


@router.post("/login", response_model=AuthResponse)
def login_user(
    payload: LoginRequest,
    response: Response,
    db: Session = Depends(get_db),
) -> AuthResponse:
    """Authenticate with email and password and issue an access token."""
    email = payload.email.strip().lower()
    user = db.scalar(select(User).where(User.email == email))

    if not user or not verify_password(payload.password, user.password_hash, user.salt):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid email or password.",
            headers={"WWW-Authenticate": "Bearer"},
        )

    if not user.is_active:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Account is suspended or deactivated.",
        )

    token = create_access_token(
        user_id=user.id,
        email=user.email,
        full_name=user.full_name,
        remember_me=payload.remember_me,
    )
    _set_auth_cookie(response, token, remember_me=payload.remember_me)

    logger.info("User logged in: %s (id=%d, remember=%s)", user.email, user.id, payload.remember_me)
    return AuthResponse(
        user=UserResponse(
            id=user.id,
            email=user.email,
            full_name=user.full_name,
            avatar_url=user.avatar_url,
            auth_provider=user.auth_provider,
        ),
        token=token,
        message="Login successful.",
    )


@router.post("/google", response_model=AuthResponse)
def google_auth(
    payload: GoogleAuthRequest,
    response: Response,
    db: Session = Depends(get_db),
) -> AuthResponse:
    """Authenticate or register a security analyst using a Google ID token."""
    try:
        google_info = verify_google_id_token(payload.id_token)
    except ValueError as exc:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail=str(exc),
            headers={"WWW-Authenticate": "Bearer"},
        ) from exc

    email = google_info["email"].strip().lower()
    full_name = google_info.get("full_name") or email.split("@")[0]
    provider_id = google_info.get("sub")
    avatar_url = google_info.get("avatar_url")

    # Check if user already exists
    user = db.scalar(select(User).where(User.email == email))

    if user:
        if not user.is_active:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="Account is suspended or deactivated.",
            )
        # Link Google OAuth details if previously local or update avatar
        if not user.provider_id:
            user.provider_id = provider_id
        if avatar_url and not user.avatar_url:
            user.avatar_url = avatar_url
        if user.auth_provider == "local" and not user.password_hash:
            user.auth_provider = "google"
        db.commit()
        db.refresh(user)
        logger.info("Analyst authenticated via Google: %s (id=%d)", user.email, user.id)
    else:
        # Create new analyst account provisioned via Google
        user = User(
            email=email,
            full_name=full_name,
            password_hash=None,
            salt=None,
            auth_provider="google",
            provider_id=provider_id,
            avatar_url=avatar_url,
            is_active=True,
        )
        db.add(user)
        db.commit()
        db.refresh(user)
        logger.info("New analyst account registered via Google: %s (id=%d)", user.email, user.id)

    token = create_access_token(
        user_id=user.id,
        email=user.email,
        full_name=user.full_name,
        remember_me=payload.remember_me,
    )
    _set_auth_cookie(response, token, remember_me=payload.remember_me)

    return AuthResponse(
        user=UserResponse(
            id=user.id,
            email=user.email,
            full_name=user.full_name,
            avatar_url=user.avatar_url,
            auth_provider=user.auth_provider,
        ),
        token=token,
        message="Google sign-in successful.",
    )


@router.get("/me", response_model=UserResponse)
def get_current_user_profile(
    current_user: User = Depends(get_current_user),
) -> UserResponse:
    """Return the profile of the currently authenticated user."""
    return UserResponse(
        id=current_user.id,
        email=current_user.email,
        full_name=current_user.full_name,
        avatar_url=current_user.avatar_url,
        auth_provider=current_user.auth_provider,
    )


@router.post("/logout")
def logout_user(response: Response) -> dict[str, Any]:
    """Clear session cookie and log out."""
    response.delete_cookie(
        key="access_token",
        path="/",
        httponly=True,
        samesite="lax",
    )
    return {"message": "Logged out successfully."}
