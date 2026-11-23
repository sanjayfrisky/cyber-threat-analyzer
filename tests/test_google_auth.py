"""Tests for Google OAuth authentication endpoint (/api/auth/google)."""
from unittest.mock import patch
import pytest
from fastapi.testclient import TestClient

from app.main import app

client = TestClient(app)


def test_google_auth_new_user():
    fake_token = "mock_valid_google_id_token_123"
    fake_google_payload = {
        "sub": "google_uid_987654321",
        "email": "google_analyst@threat-intel.org",
        "full_name": "Google Security Analyst",
        "avatar_url": "https://lh3.googleusercontent.com/a/mock-pic",
        "email_verified": True,
    }

    with patch("app.routes.auth.verify_google_id_token", return_value=fake_google_payload):
        resp = client.post(
            "/api/auth/google",
            json={"id_token": fake_token, "remember_me": True},
        )
        assert resp.status_code == 200, resp.text
        data = resp.json()
        assert data["user"]["email"] == "google_analyst@threat-intel.org"
        assert data["user"]["full_name"] == "Google Security Analyst"
        assert data["user"]["auth_provider"] == "google"
        assert data["user"]["avatar_url"] == "https://lh3.googleusercontent.com/a/mock-pic"
        assert "token" in data
        assert "access_token" in resp.cookies


def test_google_auth_existing_user():
    fake_token = "mock_valid_google_id_token_existing"
    fake_google_payload = {
        "sub": "google_uid_987654321",
        "email": "google_analyst@threat-intel.org",
        "full_name": "Google Security Analyst (Updated)",
        "avatar_url": "https://lh3.googleusercontent.com/a/mock-pic-2",
        "email_verified": True,
    }

    with patch("app.routes.auth.verify_google_id_token", return_value=fake_google_payload):
        resp = client.post(
            "/api/auth/google",
            json={"id_token": fake_token, "remember_me": False},
        )
        assert resp.status_code == 200
        data = resp.json()
        assert data["user"]["email"] == "google_analyst@threat-intel.org"
        assert "token" in data


def test_google_auth_invalid_token():
    fake_token = "invalid_or_expired_google_token"

    with patch("app.routes.auth.verify_google_id_token", side_effect=ValueError("Token expired")):
        resp = client.post(
            "/api/auth/google",
            json={"id_token": fake_token},
        )
        assert resp.status_code == 401
        assert "Token expired" in resp.json()["detail"]
