"""Tests for authentication endpoints: registration, login, token verification, session and logout."""
import pytest
from fastapi.testclient import TestClient

from app.main import app

client = TestClient(app)


def test_auth_full_lifecycle():
    unique_email = f"analyst_{int(pytest.importorskip('time').time())}@cyber.local"
    password = "SecOpsPassword2026!"
    name = "Cyber Analyst"

    # 1. Register
    reg_resp = client.post(
        "/api/auth/register",
        json={"email": unique_email, "password": password, "full_name": name},
    )
    assert reg_resp.status_code == 201, reg_resp.text
    data = reg_resp.json()
    assert data["user"]["email"] == unique_email
    assert data["user"]["full_name"] == name
    assert "token" in data
    assert "access_token" in reg_resp.cookies

    token = data["token"]

    # 2. Duplicate registration fails
    dup_resp = client.post(
        "/api/auth/register",
        json={"email": unique_email, "password": password, "full_name": name},
    )
    assert dup_resp.status_code == 400
    assert "already exists" in dup_resp.json()["detail"]

    # 3. Invalid email format fails
    inv_email = client.post(
        "/api/auth/register",
        json={"email": "not-an-email", "password": password, "full_name": name},
    )
    assert inv_email.status_code == 400

    # 4. Short password fails
    short_pw = client.post(
        "/api/auth/register",
        json={"email": "valid@cyber.local", "password": "short", "full_name": name},
    )
    assert short_pw.status_code == 422 or short_pw.status_code == 400

    # 5. Login with invalid password fails
    bad_login = client.post(
        "/api/auth/login",
        json={"email": unique_email, "password": "WrongPassword123!"},
    )
    assert bad_login.status_code == 401

    # 6. Login with valid password succeeds
    login_resp = client.post(
        "/api/auth/login",
        json={"email": unique_email, "password": password, "remember_me": True},
    )
    assert login_resp.status_code == 200
    login_data = login_resp.json()
    assert login_data["user"]["email"] == unique_email
    assert "access_token" in login_resp.cookies

    # 7. Check /api/auth/me with Bearer token
    me_resp = client.get(
        "/api/auth/me",
        headers={"Authorization": f"Bearer {token}"},
    )
    assert me_resp.status_code == 200
    assert me_resp.json()["email"] == unique_email

    # 8. Check /api/auth/me with Cookie
    cookie_client = TestClient(app)
    # Login again to get cookie on this client
    cookie_client.post(
        "/api/auth/login",
        json={"email": unique_email, "password": password},
    )
    me_cookie = cookie_client.get("/api/auth/me")
    assert me_cookie.status_code == 200
    assert me_cookie.json()["email"] == unique_email

    # 9. Check /api/auth/me unauthorized without credentials
    anon_client = TestClient(app)
    anon_resp = anon_client.get("/api/auth/me")
    assert anon_resp.status_code == 401

    # 10. Logout
    logout_resp = cookie_client.post("/api/auth/logout")
    assert logout_resp.status_code == 200
    # Following request without auth header should now be 401
    me_after_logout = cookie_client.get("/api/auth/me")
    assert me_after_logout.status_code == 401
