"""Automated test suite for centralized OAuth integrations manager and MCP tools."""
import pytest
from app.integrations.manager import manager
from app.integrations.base import ToolExecutionResponse
from app.services.token_service import encrypt_token, decrypt_token


def test_token_encryption_roundtrip():
    secret = "gho_1234567890abcdefghijklmnopqrstuvwxyz"
    encrypted = encrypt_token(secret)
    assert encrypted is not None
    assert encrypted != secret

    decrypted = decrypt_token(encrypted)
    assert decrypted == secret


def test_manager_lists_four_providers():
    providers = manager.list_all_providers()
    provider_ids = [p.provider_id for p in providers]
    assert len(provider_ids) == 4
    assert "github" in provider_ids
    assert "gmail" in provider_ids
    assert "google_drive" in provider_ids
    assert "slack" in provider_ids


def test_state_creation_and_validation():
    user_id = 42
    provider_id = "github"
    state = manager.create_oauth_state(user_id, provider_id)
    assert f"{user_id}:{provider_id}:" in state

    parsed_user = manager.parse_and_validate_state(state, "github")
    assert parsed_user == user_id

    with pytest.raises(ValueError):
        manager.parse_and_validate_state(state, "slack")  # Mismatched provider


def test_github_tools_definition():
    github = manager.get_provider("github")
    assert github is not None
    tool_names = [t.name for t in github.get_tools()]
    assert "github.list_repositories" in tool_names
    assert "github.create_pull_request" in tool_names
    # Check confirmation requirement on PR tool
    pr_tool = next(t for t in github.get_tools() if t.name == "github.create_pull_request")
    assert pr_tool.requires_confirmation is True


def test_gmail_tools_definition():
    gmail = manager.get_provider("gmail")
    assert gmail is not None
    tool_names = [t.name for t in gmail.get_tools()]
    assert "gmail.send_email" in tool_names
    send_tool = next(t for t in gmail.get_tools() if t.name == "gmail.send_email")
    assert send_tool.requires_confirmation is True


def test_slack_tools_definition():
    slack = manager.get_provider("slack")
    assert slack is not None
    tool_names = [t.name for t in slack.get_tools()]
    assert "slack.send_message" in tool_names
    msg_tool = next(t for t in slack.get_tools() if t.name == "slack.send_message")
    assert msg_tool.requires_confirmation is True
