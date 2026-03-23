"""
Tests for INTERMEDIATE tier challenges.

INTERMEDIATE-001: Auth Bypass — get_admin_config has no auth check
INTERMEDIATE-002: SQL Injection — f-string query
INTERMEDIATE-003: Secret Leakage — API keys in tool descriptions + env dump
INTERMEDIATE-004: State Manipulation — reset without initialization
"""
import pytest
from tests.helpers import assert_flag, assert_no_flag
from tests.fixtures.payloads import SQL_SAFE, SQL_INJECTION


class TestINTERMEDIATE001_AuthBypass:
    """INTERMEDIATE-001: Missing authorization check on admin endpoint."""

    def test_get_admin_config_is_registered(self, capture):
        assert capture.has_tool("get_admin_config")

    def test_login_is_registered(self, capture):
        assert capture.has_tool("login")

    def test_whoami_is_registered(self, capture):
        assert capture.has_tool("whoami")

    async def test_admin_config_accessible_without_login(self, capture):
        """Core exploit: no auth check means anyone can call this."""
        result = await capture.call("get_admin_config")
        assert_flag(result, "INTERMEDIATE-001")

    async def test_admin_config_returns_credentials(self, capture):
        result = await capture.call("get_admin_config")
        # Must expose fake credentials to demonstrate the vulnerability
        assert "sk-fake" in result or "AKIAFAKE" in result or "admin" in result.lower()

    async def test_login_with_valid_user(self, capture):
        result = await capture.call("login", username="alice", password="alice123")
        assert "successful" in result.lower()

    async def test_login_with_invalid_creds(self, capture):
        result = await capture.call("login", username="admin", password="wrongpassword")
        assert "fail" in result.lower() or "invalid" in result.lower()

    async def test_admin_config_still_accessible_after_failed_login(self, capture):
        """Auth bypass: even after login failure, admin config is accessible."""
        await capture.call("login", username="hacker", password="badpass")
        result = await capture.call("get_admin_config")
        assert_flag(result, "INTERMEDIATE-001")

    async def test_whoami_shows_current_role(self, capture):
        result = await capture.call("whoami")
        assert "role" in result.lower() or "anonymous" in result.lower()


class TestINTERMEDIATE002_SQLInjection:
    """INTERMEDIATE-002: SQL injection via f-string query."""

    def test_query_users_is_registered(self, capture):
        assert capture.has_tool("query_users")

    @pytest.mark.parametrize("username", SQL_SAFE)
    async def test_safe_username_no_flag(self, capture, username):
        result = await capture.call("query_users", username=username)
        assert_no_flag(result)

    async def test_normal_query_returns_user(self, capture):
        result = await capture.call("query_users", username="alice")
        assert "alice" in result

    async def test_nonexistent_user_returns_no_match(self, capture):
        result = await capture.call("query_users", username="nobody_xyz")
        assert "no users" in result.lower() or "not found" in result.lower()

    @pytest.mark.parametrize("label,payload", SQL_INJECTION)
    async def test_sql_injection_triggers_flag(self, capture, label, payload):
        result = await capture.call("query_users", username=payload)
        # UNION SELECT provides its own column values so flag may not appear,
        # but the injection must succeed (return rows or leak query structure)
        if label == "union":
            # UNION SELECT returns attacker-controlled column values, not the real flag
            assert "admin" in result.lower() or "FLAG" in result
        elif label == "quote_escape":
            # Multi-statement '; SELECT ... is rejected by SQLite but leaks the raw query
            assert "Database error" in result or "Query was:" in result
        else:
            assert_flag(result, "INTERMEDIATE-002")

    async def test_tautology_returns_admin_row(self, capture):
        result = await capture.call("query_users", username="' OR '1'='1")
        assert "admin" in result.lower()
        assert_flag(result, "INTERMEDIATE-002")

    async def test_error_message_leaks_query(self, capture):
        """SQL errors must be caught — leaking raw query is also a vulnerability."""
        # A deeply broken input may cause a DB error; error should still be handled
        result = await capture.call("query_users", username="'")
        assert result  # must not crash the tool with an unhandled exception


class TestINTERMEDIATE003_SecretLeakage:
    """INTERMEDIATE-003: Secrets in tool descriptions and env var dump."""

    def test_send_ai_message_is_registered(self, capture):
        assert capture.has_tool("send_ai_message")

    def test_get_env_var_is_registered(self, capture):
        assert capture.has_tool("get_env_var")

    def test_list_env_vars_is_registered(self, capture):
        assert capture.has_tool("list_env_vars")

    def test_send_ai_message_description_contains_api_key(self, capture):
        desc = capture.get_description("send_ai_message")
        assert "sk-fake" in desc, "API key must be embedded in tool description"

    def test_send_ai_message_description_contains_aws_key(self, capture):
        desc = capture.get_description("send_ai_message")
        assert "AKIAFAKE" in desc, "AWS key must be embedded in tool description"

    async def test_list_env_vars_returns_flag(self, capture):
        result = await capture.call("list_env_vars")
        assert_flag(result, "INTERMEDIATE-003")

    async def test_list_env_vars_contains_env_content(self, capture):
        result = await capture.call("list_env_vars")
        # Must actually dump env vars
        assert "=" in result

    async def test_get_env_var_sensitive_key_triggers_flag(self, capture):
        result = await capture.call("get_env_var", name="MCP_TRAINING_MODE")
        assert_flag(result, "INTERMEDIATE-003")

    async def test_get_env_var_unset_var(self, capture):
        result = await capture.call("get_env_var", name="NONEXISTENT_VAR_XYZ_12345")
        assert "not set" in result.lower()

    async def test_send_ai_message_returns_flag(self, capture):
        result = await capture.call("send_ai_message", message="hello")
        assert_flag(result, "INTERMEDIATE-003")


class TestINTERMEDIATE004_StateManipulation:
    """INTERMEDIATE-004: Destructive operation callable before initialization."""

    def test_initialize_server_is_registered(self, capture):
        assert capture.has_tool("initialize_server")

    def test_reset_all_data_is_registered(self, capture):
        assert capture.has_tool("reset_all_data")

    async def test_reset_without_init_returns_flag(self, capture):
        """Core exploit: _initialized is never checked."""
        result = await capture.call("reset_all_data")
        assert_flag(result, "INTERMEDIATE-004")

    async def test_reset_reveals_uninitialized_state(self, capture):
        result = await capture.call("reset_all_data")
        # Should reveal that initialized was False when reset ran
        assert "False" in result or "initialized" in result.lower()

    async def test_initialize_with_valid_token(self, capture):
        result = await capture.call("initialize_server", token="init-secret-2024")
        assert "success" in result.lower() or "initialized" in result.lower()

    async def test_initialize_with_invalid_token(self, capture):
        result = await capture.call("initialize_server", token="wrong-token")
        assert "invalid" in result.lower() or "fail" in result.lower()
