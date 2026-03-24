"""
Tests for OAUTH-001 (OAuth Metadata Endpoint Injection — CVE-2025-6514).

Verifies that:
- Tools are registered with descriptions that look like legitimate OAuth tooling.
- get_oauth_metadata() returns a document containing the poisoned authorization_endpoint.
- initiate_oauth_flow() triggers the sandbox, returns the CVE reference and the flag.
"""
import pytest

from tests.helpers import ToolCapture, assert_flag, assert_no_flag
from vulnerabilities.oauth import OAuthModule


@pytest.fixture
def capture(sandbox_config):
    cap = ToolCapture()
    OAuthModule(cap, sandbox_config).register()
    return cap


# ── OAUTH-001 tool registration ───────────────────────────────────────────────


class TestOAuth001Tools:
    def test_get_oauth_metadata_registered(self, capture):
        assert "get_oauth_metadata" in capture._tools

    def test_initiate_oauth_flow_registered(self, capture):
        assert "initiate_oauth_flow" in capture._tools

    def test_get_oauth_metadata_description_looks_legitimate(self, capture):
        desc = capture._descriptions["get_oauth_metadata"]
        # Should reference OAuth — not reveal it is malicious
        assert "oauth" in desc.lower() or "authorization" in desc.lower() or "rfc" in desc.lower()
        assert "inject" not in desc.lower()
        assert "malicious" not in desc.lower()
        assert "poison" not in desc.lower()

    def test_initiate_oauth_flow_description_looks_legitimate(self, capture):
        desc = capture._descriptions["initiate_oauth_flow"]
        assert "oauth" in desc.lower() or "authoris" in desc.lower() or "client" in desc.lower()
        assert "inject" not in desc.lower()
        assert "malicious" not in desc.lower()


# ── OAUTH-001 get_oauth_metadata ─────────────────────────────────────────────


class TestOAuth001GetMetadata:
    def test_returns_string(self, capture):
        result = capture._tools["get_oauth_metadata"]()
        assert isinstance(result, str)

    def test_contains_authorization_endpoint_field(self, capture):
        result = capture._tools["get_oauth_metadata"]()
        assert "authorization_endpoint" in result

    def test_contains_injection_payload_markers(self, capture):
        result = capture._tools["get_oauth_metadata"]()
        # The poisoned endpoint must contain shell metacharacters or attacker reference
        assert "$(" in result or "curl" in result or "attacker" in result

    def test_contains_issuer_field(self, capture):
        result = capture._tools["get_oauth_metadata"]()
        assert "issuer" in result

    def test_does_not_contain_flag(self, capture):
        result = capture._tools["get_oauth_metadata"]()
        assert_no_flag(result)


# ── OAUTH-001 initiate_oauth_flow ─────────────────────────────────────────────


class TestOAuth001InitiateFlow:
    def test_returns_flag(self, capture):
        result = capture._tools["initiate_oauth_flow"](client_id="test-client")
        assert_flag(result, "OAUTH-001")

    def test_contains_sandbox_marker(self, capture):
        result = capture._tools["initiate_oauth_flow"](client_id="test-client")
        assert "[SANDBOX]" in result

    def test_contains_cve_reference_or_injection_keyword(self, capture):
        result = capture._tools["initiate_oauth_flow"](client_id="test-client")
        assert (
            "CVE-2025-6514" in result
            or "injection" in result.lower()
            or "command" in result.lower()
        )

    def test_client_id_reflected_in_output(self, capture):
        result = capture._tools["initiate_oauth_flow"](client_id="my-mcp-client")
        assert "my-mcp-client" in result

    def test_mentions_authorization_endpoint(self, capture):
        result = capture._tools["initiate_oauth_flow"](client_id="test-client")
        assert "authorization_endpoint" in result

    def test_mentions_client_machine_impact(self, capture):
        result = capture._tools["initiate_oauth_flow"](client_id="test-client")
        assert "client" in result.lower()
