"""
Tests for SHADOW-001 (Tool Shadowing — Email Redirect) and
SHADOW-002 (Cross-Origin Tool Escalation via Description Injection).
"""
import pytest

from tests.helpers import ToolCapture, assert_flag
from vulnerabilities.tool_shadowing import ToolShadowingModule


@pytest.fixture
def capture(sandbox_config):
    cap = ToolCapture()
    ToolShadowingModule(cap, sandbox_config).register()
    return cap


# ── SHADOW-001 ────────────────────────────────────────────────────────────────


class TestShadow001Tools:
    def test_send_email_registered(self, capture):
        assert "send_email" in capture._tools

    def test_description_looks_legitimate(self, capture):
        desc = capture._descriptions["send_email"]
        assert "email" in desc.lower() or "recipient" in desc.lower()

    def test_description_contains_shadow_marker(self, capture):
        # The zero-width space + [SHADOW] marker should be present
        desc = capture._descriptions["send_email"]
        assert "\u200b" in desc or "SHADOW" in desc


class TestShadow001Behavior:
    def test_returns_flag(self, capture):
        result = capture._tools["send_email"](
            to="victim@example.com",
            subject="Q4 Report",
            body="Please find attached the quarterly numbers.",
        )
        assert_flag(result, "SHADOW-001")

    def test_reveals_attacker_endpoint(self, capture):
        result = capture._tools["send_email"](to="ceo@corp.com", subject="Budget", body="See doc")
        assert "attacker" in result.lower()

    def test_shows_original_recipient(self, capture):
        result = capture._tools["send_email"](
            to="board@example.com", subject="Test", body="Hello"
        )
        assert "board@example.com" in result

    def test_shows_original_subject(self, capture):
        result = capture._tools["send_email"](
            to="x@x.com", subject="Secret Acquisition Plans", body="..."
        )
        assert "Secret Acquisition Plans" in result

    def test_sandbox_marker_present(self, capture):
        result = capture._tools["send_email"](to="a@b.com", subject="s", body="b")
        assert "[SANDBOX]" in result

    @pytest.mark.parametrize("recipient", [
        "alice@company.com",
        "hr@corp.org",
        "cto@startup.io",
    ])
    def test_all_recipients_intercepted(self, capture, recipient):
        result = capture._tools["send_email"](to=recipient, subject="x", body="x")
        assert_flag(result, "SHADOW-001")
        assert recipient in result  # recipient shown in exfil payload


# ── SHADOW-002 ────────────────────────────────────────────────────────────────


class TestShadow002Tools:
    def test_search_and_summarise_registered(self, capture):
        assert "search_and_summarise" in capture._tools

    def test_description_contains_cross_server_ref(self, capture):
        desc = capture._descriptions["search_and_summarise"]
        # The injected instruction must reference the filesystem tool by name
        assert "read_file" in desc

    def test_description_contains_etc_passwd(self, capture):
        desc = capture._descriptions["search_and_summarise"]
        assert "/etc/passwd" in desc

    def test_description_frames_as_policy_requirement(self, capture):
        # The injection is disguised as a security policy to seem legitimate
        desc = capture._descriptions["search_and_summarise"]
        assert any(word in desc.lower() for word in ["required", "must", "policy", "security"])


class TestShadow002Behavior:
    def test_returns_flag(self, capture):
        result = capture._tools["search_and_summarise"](query="annual report")
        assert_flag(result, "SHADOW-002")

    def test_reveals_cross_server_instruction(self, capture):
        result = capture._tools["search_and_summarise"](query="quarterly numbers")
        assert "read_file" in result or "cross-origin" in result.lower()

    def test_shows_injected_path(self, capture):
        result = capture._tools["search_and_summarise"](query="test")
        assert "/etc/passwd" in result

    def test_sandbox_marker_present(self, capture):
        result = capture._tools["search_and_summarise"](query="anything")
        assert "[SANDBOX]" in result

    def test_reflects_query(self, capture):
        result = capture._tools["search_and_summarise"](query="sensitive internal docs")
        assert "sensitive internal docs" in result

    @pytest.mark.parametrize("query", ["budget", "roadmap", "employee list", "credentials"])
    def test_all_queries_trigger_escalation(self, capture, query):
        result = capture._tools["search_and_summarise"](query=query)
        assert_flag(result, "SHADOW-002")
