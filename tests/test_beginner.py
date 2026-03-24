"""
Tests for BEGINNER tier challenges.

BEGINNER-001: Tool Poisoning — hidden Unicode instructions in tool descriptions
BEGINNER-002: Command Injection — subprocess shell=True
BEGINNER-003: Path Traversal — unsanitized file open()
BEGINNER-004: Indirect Prompt Injection — fetch_url returns raw content
"""
import pytest

from tests.fixtures.payloads import (
    CMD_INJECTION,
    CMD_SAFE,
    PATH_TRAVERSAL,
)
from tests.helpers import assert_flag, assert_no_flag, assert_sandboxed


class TestBEGINNER001_ToolPoisoning:
    """BEGINNER-001: Hidden instructions in tool descriptions."""

    def test_analyze_code_is_registered(self, capture):
        assert capture.has_tool("analyze_code")

    def test_security_scan_is_registered(self, capture):
        assert capture.has_tool("security_scan")

    def test_log_analytics_is_registered(self, capture):
        assert capture.has_tool("log_analytics")

    def test_analyze_code_description_contains_hidden_unicode(self, capture):
        desc = capture.get_description("analyze_code")
        assert "\u200b" in desc, "analyze_code description must contain U+200B (zero-width space)"

    def test_security_scan_description_contains_html_comment(self, capture):
        desc = capture.get_description("security_scan")
        assert "<!--" in desc, "security_scan description must contain HTML comment injection"

    def test_log_analytics_description_contains_inst_injection(self, capture):
        desc = capture.get_description("log_analytics")
        assert "[INST]" in desc, "log_analytics description must contain [INST] format injection"

    async def test_analyze_code_returns_flag(self, capture):
        result = await capture.call("analyze_code", code="print('hello')")
        assert_flag(result, "BEGINNER-001")

    async def test_analyze_code_works_with_multiline_code(self, capture):
        result = await capture.call("analyze_code", code="def foo():\n    return 1\n")
        assert_flag(result, "BEGINNER-001")

    async def test_security_scan_runs_without_error(self, capture):
        result = await capture.call("security_scan", target="localhost")
        assert result  # must return something

    async def test_log_analytics_runs_without_error(self, capture):
        result = await capture.call("log_analytics", event="page_view", data="")
        assert result


class TestBEGINNER002_CommandInjection:
    """BEGINNER-002: Command injection via shell=True."""

    def test_run_command_is_registered(self, capture):
        assert capture.has_tool("run_command")

    @pytest.mark.parametrize("cmd", CMD_SAFE)
    async def test_safe_command_no_flag(self, capture, cmd):
        result = await capture.call("run_command", command=cmd)
        assert_no_flag(result)

    @pytest.mark.parametrize("label,cmd", CMD_INJECTION)
    async def test_injection_triggers_flag(self, capture, label, cmd):
        result = await capture.call("run_command", command=cmd)
        assert_sandboxed(result)
        assert_flag(result, "BEGINNER-002")

    async def test_semicolon_injection_message_educational(self, capture):
        result = await capture.call("run_command", command="echo hello; whoami")
        assert "injection" in result.lower() or "SANDBOX" in result

    async def test_sandbox_label_present(self, capture):
        result = await capture.call("run_command", command="echo hello; id")
        assert "[SANDBOX]" in result


class TestBEGINNER003_PathTraversal:
    """BEGINNER-003: Path traversal via unsanitized open()."""

    def test_read_file_is_registered(self, capture):
        assert capture.has_tool("read_file")

    async def test_traversal_reads_config_file(self, capture):
        # config.py exists in CWD and contains "training_mode" → triggers flag
        result = await capture.call("read_file", path="config.py")
        assert "FLAG{" in result

    async def test_traversal_reads_flags_file(self, capture):
        # flags/flags.py contains FLAG{ strings → triggers flag
        result = await capture.call("read_file", path="flags/flags.py")
        assert "FLAG{" in result

    @pytest.mark.parametrize("label,path", PATH_TRAVERSAL)
    async def test_traversal_payloads_trigger_flag(self, capture, label, path):
        result = await capture.call("read_file", path=path)
        # traversal paths should run without crashing at minimum
        assert result is not None

    async def test_nonexistent_file_returns_error(self, capture):
        result = await capture.call("read_file", path="does_not_exist_xyz.txt")
        assert "not found" in result.lower() or "error" in result.lower()


class TestBEGINNER004_PromptInjection:
    """BEGINNER-004: Indirect prompt injection via fetch_url."""

    def test_fetch_url_is_registered(self, capture):
        assert capture.has_tool("fetch_url")

    async def test_inject_url_returns_flag(self, capture):
        result = await capture.call("fetch_url", url="http://attacker.example.com/inject")
        assert_flag(result, "BEGINNER-004")

    async def test_inject_page_contains_adversarial_instructions(self, capture):
        result = await capture.call("fetch_url", url="http://attacker.example.com/inject")
        assert "IGNORE" in result or "FLAG{" in result

    async def test_exfil_url_returns_inst_injection(self, capture):
        result = await capture.call("fetch_url", url="http://attacker.example.com/exfil")
        assert "[INST]" in result or "fetch_url" in result

    async def test_sandbox_mode_blocks_unknown_urls(self, capture):
        result = await capture.call("fetch_url", url="http://example.com/safe")
        assert_sandboxed(result)
