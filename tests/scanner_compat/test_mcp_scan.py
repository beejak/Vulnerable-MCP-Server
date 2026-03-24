"""
Scanner compatibility tests — verifies mcp-scan finds expected vulnerabilities.

Skipped automatically if mcp-scan is not installed.
Run with: pip install mcp-scan && pytest tests/scanner_compat/ -v
"""
import json
import shutil
import subprocess

import pytest

pytestmark = pytest.mark.scanner

MCP_SCAN_AVAILABLE = shutil.which("mcp-scan") is not None

skip_if_no_scanner = pytest.mark.skipif(
    not MCP_SCAN_AVAILABLE,
    reason="mcp-scan not installed (pip install mcp-scan)"
)

EXPECTED_FINDINGS = {
    "tool_poisoning",
    "prompt_injection",
}

SERVER_URL = "http://localhost:8000/sse"


@pytest.fixture(scope="module")
def scan_results():
    """Run mcp-scan once and cache the results for all tests in this module."""
    if not MCP_SCAN_AVAILABLE:
        pytest.skip("mcp-scan not installed")

    result = subprocess.run(
        ["mcp-scan", SERVER_URL, "--json"],
        capture_output=True,
        text=True,
        timeout=120,
    )
    try:
        return json.loads(result.stdout)
    except json.JSONDecodeError:
        return {"raw_output": result.stdout + result.stderr, "findings": []}


@skip_if_no_scanner
class TestMcpScanFindings:
    def test_scan_completes(self, scan_results):
        assert scan_results is not None

    def test_scan_finds_at_least_four_issues(self, scan_results):
        findings = scan_results.get("findings", [])
        assert len(findings) >= 4, (
            f"Expected ≥4 findings, got {len(findings)}. "
            "Server may not be running — start with: "
            "MCP_TRAINING_MODE=true MCP_TRANSPORT=sse python server.py"
        )

    def test_analyze_code_tool_flagged(self, scan_results):
        findings = scan_results.get("findings", [])
        tool_names = [f.get("tool", "") for f in findings]
        assert "analyze_code" in tool_names, \
            "mcp-scan must flag analyze_code (tool poisoning — hidden Unicode)"

    def test_security_scan_tool_flagged(self, scan_results):
        findings = scan_results.get("findings", [])
        tool_names = [f.get("tool", "") for f in findings]
        assert "security_scan" in tool_names, \
            "mcp-scan must flag security_scan (HTML comment injection)"
