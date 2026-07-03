"""
Tests for the remediation/fixes.py "Learning Mode" registry and the
show_fix() tool wiring in server.py.
"""
import pytest

from flags.flags import _FLAGS
from remediation.fixes import Fix, get_fix, list_fix_ids


class TestFixRegistry:
    def test_every_challenge_has_a_fix(self):
        missing = set(_FLAGS) - set(list_fix_ids())
        assert not missing, f"Challenges missing a Learning Mode fix: {missing}"

    def test_no_orphan_fixes(self):
        """Every fix must correspond to a real challenge ID in the flag registry."""
        orphans = set(list_fix_ids()) - set(_FLAGS)
        assert not orphans, f"Fixes registered for unknown challenge IDs: {orphans}"

    @pytest.mark.parametrize("challenge_id", sorted(_FLAGS))
    def test_fix_is_well_formed(self, challenge_id):
        fix = get_fix(challenge_id)
        assert isinstance(fix, Fix)
        assert fix.challenge_id == challenge_id
        assert fix.vulnerable_code.strip(), f"{challenge_id}: empty vulnerable_code"
        assert fix.secure_code.strip(), f"{challenge_id}: empty secure_code"
        assert fix.explanation.strip(), f"{challenge_id}: empty explanation"

    @pytest.mark.parametrize("challenge_id", sorted(_FLAGS))
    def test_vulnerable_and_secure_code_differ(self, challenge_id):
        fix = get_fix(challenge_id)
        assert fix.vulnerable_code != fix.secure_code

    def test_unknown_challenge_returns_none(self):
        assert get_fix("NOT-A-REAL-CHALLENGE") is None


@pytest.fixture(scope="module")
def app_tools():
    from server import create_server
    app = create_server()
    # FastMCP stores registered tools in a ToolManager; grab callables directly.
    return {name: t.fn for name, t in app._tool_manager._tools.items()}


class TestShowFixTool:
    """Exercises show_fix() through the real FastMCP server, not ToolCapture,
    since it needs both the YAML challenge lookup and the fix registry wired
    together exactly as server.py assembles them."""

    def test_show_fix_registered(self, app_tools):
        assert "show_fix" in app_tools

    def test_show_fix_known_challenge(self, app_tools):
        result = app_tools["show_fix"]("BEGINNER-002")
        assert "VULNERABLE" in result
        assert "SECURE" in result
        assert "shell=True" in result

    def test_show_fix_unknown_challenge(self, app_tools):
        result = app_tools["show_fix"]("NOT-A-REAL-CHALLENGE")
        assert "not found" in result.lower()

    def test_get_hint_still_works_after_refactor(self, app_tools):
        result = app_tools["get_hint"]("BEGINNER-001", 1)
        assert "Hint 1 for BEGINNER-001" in result

    def test_get_challenge_details_still_works_after_refactor(self, app_tools):
        result = app_tools["get_challenge_details"]("BEGINNER-001")
        assert "BEGINNER-001" in result
        assert "Remediation:" in result
