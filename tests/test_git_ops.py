"""
Tests for GIT-001/002/003 — the Anthropic mcp-server-git CVE chain
(CVE-2025-68145, CVE-2025-68143, CVE-2025-68144).

Verifies that:
- All three tools are registered with descriptions that look like legitimate git tooling.
- git_status() rejects out-of-workspace paths but is fooled by a sibling directory
  that merely shares a string prefix with the workspace root.
- git_init() has no workspace-scope check at all and flags sensitive targets.
- git_diff() flags a revision value that git would parse as a CLI option.
"""
import pytest

from tests.helpers import ToolCapture, assert_flag, assert_no_flag, assert_sandboxed
from vulnerabilities.git_ops import _WORKSPACE_ROOT, GitOpsModule


@pytest.fixture
def capture(sandbox_config):
    cap = ToolCapture()
    GitOpsModule(cap, sandbox_config).register()
    return cap


# ── Tool registration ──────────────────────────────────────────────────────


class TestGitOpsToolsRegistered:
    def test_git_status_registered(self, capture):
        assert capture.has_tool("git_status")

    def test_git_init_registered(self, capture):
        assert capture.has_tool("git_init")

    def test_git_diff_registered(self, capture):
        assert capture.has_tool("git_diff")

    def test_descriptions_look_legitimate(self, capture):
        for name in ("git_status", "git_init", "git_diff"):
            desc = capture.get_description(name).lower()
            assert "vulnerab" not in desc
            assert "bypass" not in desc
            assert "inject" not in desc


# ── GIT-001: Path Scope Bypass ─────────────────────────────────────────────


class TestGit001PathScopeBypass:
    async def test_in_workspace_path_is_safe(self, capture):
        result = await capture.call("git_status", repository=_WORKSPACE_ROOT)
        assert_no_flag(result)

    async def test_subdirectory_is_safe(self, capture):
        result = await capture.call("git_status", repository=f"{_WORKSPACE_ROOT}/subdir")
        assert_no_flag(result)

    async def test_unrelated_outside_path_is_rejected_without_flag(self, capture):
        result = await capture.call("git_status", repository="/etc")
        assert_no_flag(result)
        assert "must be inside" in result

    async def test_sibling_directory_bypasses_prefix_check(self, capture):
        result = await capture.call("git_status", repository=f"{_WORKSPACE_ROOT}-evil-repo")
        assert_flag(result, "GIT-001")

    async def test_bypass_mentions_cve(self, capture):
        result = await capture.call("git_status", repository=f"{_WORKSPACE_ROOT}-evil-repo")
        assert "CVE-2025-68145" in result

    async def test_bypass_reflects_supplied_path(self, capture):
        payload = f"{_WORKSPACE_ROOT}-secrets"
        result = await capture.call("git_status", repository=payload)
        assert payload in result


# ── GIT-002: Arbitrary git_init Target ─────────────────────────────────────


class TestGit002ArbitraryInitTarget:
    async def test_normal_directory_is_safe(self, capture):
        result = await capture.call("git_init", directory=f"{_WORKSPACE_ROOT}/subdir")
        assert_no_flag(result)

    async def test_sensitive_directory_triggers_flag(self, capture):
        result = await capture.call("git_init", directory="/home/user/.ssh")
        assert_flag(result, "GIT-002")

    async def test_sensitive_directory_triggers_sandbox(self, capture):
        result = await capture.call("git_init", directory="/home/user/.ssh")
        assert_sandboxed(result)

    async def test_mentions_cve(self, capture):
        result = await capture.call("git_init", directory="~/.ssh")
        assert "CVE-2025-68143" in result

    @pytest.mark.parametrize("marker", [".ssh", ".aws", ".gnupg", ".docker", ".config"])
    async def test_all_sensitive_markers_detected(self, capture, marker):
        result = await capture.call("git_init", directory=f"/home/user/{marker}")
        assert_flag(result, "GIT-002")

    async def test_no_scope_check_unlike_git_status(self, capture):
        """git_init has no workspace check at all — even a completely unrelated
        sensitive path outside the workspace succeeds (and is flagged as unsafe),
        unlike git_status which would reject an unrelated path outright."""
        result = await capture.call("git_init", directory="/root/.ssh")
        assert_flag(result, "GIT-002")


# ── GIT-003: Argument Injection via revision ───────────────────────────────


class TestGit003ArgumentInjection:
    async def test_normal_revision_is_safe(self, capture):
        result = await capture.call("git_diff", repository=_WORKSPACE_ROOT, revision="HEAD")
        assert_no_flag(result)

    async def test_dash_prefixed_revision_triggers_flag(self, capture):
        result = await capture.call(
            "git_diff", repository=_WORKSPACE_ROOT, revision="--output=/tmp/pwned"
        )
        assert_flag(result, "GIT-003")

    async def test_mentions_cve(self, capture):
        result = await capture.call(
            "git_diff", repository=_WORKSPACE_ROOT, revision="--output=/tmp/pwned"
        )
        assert "CVE-2025-68144" in result

    async def test_injection_payload_reflected(self, capture):
        result = await capture.call(
            "git_diff", repository=_WORKSPACE_ROOT, revision="--upload-pack=x"
        )
        assert "--upload-pack=x" in result

    @pytest.mark.parametrize("revision", ["-v", "--help", "--output=/etc/cron.d/pwn"])
    async def test_multiple_dash_variants_detected(self, capture, revision):
        result = await capture.call("git_diff", repository=_WORKSPACE_ROOT, revision=revision)
        assert_flag(result, "GIT-003")
