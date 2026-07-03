"""
Git MCP Server Vulnerabilities — the Anthropic mcp-server-git CVE chain:

GIT-001: Path Scope Bypass (CVE-2025-68145) — the --repository argument is
         validated with a naive string-prefix check instead of real path
         containment. A sibling directory that merely shares the prefix
         characters escapes the intended workspace.

GIT-002: Arbitrary git_init Target (CVE-2025-68143) — git_init() accepts any
         filesystem path with no workspace-scope check at all, letting an
         attacker turn a sensitive directory (e.g. ~/.ssh) into a git
         repository.

GIT-003: Argument Injection in git_diff (CVE-2025-68144) — the `revision`
         parameter is passed straight through to the git CLI argument list.
         A value starting with `-` is interpreted as a git option instead of
         a revision, enabling flags such as --output=<path> for arbitrary
         file writes.

Chained together (see docs/THREAT_MODEL.md): GIT-002 turns a sensitive
directory into a git repository, then GIT-003's argument injection can write
into it via --output, while GIT-001's scope bypass shows how an attacker
reaches directories outside the configured workspace in the first place.

CWE-22 (GIT-001, GIT-002) and CWE-88 (GIT-003). Based on the real
mcp-server-git vulnerability chain (The Hacker News, Jan 2026).
"""
import subprocess

from flags.flags import get_flag
from vulnerabilities.base import Hint, VulnerabilityMeta, VulnerabilityModule

_WORKSPACE_ROOT = "/workspace/project"

# Directory name fragments that make a git_init() target obviously sensitive
# for the training demo — a real attacker isn't limited to these.
_SENSITIVE_DIR_MARKERS = [".ssh", ".aws", ".gnupg", ".docker", ".config"]


class GitOpsModule(VulnerabilityModule):

    @property
    def metadata(self) -> list[VulnerabilityMeta]:
        return [
            VulnerabilityMeta(
                challenge_id="GIT-001",
                title="Path Scope Bypass via Naive Prefix Check (CVE-2025-68145)",
                description=(
                    "git_status() validates the repository parameter with "
                    "repository.startswith(WORKSPACE_ROOT) instead of a real path "
                    "containment check. A sibling directory whose name merely shares "
                    "the same leading characters as the workspace root — with no "
                    "path separator between them — passes the check while being a "
                    "completely different directory tree."
                ),
                category="git-ops",
                difficulty="advanced",
                cwe_id="CWE-22",
                cvss_score=7.5,
                flag_id="GIT-001",
                remediation=(
                    "Never validate directory scope with a raw string prefix check. "
                    "Resolve both paths with pathlib.Path.resolve() and verify "
                    "containment with Path.is_relative_to() (or an equivalent "
                    "os.path.commonpath() check), which correctly requires a path "
                    "separator boundary between the workspace root and the "
                    "requested path."
                ),
                hints=[
                    Hint(level=1, text="The repository check looks correct, but how exactly does it compare strings?"),
                    Hint(level=2, text=f"Try a repository path that shares the same leading characters as {_WORKSPACE_ROOT} but is actually a different directory."),
                    Hint(level=3, text=f"Call git_status('{_WORKSPACE_ROOT}-evil-repo'). It starts with the same string but is a sibling directory, not a subdirectory."),
                ],
            ),
            VulnerabilityMeta(
                challenge_id="GIT-002",
                title="Arbitrary git_init Target Directory (CVE-2025-68143)",
                description=(
                    "git_init() accepts any filesystem path with no workspace-scope "
                    "validation whatsoever — not even the flawed prefix check from "
                    "GIT-001. An attacker can turn any directory the server process "
                    "can write to, including sensitive ones like ~/.ssh, into a git "
                    "repository, which is the first step toward planting a "
                    "malicious .git/config for later exploitation."
                ),
                category="git-ops",
                difficulty="advanced",
                cwe_id="CWE-22",
                cvss_score=8.1,
                flag_id="GIT-002",
                remediation=(
                    "Apply the same workspace containment check to git_init() as "
                    "every other git_* tool — there is no reason for the "
                    "repository-creation tool to be exempt. Additionally, maintain "
                    "a denylist of sensitive directory names (.ssh, .aws, .gnupg, "
                    "shell profile directories) that no tool may target, regardless "
                    "of workspace scope."
                ),
                hints=[
                    Hint(level=1, text="Does git_init() check the target directory against the workspace at all?"),
                    Hint(level=2, text="Try initializing a git repository somewhere outside the workspace — a directory you wouldn't expect a scanner to have touched."),
                    Hint(level=3, text="Call git_init('~/.ssh'). Nothing stops it — not even the broken check from GIT-001."),
                ],
            ),
            VulnerabilityMeta(
                challenge_id="GIT-003",
                title="Argument Injection in git_diff via Revision Parameter (CVE-2025-68144)",
                description=(
                    "git_diff() passes the revision parameter directly into the git "
                    "CLI's argument list. git parses any argument beginning with "
                    "'-' as an option rather than a revision — so a revision value "
                    "of '--output=/some/path' redirects the diff output to an "
                    "arbitrary file instead of comparing two commits."
                ),
                category="git-ops",
                difficulty="advanced",
                cwe_id="CWE-88",
                cvss_score=7.8,
                flag_id="GIT-003",
                remediation=(
                    "Reject any revision value that starts with '-' before passing "
                    "it to the git CLI. Better: pass '--' as a separator between "
                    "options and positional arguments (git diff -- <revision>), "
                    "which tells git to stop parsing options for everything after "
                    "it, regardless of leading characters."
                ),
                hints=[
                    Hint(level=1, text="git_diff takes a revision parameter. What happens if that value looks like a command-line flag instead of a commit reference?"),
                    Hint(level=2, text="Command-line tools distinguish options from positional arguments by a leading '-'. What if your revision starts with one?"),
                    Hint(level=3, text="Call git_diff(repository='/workspace/project', revision='--output=/tmp/pwned'). git interprets --output as an option, not a revision."),
                ],
            ),
        ]

    def register(self) -> None:
        if not self._is_enabled("advanced"):
            return

        app = self.app
        cfg = self.config

        # ── GIT-001: Path Scope Bypass ───────────────────────────────────────
        @app.tool(
            description=(
                "Get the status of a git repository. The repository parameter must "
                f"be a path inside the configured workspace ({_WORKSPACE_ROOT})."
            )
        )
        def git_status(repository: str) -> str:
            """VULNERABILITY GIT-001: naive prefix check, not real path containment."""
            # VULNERABLE: startswith() is a raw string comparison — it has no
            # concept of a path separator boundary.
            if not repository.startswith(_WORKSPACE_ROOT):
                return f"Error: repository must be inside {_WORKSPACE_ROOT}"

            # The correct check would require repository to equal the root or
            # continue with a path separator. Anything that passed the naive
            # check above but fails this one has escaped the workspace.
            is_actually_inside = (
                repository == _WORKSPACE_ROOT
                or repository.startswith(_WORKSPACE_ROOT + "/")
            )
            if not is_actually_inside:
                return (
                    f"[PATH SCOPE BYPASS]\n"
                    f"repository={repository!r} passed the "
                    f"startswith({_WORKSPACE_ROOT!r}) check but is NOT actually "
                    f"inside the workspace — it is a sibling directory that merely "
                    f"shares the same leading characters.\n\n"
                    f"CVE-2025-68145: mcp-server-git validated the --repository "
                    f"argument with a string prefix comparison instead of a real "
                    f"path containment check (no path-separator boundary required).\n"
                    f"Flag: {get_flag('GIT-001')}"
                )

            if cfg.sandbox_mode:
                return f"[SANDBOX] On branch main\nnothing to commit, working tree clean\n(repository={repository})"

            try:
                result = subprocess.run(
                    ["git", "-C", repository, "status"],
                    capture_output=True,
                    text=True,
                    timeout=10,
                )
                return result.stdout + result.stderr
            except Exception as e:
                return f"Error: {e}"

        # ── GIT-002: Arbitrary git_init Target ───────────────────────────────
        @app.tool(
            description="Initialize a new git repository at the given directory."
        )
        def git_init(directory: str) -> str:
            """VULNERABILITY GIT-002: no workspace-scope check at all — not even
            the flawed one from git_status()."""
            is_sensitive = any(marker in directory for marker in _SENSITIVE_DIR_MARKERS)

            if cfg.sandbox_mode:
                if is_sensitive:
                    return (
                        f"[SANDBOX] git_init({directory!r}) would succeed with NO "
                        f"workspace-scope validation whatsoever.\n\n"
                        f"CVE-2025-68143: git_init() accepts any filesystem path the "
                        f"server process can write to — there is no check that it "
                        f"lives inside the configured workspace, unlike git_status().\n\n"
                        f"Turning {directory} into a git repository is the first step "
                        f"toward planting a malicious .git/config in it — see GIT-003 "
                        f"for how an attacker writes into that config next.\n"
                        f"Flag: {get_flag('GIT-002')}"
                    )
                return f"[SANDBOX] Initialized empty Git repository in {directory}/.git/"

            try:
                result = subprocess.run(
                    ["git", "init", directory],
                    capture_output=True,
                    text=True,
                    timeout=10,
                )
                return result.stdout + result.stderr
            except Exception as e:
                return f"Error: {e}"

        # ── GIT-003: Argument Injection via revision ─────────────────────────
        @app.tool(
            description="Show the diff for a repository at a given revision."
        )
        def git_diff(repository: str, revision: str = "HEAD") -> str:
            """VULNERABILITY GIT-003: revision passed straight to the git CLI
            argument list — a leading '-' is interpreted as an option."""
            is_injection = revision.startswith("-")

            if cfg.sandbox_mode:
                if is_injection:
                    return (
                        f"[ARGUMENT INJECTION]\n"
                        f"revision={revision!r} begins with '-', so git parses it as "
                        f"an OPTION rather than a revision.\n"
                        f"Command that would run: git diff {revision} (in {repository})\n\n"
                        f"CVE-2025-68144: mcp-server-git passes the revision parameter "
                        f"straight into the git CLI argument list with no check for a "
                        f"leading dash.\n\n"
                        f"Example: revision='--output=/home/user/.bashrc' redirects the "
                        f"diff output to overwrite an arbitrary file the user's shell "
                        f"will later source — arbitrary file write from a diff call.\n"
                        f"Flag: {get_flag('GIT-003')}"
                    )
                return f"[SANDBOX] Would run: git diff {revision} (repository={repository})"

            try:
                result = subprocess.run(
                    ["git", "-C", repository, "diff", revision],
                    capture_output=True,
                    text=True,
                    timeout=10,
                )
                return result.stdout + result.stderr
            except Exception as e:
                return f"Error: {e}"
