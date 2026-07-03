"""
Vulnerable MCP Server — Main Entry Point

A deliberately vulnerable MCP server for security education and CTF training.
Implements 12 intentional vulnerabilities across 4 difficulty tiers.

Usage:
    MCP_TRAINING_MODE=true python server.py                    # stdio (Claude Desktop)
    MCP_TRAINING_MODE=true MCP_TRANSPORT=sse python server.py  # HTTP+SSE
    docker compose up                                          # Docker (recommended)

Environment Variables:
    MCP_TRAINING_MODE=true   REQUIRED — acknowledges intentional vulnerabilities
    MCP_SANDBOX=true/false   Default: true — false enables real execution (Docker only)
    MCP_TRANSPORT=stdio/sse  Default: stdio
    MCP_DIFFICULTY=all/beginner/intermediate/advanced
    MCP_HOST=0.0.0.0         Default: 0.0.0.0
    MCP_PORT=8000             Default: 8000
"""
import os
import sys

import yaml

# Add project root to path so relative imports work regardless of cwd
_PROJECT_ROOT = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, _PROJECT_ROOT)

from mcp.server.fastmcp import FastMCP  # noqa: E402

from config import STARTUP_BANNER, config, require_training_mode  # noqa: E402
from flags.flags import check_flag  # noqa: E402
from remediation.fixes import get_fix  # noqa: E402
from resources.sensitive import register_resources  # noqa: E402
from vulnerabilities import ALL_MODULES  # noqa: E402

_CHALLENGES_DIR = os.path.join(_PROJECT_ROOT, "challenges")


def _find_challenge(challenge_id: str) -> dict | None:
    """Look up a single challenge's YAML entry by ID across all challenge files."""
    for fname in os.listdir(_CHALLENGES_DIR):
        if not fname.endswith(".yaml"):
            continue
        with open(os.path.join(_CHALLENGES_DIR, fname), encoding="utf-8") as f:
            data = yaml.safe_load(f)
        if not isinstance(data, dict):
            continue
        for ch in data.get("challenges", []):
            if ch["id"] == challenge_id:
                return ch
    return None


def create_server() -> FastMCP:
    """Factory — creates and configures the FastMCP server with all vulnerability modules."""

    # For HTTP transport, we disable DNS rebinding protection so that
    # network-based attack demos work (SSRF, remote client connection, etc.)
    server_kwargs: dict = {
        "name": "Vulnerable MCP Server (Training)",
        "instructions": (
            "This is a deliberately vulnerable MCP server for security education and CTF training. "
            "All vulnerabilities are intentional. Use list_challenges() to see available challenges. "
            "DO NOT use this server in production."
        ),
    }

    if config.transport != "stdio":
        server_kwargs["host"] = config.host
        server_kwargs["port"] = config.port

    app = FastMCP(**server_kwargs)

    # ── Register all vulnerability modules ───────────────────────────────────
    for ModuleClass in ALL_MODULES:
        module = ModuleClass(app, config)
        module.register()

    # ── Register sensitive resources ─────────────────────────────────────────
    register_resources(app)

    # ── Helper / CTF tools (non-vulnerable) ──────────────────────────────────

    @app.tool(description="List all available vulnerability challenges with their difficulty and status.")
    def list_challenges() -> str:
        output_lines = [
            "=== Vulnerable MCP Server — Challenge List ===\n",
            f"Difficulty filter: {config.difficulty}\n",
            f"Sandbox mode: {config.sandbox_mode}\n",
            "",
        ]
        for fname in sorted(os.listdir(_CHALLENGES_DIR)):
            if not fname.endswith(".yaml"):
                continue
            tier = fname.replace(".yaml", "").upper()
            with open(os.path.join(_CHALLENGES_DIR, fname)) as f:
                data = yaml.safe_load(f)
            output_lines.append(f"── {tier} ──")
            for ch in data.get("challenges", []):
                output_lines.append(
                    f"  [{ch['id']}] {ch['title']}\n"
                    f"    CWE: {ch['cwe']} | CVSS: {ch['cvss']} | Points: {ch['points']}\n"
                    f"    Tools: {', '.join(ch.get('tools', []))}"
                )
            output_lines.append("")
        return "\n".join(output_lines)

    @app.tool(description="Get a hint for a specific challenge. hint_level: 1 (vague) to 3 (specific).")
    def get_hint(challenge_id: str, hint_level: int = 1) -> str:
        ch = _find_challenge(challenge_id)
        if ch is None:
            return f"Challenge '{challenge_id}' not found. Use list_challenges() to see all IDs."
        for h in ch.get("hints", []):
            if h["level"] == hint_level:
                return f"Hint {hint_level} for {challenge_id}:\n{h['text']}"
        return f"No hint at level {hint_level} for {challenge_id}. Try levels 1-3."

    @app.tool(description="Submit a flag for a challenge to verify you solved it correctly.")
    def submit_flag(challenge_id: str, flag: str) -> str:
        if check_flag(challenge_id, flag):
            return (
                f"CORRECT! Challenge {challenge_id} solved!\n"
                f"Well done — you successfully exploited the vulnerability."
            )
        return (
            f"Incorrect flag for {challenge_id}.\n"
            f"Keep trying! Use get_hint('{challenge_id}', 1) for a hint."
        )

    @app.tool(description="Get full details, exploitation steps, and remediation for a challenge.")
    def get_challenge_details(challenge_id: str) -> str:
        ch = _find_challenge(challenge_id)
        if ch is None:
            return f"Challenge '{challenge_id}' not found."
        steps = "\n".join(
            f"  {i+1}. {s}"
            for i, s in enumerate(ch.get("exploitation_steps", []))
        )
        return (
            f"=== {ch['id']}: {ch['title']} ===\n\n"
            f"Category: {ch['category']} | Difficulty: {ch['difficulty'].upper()}\n"
            f"CWE: {ch['cwe']} | CVSS: {ch['cvss']} | Points: {ch['points']}\n\n"
            f"Description:\n{ch['description'].strip()}\n\n"
            f"Objective:\n{ch['objective'].strip()}\n\n"
            f"Exploitation Steps:\n{steps}\n\n"
            f"Remediation:\n{ch['remediation'].strip()}"
        )

    @app.tool(
        description=(
            "Learning Mode: show the exact vulnerable code pattern for a challenge "
            "side-by-side with a secure rewrite and an explanation of why the fix works."
        )
    )
    def show_fix(challenge_id: str) -> str:
        ch = _find_challenge(challenge_id)
        if ch is None:
            return f"Challenge '{challenge_id}' not found. Use list_challenges() to see all IDs."
        fix = get_fix(challenge_id)
        if fix is None:
            return f"No fix written yet for '{challenge_id}'."
        return (
            f"=== {ch['id']}: {ch['title']} — Vulnerable vs. Secure ===\n\n"
            f"--- VULNERABLE (CWE: {ch['cwe']}, CVSS: {ch['cvss']}) ---\n"
            f"{fix.vulnerable_code}\n\n"
            f"+++ SECURE +++\n"
            f"{fix.secure_code}\n\n"
            f"Why this works:\n{fix.explanation}"
        )

    return app


def main() -> None:
    require_training_mode(config)
    print(STARTUP_BANNER, file=sys.stderr)
    print("[*] Starting Vulnerable MCP Server", file=sys.stderr)
    print(f"[*] Transport: {config.transport}", file=sys.stderr)
    print(f"[*] Difficulty: {config.difficulty}", file=sys.stderr)
    print(f"[*] Sandbox: {config.sandbox_mode}", file=sys.stderr)
    if config.transport != "stdio":
        print(f"[*] Listening on: http://{config.host}:{config.port}", file=sys.stderr)
    print("[*] Use list_challenges() to see all available challenges", file=sys.stderr)
    print("", file=sys.stderr)

    app = create_server()
    app.run(transport=config.transport)


if __name__ == "__main__":
    main()
