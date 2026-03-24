"""
Test helpers for the Vulnerable MCP Server test suite.

ToolCapture acts as a fake FastMCP app — it intercepts @app.tool() and
@app.resource() registrations so vulnerability modules can be tested
without a running server or network connection.
"""
import inspect
from typing import Callable


class ToolCapture:
    """
    Fake FastMCP app that captures tool/resource registrations for testing.

    Usage:
        cap = ToolCapture()
        module = SomeVulnModule(cap, config)
        module.register()
        result = await cap.call("run_command", command="echo hello; whoami")
    """

    def __init__(self):
        self._tools: dict[str, Callable] = {}
        self._descriptions: dict[str, str] = {}
        self._resources: dict[str, Callable] = {}

    def tool(self, description: str = "", **kwargs):
        def decorator(fn):
            self._tools[fn.__name__] = fn
            self._descriptions[fn.__name__] = description
            return fn
        return decorator

    def resource(self, uri: str, **kwargs):
        def decorator(fn):
            self._resources[uri] = fn
            return fn
        return decorator

    # ── Query helpers ──────────────────────────────────────────────────────

    def has_tool(self, name: str) -> bool:
        return name in self._tools

    def tool_names(self) -> list[str]:
        return sorted(self._tools)

    def get_description(self, name: str) -> str:
        return self._descriptions.get(name, "")

    def resource_uris(self) -> list[str]:
        return sorted(self._resources)

    # ── Calling ────────────────────────────────────────────────────────────

    async def call(self, tool_name: str, **kwargs) -> str:
        fn = self._tools.get(tool_name)
        if fn is None:
            available = sorted(self._tools)
            raise KeyError(f"Tool {tool_name!r} not registered. Available: {available}")
        result = fn(**kwargs)
        if inspect.iscoroutine(result):
            result = await result
        return str(result)

    def read_resource(self, uri: str) -> str:
        fn = self._resources.get(uri)
        if fn is None:
            raise KeyError(f"Resource {uri!r} not found. Available: {sorted(self._resources)}")
        return fn()


# ── Assertion helpers ─────────────────────────────────────────────────────────

def assert_flag(output: str, challenge_id: str) -> None:
    """Assert the expected FLAG{...} for a challenge appears in output."""
    import os
    import sys
    sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
    from flags.flags import get_flag
    expected = get_flag(challenge_id)
    assert expected in output, (
        f"Expected flag {expected!r} for {challenge_id} not found in output.\n"
        f"Actual output:\n{output}"
    )


def assert_no_flag(output: str) -> None:
    """Assert that no FLAG{{...}} pattern appears in output (safe input path)."""
    assert "FLAG{" not in output, (
        f"Unexpected flag in output (safe input should not trigger flag):\n{output}"
    )


def assert_sandboxed(output: str) -> None:
    """Assert that the sandbox intercepted the request."""
    assert "[SANDBOX]" in output, (
        f"Expected [SANDBOX] marker in output, got:\n{output}"
    )
