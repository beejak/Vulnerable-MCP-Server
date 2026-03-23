"""
Testing Agent

Verifies that each vulnerability challenge is actually exploitable.
Runs the pytest test suite, interprets failures, and validates scanner
compatibility. Can also write standalone exploit scripts.
"""
import asyncio
import json
import os
import subprocess
import sys
from agents.base_agent import BaseAgent


class TestingAgent(BaseAgent):

    def __init__(self, event_bus: asyncio.Queue, work_dir: str = None):
        super().__init__("TESTING", event_bus, work_dir)

    @property
    def system_prompt(self) -> str:
        return """You are a security testing specialist. Your job is to verify that each
challenge in the vulnerable MCP server is actually exploitable and returns the correct flag.

WHAT YOU DO:
1. Run the full pytest test suite with run_all_tests()
2. If tests fail, read the failure output carefully
3. Use run_specific_test() to isolate a failing test
4. Write standalone exploit scripts for manual verification
5. Run mcp-scan for scanner compatibility checks
6. Report PASS/FAIL for each challenge with evidence

PYTEST TEST LOCATIONS:
- tests/test_beginner.py       — BEGINNER-001 through BEGINNER-004
- tests/test_intermediate.py   — INTERMEDIATE-001 through INTERMEDIATE-004
- tests/test_advanced.py       — ADVANCED-001 through ADVANCED-004
- tests/test_sandbox.py        — Sandbox mode behavior
- tests/test_ctf_system.py     — CTF helper tool system (YAML + flags)
- tests/test_resources.py      — MCP sensitive resources
- tests/test_modules.py        — VulnerabilityModule contract
- tests/test_config.py         — Safety gate + env vars
- tests/test_flags.py          — Flag registry

A challenge PASSES if its pytest test class is all green.
A challenge FAILS if any test in its class is red.

SCANNER COMPATIBILITY:
- mcp-scan must find: prompt injection, tool poisoning, cross-origin issues
- Only run scanner tests if mcp-scan is installed

DO NOT modify production source code to make tests pass — that is the debugging agent's job."""

    @property
    def tools(self) -> list[dict]:
        return [
            {
                "name": "run_all_tests",
                "description": "Run the complete pytest test suite and return results",
                "input_schema": {
                    "type": "object",
                    "properties": {
                        "extra_args": {
                            "type": "array",
                            "items": {"type": "string"},
                            "description": "Extra pytest arguments e.g. ['-x', '--tb=long']",
                        }
                    }
                }
            },
            {
                "name": "run_specific_test",
                "description": "Run a specific test file or test class",
                "input_schema": {
                    "type": "object",
                    "properties": {
                        "test_path": {
                            "type": "string",
                            "description": "e.g. 'tests/test_beginner.py::TestBEGINNER002' or 'tests/test_beginner.py'"
                        },
                        "verbose": {"type": "boolean", "default": True},
                    },
                    "required": ["test_path"]
                }
            },
            {
                "name": "read_file",
                "description": "Read challenge YAML, test file, or source code",
                "input_schema": {
                    "type": "object",
                    "properties": {
                        "path": {"type": "string"},
                        "start_line": {"type": "integer"},
                        "end_line": {"type": "integer"},
                    },
                    "required": ["path"]
                }
            },
            {
                "name": "write_exploit",
                "description": "Write a standalone exploit script for a challenge",
                "input_schema": {
                    "type": "object",
                    "properties": {
                        "challenge_id": {"type": "string"},
                        "script_content": {"type": "string"}
                    },
                    "required": ["challenge_id", "script_content"]
                }
            },
            {
                "name": "run_exploit",
                "description": "Run a standalone exploit script",
                "input_schema": {
                    "type": "object",
                    "properties": {
                        "challenge_id": {"type": "string"},
                        "timeout": {"type": "integer", "default": 30}
                    },
                    "required": ["challenge_id"]
                }
            },
            {
                "name": "check_flag",
                "description": "Check if a flag appears in exploit output",
                "input_schema": {
                    "type": "object",
                    "properties": {
                        "challenge_id": {"type": "string"},
                        "output": {"type": "string"}
                    },
                    "required": ["challenge_id", "output"]
                }
            },
            {
                "name": "run_mcp_scan",
                "description": "Run mcp-scan against the server (must be running in SSE mode)",
                "input_schema": {
                    "type": "object",
                    "properties": {
                        "server_url": {"type": "string", "default": "http://localhost:8000/sse"}
                    }
                }
            },
        ]

    async def handle_tool_call(self, tool_name: str, tool_input: dict) -> str:
        if tool_name == "run_all_tests":
            return self._run_all_tests(tool_input.get("extra_args", []))
        elif tool_name == "run_specific_test":
            return self._run_specific_test(tool_input["test_path"], tool_input.get("verbose", True))
        elif tool_name == "read_file":
            return self._read_file(tool_input["path"], tool_input.get("start_line"), tool_input.get("end_line"))
        elif tool_name == "write_exploit":
            return self._write_exploit(tool_input["challenge_id"], tool_input["script_content"])
        elif tool_name == "run_exploit":
            return self._run_exploit(tool_input["challenge_id"], tool_input.get("timeout", 30))
        elif tool_name == "check_flag":
            return self._check_flag(tool_input["challenge_id"], tool_input["output"])
        elif tool_name == "run_mcp_scan":
            return self._run_mcp_scan(tool_input.get("server_url", "http://localhost:8000/sse"))
        else:
            raise ValueError(f"Unknown tool: {tool_name}")

    def _abs(self, path: str) -> str:
        if os.path.isabs(path):
            return path
        return os.path.join(self.work_dir, path)

    def _run_pytest(self, args: list[str], timeout: int = 120) -> str:
        """Core pytest runner shared by run_all_tests and run_specific_test."""
        env = {**os.environ, "MCP_TRAINING_MODE": "true", "MCP_SANDBOX": "true"}
        result = subprocess.run(
            [sys.executable, "-m", "pytest"] + args,
            capture_output=True,
            text=True,
            timeout=timeout,
            cwd=self.work_dir,
            env=env,
        )
        return (
            f"Exit code: {result.returncode}\n"
            f"{'PASSED' if result.returncode == 0 else 'FAILED'}\n\n"
            f"{result.stdout}\n{result.stderr}"
        )

    def _run_all_tests(self, extra_args: list[str]) -> str:
        args = ["tests/", "-v", "--tb=short"] + extra_args
        return self._run_pytest(args, timeout=180)

    def _run_specific_test(self, test_path: str, verbose: bool) -> str:
        args = [test_path, "--tb=long"]
        if verbose:
            args.append("-v")
        return self._run_pytest(args)

    def _read_file(self, path: str, start: int = None, end: int = None) -> str:
        abs_path = self._abs(path)
        if not os.path.exists(abs_path):
            return f"ERROR: File not found: {path}"
        with open(abs_path, "r", encoding="utf-8") as f:
            lines = f.readlines()
        if start or end:
            s = (start or 1) - 1
            e = end or len(lines)
            lines = lines[s:e]
            return f"[Lines {s+1}–{e}]\n" + "".join(lines)
        return "".join(lines)

    def _write_exploit(self, challenge_id: str, script_content: str) -> str:
        exploits_dir = os.path.join(self.work_dir, "tests", "exploits")
        os.makedirs(exploits_dir, exist_ok=True)
        path = os.path.join(exploits_dir, f"exploit_{challenge_id.lower().replace('-', '_')}.py")
        with open(path, "w", encoding="utf-8") as f:
            f.write(script_content)
        return f"Exploit written: {path}"

    def _run_exploit(self, challenge_id: str, timeout: int) -> str:
        script_name = f"exploit_{challenge_id.lower().replace('-', '_')}.py"
        script_path = os.path.join(self.work_dir, "tests", "exploits", script_name)
        if not os.path.exists(script_path):
            return f"ERROR: Exploit script not found: {script_path}"
        env = {**os.environ, "MCP_TRAINING_MODE": "true", "MCP_SANDBOX": "true"}
        result = subprocess.run(
            [sys.executable, script_path],
            capture_output=True,
            text=True,
            timeout=timeout,
            cwd=self.work_dir,
            env=env,
        )
        output = f"=== STDOUT ===\n{result.stdout}\n=== STDERR ===\n{result.stderr}"
        if result.returncode != 0:
            output = f"EXIT CODE: {result.returncode}\n" + output
        return output

    def _check_flag(self, challenge_id: str, output: str) -> str:
        sys.path.insert(0, self.work_dir)
        try:
            from flags.flags import get_flag
            expected = get_flag(challenge_id)
            if expected in output:
                return f"PASS: Flag {expected} found in output"
            return f"FAIL: Expected flag {expected} not found in output"
        except Exception as e:
            return f"ERROR checking flag: {e}"

    def _run_mcp_scan(self, server_url: str) -> str:
        try:
            result = subprocess.run(
                ["mcp-scan", server_url, "--json"],
                capture_output=True,
                text=True,
                timeout=120,
                cwd=self.work_dir,
            )
            return result.stdout or result.stderr or "No output from mcp-scan"
        except FileNotFoundError:
            return "mcp-scan not installed. Install with: pip install mcp-scan"
        except subprocess.TimeoutExpired:
            return "mcp-scan timed out after 120s"
