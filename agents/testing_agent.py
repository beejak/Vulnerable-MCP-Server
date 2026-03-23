"""
Testing Agent

Verifies that each vulnerability challenge is actually exploitable.
Runs exploit scripts against the running server, checks that flags
are returned, and validates scanner compatibility.
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
1. Read the challenge YAML to understand what the exploit should be
2. Write a Python exploit script that calls the vulnerable tool with a malicious payload
3. Run the exploit and verify the flag appears in the output
4. Run mcp-scan against the server and verify it finds expected findings
5. Report PASS/FAIL for each challenge with evidence

EXPLOIT APPROACH:
- For each challenge, use the MCP Python SDK to connect and call the tool
- Use server stdin/stdout (stdio transport) for testing
- Parse tool output for the FLAG{...} pattern
- A challenge PASSES if the flag is in the output
- A challenge FAILS if the flag is not in the output or an exception occurs

SCANNER COMPATIBILITY:
- mcp-scan must find: prompt injection, tool poisoning, cross-origin issues
- Report which scanner findings match which challenge IDs

DO NOT:
- Modify production code to make tests pass (that's the debugging agent's job)
- Write tests that hard-code expected output (use flag pattern matching)
- Test anything outside the documented challenge scope"""

    @property
    def tools(self) -> list[dict]:
        return [
            {
                "name": "read_file",
                "description": "Read challenge YAML or source code",
                "input_schema": {
                    "type": "object",
                    "properties": {"path": {"type": "string"}},
                    "required": ["path"]
                }
            },
            {
                "name": "write_exploit",
                "description": "Write an exploit script for a challenge",
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
                "description": "Run an exploit script and capture output",
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
                "description": "Run mcp-scan against the server config and return findings",
                "input_schema": {
                    "type": "object",
                    "properties": {
                        "config_path": {"type": "string", "default": "tests/scanner_compat/mcp_scan_config.json"}
                    }
                }
            }
        ]

    async def handle_tool_call(self, tool_name: str, tool_input: dict) -> str:
        if tool_name == "read_file":
            return self._read_file(tool_input["path"])
        elif tool_name == "write_exploit":
            return self._write_exploit(tool_input["challenge_id"], tool_input["script_content"])
        elif tool_name == "run_exploit":
            return self._run_exploit(tool_input["challenge_id"], tool_input.get("timeout", 30))
        elif tool_name == "check_flag":
            return self._check_flag(tool_input["challenge_id"], tool_input["output"])
        elif tool_name == "run_mcp_scan":
            return self._run_mcp_scan(tool_input.get("config_path"))
        else:
            raise ValueError(f"Unknown tool: {tool_name}")

    def _abs(self, path: str) -> str:
        if os.path.isabs(path):
            return path
        return os.path.join(self.work_dir, path)

    def _read_file(self, path: str) -> str:
        abs_path = self._abs(path)
        if not os.path.exists(abs_path):
            return f"ERROR: File not found: {path}"
        with open(abs_path, "r", encoding="utf-8") as f:
            return f.read()

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

        env = os.environ.copy()
        env["MCP_TRAINING_MODE"] = "true"
        env["MCP_SANDBOX"] = "true"

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
            output = f"PROCESS EXIT CODE: {result.returncode}\n" + output
        return output

    def _check_flag(self, challenge_id: str, output: str) -> str:
        import sys
        sys.path.insert(0, self.work_dir)
        try:
            from flags.flags import get_flag
            expected = get_flag(challenge_id)
            if expected in output:
                return f"PASS: Flag {expected} found in output"
            return f"FAIL: Expected flag {expected} not found in output"
        except Exception as e:
            return f"ERROR checking flag: {e}"

    def _run_mcp_scan(self, config_path: str = None) -> str:
        try:
            result = subprocess.run(
                ["mcp-scan", "--json"],
                capture_output=True, text=True, timeout=120, cwd=self.work_dir
            )
            return result.stdout or result.stderr or "No output from mcp-scan"
        except FileNotFoundError:
            return "mcp-scan not installed. Install with: pip install mcp-scan"
        except subprocess.TimeoutExpired:
            return "mcp-scan timed out after 120s"
