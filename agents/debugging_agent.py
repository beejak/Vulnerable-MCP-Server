"""
Debugging Agent

Reads test output and error logs, traces failures to root cause,
and applies minimal targeted fixes. Does not rewrite working code.
"""
import ast
import asyncio
import json
import os
import re
import subprocess
import sys

from agents.base_agent import BaseAgent


class DebuggingAgent(BaseAgent):

    def __init__(self, event_bus: asyncio.Queue, work_dir: str = None):
        super().__init__("DEBUGGING", event_bus, work_dir)

    @property
    def system_prompt(self) -> str:
        return """You are a debugging specialist for a Python security training server.
You receive failing test output and fix the root cause with minimal changes.

RULES:
- Read the error output carefully before touching any code
- Fix the root cause, not just the symptom
- Make the smallest possible change that fixes the issue
- Do not refactor working code while fixing a bug
- Do not add new dependencies
- After patching, verify the fix with run_failing_tests — it must go green
- If the error is in test code (not source), fix the test
- If the issue is a missing import, add only the import — nothing else
- Always explain: what was wrong, what you changed, why it now works

DEBUGGING PROCESS:
1. run_failing_tests() — get the current failure list
2. parse_pytest_failures() — extract structured failure info
3. read_file() on the failing file at the failing line
4. Understand: wrong assertion? wrong tool output? import error? fixture missing?
5. apply_patch() — smallest change that fixes the issue
6. check_syntax() — verify file is still valid Python
7. run_failing_tests() — confirm the test passes now

COMMON FAILURES IN THIS PROJECT:
- ToolCapture.call() raises KeyError → tool not registered → check module's register() method
- assert_flag() fails → tool not returning FLAG{} → check sandbox detection logic
- assert_no_flag() fails → tool returning flag for safe input → fix detection pattern
- ImportError → check sys.path setup in conftest.py
- asyncio warnings → mark test as async or use pytest-asyncio"""

    @property
    def tools(self) -> list[dict]:
        return [
            {
                "name": "run_failing_tests",
                "description": "Run pytest and return only failing tests with error details",
                "input_schema": {
                    "type": "object",
                    "properties": {
                        "test_path": {"type": "string", "default": "tests/"},
                        "extra_args": {"type": "array", "items": {"type": "string"}},
                    }
                }
            },
            {
                "name": "parse_pytest_failures",
                "description": "Parse pytest output into structured failure list",
                "input_schema": {
                    "type": "object",
                    "properties": {
                        "pytest_output": {"type": "string"},
                    },
                    "required": ["pytest_output"]
                }
            },
            {
                "name": "read_file",
                "description": "Read a file to understand the error context",
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
                "name": "apply_patch",
                "description": "Apply a targeted string replacement to a file",
                "input_schema": {
                    "type": "object",
                    "properties": {
                        "path": {"type": "string"},
                        "old_string": {"type": "string"},
                        "new_string": {"type": "string"},
                    },
                    "required": ["path", "old_string", "new_string"]
                }
            },
            {
                "name": "write_file",
                "description": "Write a complete fixed version of a file",
                "input_schema": {
                    "type": "object",
                    "properties": {
                        "path": {"type": "string"},
                        "content": {"type": "string"},
                    },
                    "required": ["path", "content"]
                }
            },
            {
                "name": "check_syntax",
                "description": "Verify Python syntax is valid after a patch",
                "input_schema": {
                    "type": "object",
                    "properties": {"path": {"type": "string"}},
                    "required": ["path"]
                }
            },
            {
                "name": "run_import_check",
                "description": "Try to import a module to verify it loads cleanly",
                "input_schema": {
                    "type": "object",
                    "properties": {
                        "module_path": {"type": "string", "description": "e.g. 'vulnerabilities.auth'"}
                    },
                    "required": ["module_path"]
                }
            },
        ]

    async def handle_tool_call(self, tool_name: str, tool_input: dict) -> str:
        if tool_name == "run_failing_tests":
            return self._run_failing_tests(
                tool_input.get("test_path", "tests/"),
                tool_input.get("extra_args", []),
            )
        elif tool_name == "parse_pytest_failures":
            return self._parse_pytest_failures(tool_input["pytest_output"])
        elif tool_name == "read_file":
            return self._read_file(tool_input["path"], tool_input.get("start_line"), tool_input.get("end_line"))
        elif tool_name == "apply_patch":
            return self._apply_patch(tool_input["path"], tool_input["old_string"], tool_input["new_string"])
        elif tool_name == "write_file":
            return self._write_file(tool_input["path"], tool_input["content"])
        elif tool_name == "check_syntax":
            return self._check_syntax(tool_input["path"])
        elif tool_name == "run_import_check":
            return self._run_import_check(tool_input["module_path"])
        else:
            raise ValueError(f"Unknown tool: {tool_name}")

    def _abs(self, path: str) -> str:
        if os.path.isabs(path):
            return path
        return os.path.join(self.work_dir, path)

    def _run_failing_tests(self, test_path: str, extra_args: list) -> str:
        env = {**os.environ, "MCP_TRAINING_MODE": "true", "MCP_SANDBOX": "true"}
        result = subprocess.run(
            [sys.executable, "-m", "pytest", test_path, "--tb=short", "-q"] + extra_args,
            capture_output=True,
            text=True,
            timeout=180,
            cwd=self.work_dir,
            env=env,
        )
        return (
            f"Exit code: {result.returncode}\n"
            f"{'ALL PASSING' if result.returncode == 0 else 'FAILURES DETECTED'}\n\n"
            f"{result.stdout}\n{result.stderr}"
        )

    def _parse_pytest_failures(self, pytest_output: str) -> str:
        """Extract structured failure info from pytest output."""
        failures = []
        # Match: FAILED tests/test_foo.py::TestClass::test_name - AssertionError: ...
        pattern = re.compile(r"FAILED\s+(tests/\S+)\s+-\s+(.*)")
        for match in pattern.finditer(pytest_output):
            test_id, error = match.groups()
            failures.append({"test": test_id, "error": error.strip()})

        # Also catch ERROR entries
        error_pattern = re.compile(r"ERROR\s+(tests/\S+)\s+-\s+(.*)")
        for match in error_pattern.finditer(pytest_output):
            test_id, error = match.groups()
            failures.append({"test": test_id, "type": "ERROR", "error": error.strip()})

        if not failures:
            if "passed" in pytest_output.lower() and "failed" not in pytest_output.lower():
                return json.dumps({"status": "ALL_PASSING", "failures": []}, indent=2)
            return json.dumps({"status": "UNKNOWN", "raw_snippet": pytest_output[:500]}, indent=2)

        return json.dumps({"status": "FAILURES", "count": len(failures), "failures": failures}, indent=2)

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

    def _apply_patch(self, path: str, old_string: str, new_string: str) -> str:
        abs_path = self._abs(path)
        with open(abs_path, "r", encoding="utf-8") as f:
            content = f.read()
        if old_string not in content:
            return f"ERROR: old_string not found in {path}."
        count = content.count(old_string)
        if count > 1:
            return f"ERROR: old_string appears {count} times in {path}. Be more specific."
        with open(abs_path, "w", encoding="utf-8") as f:
            f.write(content.replace(old_string, new_string, 1))
        return f"Patch applied: {path}"

    def _write_file(self, path: str, content: str) -> str:
        abs_path = self._abs(path)
        os.makedirs(os.path.dirname(abs_path), exist_ok=True)
        with open(abs_path, "w", encoding="utf-8") as f:
            f.write(content)
        return f"Written: {path}"

    def _check_syntax(self, path: str) -> str:
        abs_path = self._abs(path)
        try:
            with open(abs_path, "r") as f:
                ast.parse(f.read())
            return f"Syntax OK: {path}"
        except SyntaxError as e:
            return f"Syntax ERROR: {e}"

    def _run_import_check(self, module_path: str) -> str:
        result = subprocess.run(
            [sys.executable, "-c",
             f"import sys; sys.path.insert(0, '.'); import {module_path}; print('OK')"],
            capture_output=True,
            text=True,
            cwd=self.work_dir,
            timeout=15,
            env={**os.environ, "MCP_TRAINING_MODE": "true"},
        )
        if result.returncode == 0:
            return f"Import OK: {module_path}"
        return f"Import FAILED:\n{result.stderr}"
