"""
Debugging Agent

Reads test output and error logs, traces failures to root cause,
and applies minimal targeted fixes. Does not rewrite working code.
"""
import asyncio
import os
import subprocess
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
- After patching, verify the fix with check_syntax
- If the error is in test code (not source), fix the test
- If the issue is a missing import, add only the import — nothing else
- Always explain what was wrong and what you changed in your response

DEBUGGING APPROACH:
1. Read the error message — identify file, line number, error type
2. Read the failing file around the error line
3. Understand why it fails (missing import, wrong type, missing method, etc.)
4. Apply the minimal fix
5. Verify syntax is clean
6. Summarize: what was wrong, what you changed, why it works now"""

    @property
    def tools(self) -> list[dict]:
        return [
            {
                "name": "read_file",
                "description": "Read a file to understand the error context",
                "input_schema": {
                    "type": "object",
                    "properties": {
                        "path": {"type": "string"},
                        "start_line": {"type": "integer", "description": "Start reading from this line (1-indexed)"},
                        "end_line": {"type": "integer", "description": "Stop reading at this line"}
                    },
                    "required": ["path"]
                }
            },
            {
                "name": "write_file",
                "description": "Write a fixed version of a file",
                "input_schema": {
                    "type": "object",
                    "properties": {
                        "path": {"type": "string"},
                        "content": {"type": "string"}
                    },
                    "required": ["path", "content"]
                }
            },
            {
                "name": "apply_patch",
                "description": "Apply a targeted line replacement to a file (less risky than rewriting)",
                "input_schema": {
                    "type": "object",
                    "properties": {
                        "path": {"type": "string"},
                        "old_string": {"type": "string", "description": "Exact string to replace (must be unique in file)"},
                        "new_string": {"type": "string", "description": "Replacement string"}
                    },
                    "required": ["path", "old_string", "new_string"]
                }
            },
            {
                "name": "check_syntax",
                "description": "Verify Python syntax after patch",
                "input_schema": {
                    "type": "object",
                    "properties": {"path": {"type": "string"}},
                    "required": ["path"]
                }
            },
            {
                "name": "run_import_check",
                "description": "Try to import a Python module to verify it loads without errors",
                "input_schema": {
                    "type": "object",
                    "properties": {"module_path": {"type": "string", "description": "e.g. 'vulnerabilities.oauth'"}},
                    "required": ["module_path"]
                }
            }
        ]

    async def handle_tool_call(self, tool_name: str, tool_input: dict) -> str:
        if tool_name == "read_file":
            return self._read_file(
                tool_input["path"],
                tool_input.get("start_line"),
                tool_input.get("end_line")
            )
        elif tool_name == "write_file":
            return self._write_file(tool_input["path"], tool_input["content"])
        elif tool_name == "apply_patch":
            return self._apply_patch(tool_input["path"], tool_input["old_string"], tool_input["new_string"])
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

    def _read_file(self, path: str, start: int = None, end: int = None) -> str:
        abs_path = self._abs(path)
        if not os.path.exists(abs_path):
            return f"ERROR: File not found: {path}"
        with open(abs_path, "r", encoding="utf-8") as f:
            lines = f.readlines()
        if start or end:
            start = (start or 1) - 1
            end = end or len(lines)
            lines = lines[start:end]
            return f"[Lines {start+1}-{end}]\n" + "".join(lines)
        return "".join(lines)

    def _write_file(self, path: str, content: str) -> str:
        abs_path = self._abs(path)
        os.makedirs(os.path.dirname(abs_path), exist_ok=True)
        with open(abs_path, "w", encoding="utf-8") as f:
            f.write(content)
        return f"Written: {path}"

    def _apply_patch(self, path: str, old_string: str, new_string: str) -> str:
        abs_path = self._abs(path)
        with open(abs_path, "r", encoding="utf-8") as f:
            content = f.read()
        if old_string not in content:
            return f"ERROR: old_string not found in {path}. Cannot apply patch."
        count = content.count(old_string)
        if count > 1:
            return f"ERROR: old_string appears {count} times in {path}. Make it more specific."
        new_content = content.replace(old_string, new_string, 1)
        with open(abs_path, "w", encoding="utf-8") as f:
            f.write(new_content)
        return f"Patch applied to {path}"

    def _check_syntax(self, path: str) -> str:
        import ast
        abs_path = self._abs(path)
        try:
            with open(abs_path, "r") as f:
                ast.parse(f.read())
            return f"Syntax OK: {path}"
        except SyntaxError as e:
            return f"Syntax ERROR: {e}"

    def _run_import_check(self, module_path: str) -> str:
        result = subprocess.run(
            ["python", "-c", f"import sys; sys.path.insert(0, '.'); import {module_path}; print('OK')"],
            capture_output=True, text=True, cwd=self.work_dir, timeout=15
        )
        if result.returncode == 0:
            return f"Import OK: {module_path}"
        return f"Import FAILED: {result.stderr}"
