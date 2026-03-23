"""
Coding Agent

Writes and modifies vulnerability modules following the project's established
patterns. Reads PRD.md and SCOPE.md for requirements before writing code.
Uses read_file, write_file, and list_files tools.
"""
import asyncio
import os
from agents.base_agent import BaseAgent, AgentResult


class CodingAgent(BaseAgent):

    def __init__(self, event_bus: asyncio.Queue, work_dir: str = None):
        super().__init__("CODING", event_bus, work_dir)

    @property
    def system_prompt(self) -> str:
        return """You are a security researcher writing deliberately vulnerable Python code
for a security training server. Your job is to implement vulnerability modules
following the project's exact patterns.

RULES:
- Every vulnerability module extends VulnerabilityModule from vulnerabilities/base.py
- Every module must have a register() method that attaches tools with @app.tool()
- Every vulnerable function must have a comment marking the exact vulnerable line
- Sandbox mode (config.sandbox_mode) must be respected: simulate when True, execute when False
- Every tool must return the challenge flag when the vulnerability is triggered in sandbox mode
- Use get_flag(challenge_id) from flags.flags for all flags
- Follow existing code style exactly (read an existing module first)
- No new dependencies unless explicitly required
- All fake credentials must start with 'sk-fake', 'AKIAFAKE', etc.

BEFORE WRITING:
1. Read docs/PRD.md to understand requirements
2. Read docs/SCOPE.md to confirm what's in scope
3. Read an existing vulnerability module (e.g. vulnerabilities/injection.py) for patterns
4. Read vulnerabilities/base.py for the base class interface

WHEN WRITING:
- Write complete, working code — no stubs, no TODOs (except intentional vulnerability TODOs)
- Add the module to vulnerabilities/__init__.py ALL_MODULES list
- Add the flag to flags/flags.py
- Write the challenge YAML definition"""

    @property
    def tools(self) -> list[dict]:
        return [
            {
                "name": "read_file",
                "description": "Read a file from the project directory",
                "input_schema": {
                    "type": "object",
                    "properties": {
                        "path": {"type": "string", "description": "Relative path from project root"}
                    },
                    "required": ["path"]
                }
            },
            {
                "name": "write_file",
                "description": "Write content to a file (creates or overwrites)",
                "input_schema": {
                    "type": "object",
                    "properties": {
                        "path": {"type": "string", "description": "Relative path from project root"},
                        "content": {"type": "string", "description": "File content to write"}
                    },
                    "required": ["path", "content"]
                }
            },
            {
                "name": "list_files",
                "description": "List files in a directory",
                "input_schema": {
                    "type": "object",
                    "properties": {
                        "directory": {"type": "string", "description": "Relative path from project root", "default": "."}
                    }
                }
            },
            {
                "name": "check_syntax",
                "description": "Check Python file for syntax errors without executing it",
                "input_schema": {
                    "type": "object",
                    "properties": {
                        "path": {"type": "string", "description": "Relative path to Python file"}
                    },
                    "required": ["path"]
                }
            }
        ]

    async def handle_tool_call(self, tool_name: str, tool_input: dict) -> str:
        if tool_name == "read_file":
            return self._read_file(tool_input["path"])
        elif tool_name == "write_file":
            return self._write_file(tool_input["path"], tool_input["content"])
        elif tool_name == "list_files":
            return self._list_files(tool_input.get("directory", "."))
        elif tool_name == "check_syntax":
            return self._check_syntax(tool_input["path"])
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

    def _write_file(self, path: str, content: str) -> str:
        abs_path = self._abs(path)
        os.makedirs(os.path.dirname(abs_path), exist_ok=True)
        with open(abs_path, "w", encoding="utf-8") as f:
            f.write(content)
        return f"Written: {path} ({len(content)} bytes)"

    def _list_files(self, directory: str) -> str:
        abs_dir = self._abs(directory)
        if not os.path.exists(abs_dir):
            return f"ERROR: Directory not found: {directory}"
        files = []
        for root, dirs, filenames in os.walk(abs_dir):
            # Skip hidden dirs and __pycache__
            dirs[:] = [d for d in dirs if not d.startswith(".") and d != "__pycache__"]
            for fname in filenames:
                if fname.endswith(".pyc"):
                    continue
                rel = os.path.relpath(os.path.join(root, fname), self.work_dir)
                files.append(rel)
        return "\n".join(sorted(files))

    def _check_syntax(self, path: str) -> str:
        import ast
        abs_path = self._abs(path)
        try:
            with open(abs_path, "r") as f:
                source = f.read()
            ast.parse(source)
            return f"Syntax OK: {path}"
        except SyntaxError as e:
            return f"Syntax ERROR in {path}: {e}"
        except FileNotFoundError:
            return f"ERROR: File not found: {path}"
