"""
Test Data Agent

Analyzes vulnerability modules and challenge YAML files to:
1. Identify gaps in test coverage (missing cases, edge cases)
2. Generate additional attack payloads for parametrized tests
3. Verify payload correctness against sandbox detection logic
4. Report which challenges have no tests vs full coverage

Run standalone:
    python agents/test_data_agent.py --analyze    # coverage analysis
    python agents/test_data_agent.py --generate   # generate missing payloads
"""
import asyncio
import json
import os
import subprocess
import sys

from agents.base_agent import AgentResult, BaseAgent


class TestDataAgent(BaseAgent):
    """
    Analyzes the test suite to find coverage gaps and generate missing payloads.

    Unlike the TestingAgent (which runs tests), this agent works at the meta
    level: it reads both the source code and the tests, identifies what attack
    vectors are not covered, and either reports them or generates the missing
    fixture data.
    """

    def __init__(self, event_bus: asyncio.Queue, work_dir: str = None):
        super().__init__("TEST_DATA", event_bus, work_dir)

    @property
    def system_prompt(self) -> str:
        return """You are a security test coverage analyst for a deliberately vulnerable MCP server.

YOUR JOB:
1. Read all vulnerability modules in vulnerabilities/ to understand what attack vectors exist
2. Read tests/fixtures/payloads.py to see what payloads are already defined
3. Read test files in tests/ to see what cases are already covered
4. Identify GAPS: attack vectors in source code not covered by any test
5. Generate missing payloads and test cases to fill those gaps
6. Write missing payloads to tests/fixtures/payloads.py

WHAT MAKES A GOOD PAYLOAD:
- Covers a real attack variant, not a duplicate of an existing one
- Uses a technique documented in CVEs or published research
- Works in sandbox mode (triggers the flag without real execution)
- Is clearly labeled with what it tests

COVERAGE GAPS TO LOOK FOR:
- Edge cases: empty input, very long input, unicode in input
- Injection variants: different shell operators, different SQL keywords
- Path traversal: null bytes, double encoding, URL encoding
- Template injection: filter bypass patterns
- Pickle: different __reduce__ patterns

WHAT YOU MUST NOT DO:
- Generate payloads that would work outside the sandbox (no real-world exploits)
- Add tests for features that don't exist yet (roadmap items)
- Modify source vulnerability code

OUTPUT FORMAT:
Produce a JSON coverage report:
{
  "covered": ["BEGINNER-001", ...],
  "gaps": [
    {
      "challenge_id": "BEGINNER-002",
      "missing_case": "newline injection \\n",
      "suggested_payload": "echo hello\\nwhoami",
      "rationale": "Shell treats newline as command separator on some systems"
    }
  ],
  "new_payloads_added": ["path_null_byte", "sql_stacked_queries", ...]
}"""

    @property
    def tools(self) -> list[dict]:
        return [
            {
                "name": "read_file",
                "description": "Read a source or test file",
                "input_schema": {
                    "type": "object",
                    "properties": {
                        "path": {"type": "string"},
                        "start_line": {"type": "integer"},
                        "end_line": {"type": "integer"},
                    },
                    "required": ["path"],
                }
            },
            {
                "name": "list_files",
                "description": "List files in a directory",
                "input_schema": {
                    "type": "object",
                    "properties": {
                        "directory": {"type": "string"},
                        "pattern": {"type": "string", "description": "glob pattern, e.g. '*.py'"},
                    },
                    "required": ["directory"],
                }
            },
            {
                "name": "run_coverage_check",
                "description": "Run pytest with --collect-only to see what tests exist",
                "input_schema": {
                    "type": "object",
                    "properties": {
                        "test_path": {"type": "string", "default": "tests/"},
                    }
                }
            },
            {
                "name": "append_to_payloads",
                "description": "Add new payload constants to tests/fixtures/payloads.py",
                "input_schema": {
                    "type": "object",
                    "properties": {
                        "section_comment": {"type": "string", "description": "Section header comment"},
                        "python_code": {"type": "string", "description": "Valid Python code to append"},
                    },
                    "required": ["section_comment", "python_code"],
                }
            },
            {
                "name": "write_coverage_report",
                "description": "Write the coverage analysis JSON to tests/coverage_gaps.json",
                "input_schema": {
                    "type": "object",
                    "properties": {
                        "report": {"type": "object", "description": "Coverage report dict"},
                    },
                    "required": ["report"],
                }
            },
            {
                "name": "run_syntax_check",
                "description": "Verify Python syntax of a file after modifications",
                "input_schema": {
                    "type": "object",
                    "properties": {"path": {"type": "string"}},
                    "required": ["path"],
                }
            },
        ]

    async def handle_tool_call(self, tool_name: str, tool_input: dict) -> str:
        if tool_name == "read_file":
            return self._read_file(
                tool_input["path"],
                tool_input.get("start_line"),
                tool_input.get("end_line"),
            )
        elif tool_name == "list_files":
            return self._list_files(tool_input["directory"], tool_input.get("pattern"))
        elif tool_name == "run_coverage_check":
            return self._run_coverage_check(tool_input.get("test_path", "tests/"))
        elif tool_name == "append_to_payloads":
            return self._append_to_payloads(
                tool_input["section_comment"],
                tool_input["python_code"],
            )
        elif tool_name == "write_coverage_report":
            return self._write_coverage_report(tool_input["report"])
        elif tool_name == "run_syntax_check":
            return self._run_syntax_check(tool_input["path"])
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
            s = (start or 1) - 1
            e = end or len(lines)
            lines = lines[s:e]
            return f"[Lines {s+1}–{e}]\n" + "".join(lines)
        return "".join(lines)

    def _list_files(self, directory: str, pattern: str = None) -> str:
        abs_dir = self._abs(directory)
        if not os.path.isdir(abs_dir):
            return f"ERROR: Directory not found: {directory}"
        import glob as _glob
        if pattern:
            files = _glob.glob(os.path.join(abs_dir, "**", pattern), recursive=True)
        else:
            files = []
            for root, dirs, fnames in os.walk(abs_dir):
                dirs[:] = [d for d in dirs if not d.startswith(".")]
                for fn in fnames:
                    files.append(os.path.join(root, fn))
        rel_files = [os.path.relpath(f, self.work_dir) for f in sorted(files)]
        return "\n".join(rel_files) if rel_files else "(empty)"

    def _run_coverage_check(self, test_path: str) -> str:
        result = subprocess.run(
            [sys.executable, "-m", "pytest", test_path, "--collect-only", "-q"],
            capture_output=True,
            text=True,
            cwd=self.work_dir,
            env={**os.environ, "MCP_TRAINING_MODE": "true", "MCP_SANDBOX": "true"},
            timeout=60,
        )
        return result.stdout + result.stderr

    def _append_to_payloads(self, section_comment: str, python_code: str) -> str:
        payloads_path = os.path.join(self.work_dir, "tests", "fixtures", "payloads.py")
        if not os.path.exists(payloads_path):
            return f"ERROR: payloads.py not found at {payloads_path}"
        with open(payloads_path, "r", encoding="utf-8") as f:
            existing = f.read()
        # Check for duplicate constant names
        import ast
        try:
            tree = ast.parse(python_code)
            new_names = {node.targets[0].id for node in ast.walk(tree)
                         if isinstance(node, ast.Assign) and node.targets}
            for name in new_names:
                if name in existing:
                    return f"WARNING: Constant {name!r} already exists in payloads.py — skipping"
        except SyntaxError as e:
            return f"ERROR: Syntax error in new code: {e}"

        with open(payloads_path, "a", encoding="utf-8") as f:
            f.write(f"\n# ── {section_comment} {'─' * max(0, 60 - len(section_comment))}\n\n")
            f.write(python_code)
            f.write("\n")
        return f"Appended to payloads.py: {section_comment}"

    def _write_coverage_report(self, report: dict) -> str:
        out_path = os.path.join(self.work_dir, "tests", "coverage_gaps.json")
        with open(out_path, "w", encoding="utf-8") as f:
            json.dump(report, f, indent=2)
        return f"Coverage report written: {out_path}"

    def _run_syntax_check(self, path: str) -> str:
        import ast
        abs_path = self._abs(path)
        try:
            with open(abs_path, "r") as f:
                ast.parse(f.read())
            return f"Syntax OK: {path}"
        except SyntaxError as e:
            return f"Syntax ERROR in {path}: {e}"


async def run_analysis(work_dir: str = None) -> AgentResult:
    """Run the test data agent standalone."""
    bus: asyncio.Queue = asyncio.Queue()
    agent = TestDataAgent(bus, work_dir)

    async def drain():
        while True:
            try:
                event = await asyncio.wait_for(bus.get(), timeout=0.1)
                print(f"[{event.agent}] {event.event}: {event.data.get('message', event.data.get('tool', ''))}")
            except asyncio.TimeoutError:
                pass

    drain_task = asyncio.create_task(drain())
    result = await agent.run_task(
        "Analyze test coverage gaps in the test suite. "
        "Read all vulnerability modules, all test files, and the payloads fixture. "
        "Identify any attack vectors without test coverage. "
        "Add missing payloads to tests/fixtures/payloads.py. "
        "Write a JSON coverage report to tests/coverage_gaps.json."
    )
    drain_task.cancel()
    return result


if __name__ == "__main__":
    import argparse

    parser = argparse.ArgumentParser(description="Test Data Agent — coverage analysis and payload generation")
    parser.add_argument("--analyze", action="store_true", help="Run coverage analysis only")
    parser.add_argument("--generate", action="store_true", help="Analyze and generate missing payloads")
    parser.add_argument("--work-dir", type=str, default=None)
    args = parser.parse_args()

    if args.analyze or args.generate:
        result = asyncio.run(run_analysis(args.work_dir))
        print(f"\nResult: {'SUCCESS' if result.success else 'FAILED'}")
        print(result.output)
    else:
        parser.print_help()
