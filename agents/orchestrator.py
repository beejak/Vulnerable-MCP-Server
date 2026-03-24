"""
Orchestrator Agent

Governs all other agents. Breaks high-level tasks into sub-tasks,
assigns them to the right agent, monitors progress, handles failures,
and reports final status.
"""
import asyncio
import os
from dataclasses import dataclass
from typing import Literal

from agents.base_agent import AgentResult, BaseAgent
from agents.coding_agent import CodingAgent
from agents.debugging_agent import DebuggingAgent
from agents.docs_agent import DocsAgent
from agents.testing_agent import TestingAgent

AgentType = Literal["coding", "debugging", "testing", "docs"]


@dataclass
class SubTask:
    id: str
    agent: AgentType
    task: str
    context: str = ""
    depends_on: list[str] = None  # sub-task IDs that must complete first
    result: AgentResult = None
    status: str = "pending"  # pending | running | done | failed


class OrchestratorAgent(BaseAgent):
    """
    Orchestrates task execution across specialized agents.

    Usage:
        event_bus = asyncio.Queue()
        orch = OrchestratorAgent(event_bus, work_dir="/path/to/project")
        result = await orch.run_task("Implement OAUTH-001 challenge")
    """

    def __init__(self, event_bus: asyncio.Queue, work_dir: str = None):
        super().__init__("ORCHESTRATOR", event_bus, work_dir)
        self._agents = {
            "coding": CodingAgent(event_bus, work_dir),
            "debugging": DebuggingAgent(event_bus, work_dir),
            "testing": TestingAgent(event_bus, work_dir),
            "docs": DocsAgent(event_bus, work_dir),
        }

    @property
    def system_prompt(self) -> str:
        return """You are an orchestrator managing a multi-agent software development system
for a security training server. You break tasks into sub-tasks and assign them to agents.

AGENTS AVAILABLE:
- coding: Writes Python vulnerability modules and supporting code
- debugging: Diagnoses and fixes test failures with minimal changes
- testing: Runs exploits, verifies flags, checks scanner compatibility
- docs: Updates YAML challenge definitions and README documentation

TASK DECOMPOSITION RULES:
1. coding tasks always come before testing tasks (can't test unwritten code)
2. debugging tasks come after testing tasks (need failure output to debug)
3. docs tasks come last (docs reflect what was actually built)
4. Each sub-task must be self-contained — include all context the agent needs
5. If testing fails, assign a debugging task, then re-assign the same testing task
6. Max 3 debugging cycles per challenge before escalating to user

OUTPUT FORMAT:
Return a JSON list of sub-tasks in execution order:
[
  {"id": "1", "agent": "coding", "task": "...", "context": "..."},
  {"id": "2", "agent": "testing", "task": "...", "depends_on": ["1"]},
  {"id": "3", "agent": "docs", "task": "...", "depends_on": ["2"]}
]"""

    @property
    def tools(self) -> list[dict]:
        return [
            {
                "name": "read_file",
                "description": "Read a project file for context",
                "input_schema": {
                    "type": "object",
                    "properties": {"path": {"type": "string"}},
                    "required": ["path"]
                }
            },
            {
                "name": "list_files",
                "description": "List project files",
                "input_schema": {
                    "type": "object",
                    "properties": {"directory": {"type": "string", "default": "."}}
                }
            }
        ]

    async def handle_tool_call(self, tool_name: str, tool_input: dict) -> str:
        if tool_name == "read_file":
            path = os.path.join(self.work_dir, tool_input["path"])
            if not os.path.exists(path):
                return f"File not found: {path}"
            with open(path) as f:
                return f.read()
        elif tool_name == "list_files":
            directory = os.path.join(self.work_dir, tool_input.get("directory", "."))
            files = []
            for root, dirs, filenames in os.walk(directory):
                dirs[:] = [d for d in dirs if not d.startswith(".") and d != "__pycache__"]
                for fname in filenames:
                    if not fname.endswith(".pyc"):
                        files.append(os.path.relpath(os.path.join(root, fname), self.work_dir))
            return "\n".join(sorted(files))
        raise ValueError(f"Unknown tool: {tool_name}")

    async def run_task(self, task: str, context: str = "") -> AgentResult:
        """
        Main entry point. Decomposes task, executes sub-tasks, handles failures.
        """
        await self.emit("STARTED", {"task": task[:100]})

        # Step 1: Plan the sub-tasks using Claude
        plan = await self._plan_subtasks(task, context)
        if not plan:
            await self.emit("FAILED", {"task": task, "error": "Could not decompose task"})
            return AgentResult(success=False, output="", error="Task decomposition failed")

        await self.emit("THINKING", {"subtask_count": len(plan), "tasks": [s.id for s in plan]})

        # Step 2: Execute sub-tasks in dependency order
        completed: dict[str, SubTask] = {}
        all_files_modified = []

        for subtask in plan:
            # Wait for dependencies
            if subtask.depends_on:
                for dep_id in subtask.depends_on:
                    if dep_id not in completed or completed[dep_id].status != "done":
                        await self.emit("THINKING", {
                            "message": f"Skipping {subtask.id} — dependency {dep_id} not complete"
                        })
                        subtask.status = "skipped"
                        continue

            # Build context from completed dependencies
            dep_context = ""
            if subtask.depends_on:
                for dep_id in (subtask.depends_on or []):
                    if dep_id in completed and completed[dep_id].result:
                        dep_context += f"\nPrevious step ({dep_id}) output:\n{completed[dep_id].result.output[:500]}\n"

            full_context = subtask.context + dep_context

            subtask.status = "running"
            await self.emit("TOOL_CALL", {
                "tool": f"assign_to_{subtask.agent}",
                "input_preview": subtask.task[:100]
            })

            agent = self._agents[subtask.agent]
            result = await agent.run_task(subtask.task, full_context)
            subtask.result = result

            if result.success:
                subtask.status = "done"
                all_files_modified.extend(result.files_modified)
                await self.emit("TOOL_RESULT", {
                    "tool": f"{subtask.agent}_agent",
                    "success": True,
                    "output_preview": result.output[:200]
                })
            else:
                subtask.status = "failed"
                await self.emit("TOOL_RESULT", {
                    "tool": f"{subtask.agent}_agent",
                    "success": False,
                    "error": result.error
                })

                # Auto-assign debugging if testing fails
                if subtask.agent == "testing" and subtask.status == "failed":
                    debug_result = await self._agents["debugging"].run_task(
                        f"Fix the failure in subtask {subtask.id}",
                        f"Error from testing:\n{result.error}\n\nOutput:\n{result.output}"
                    )
                    if debug_result.success:
                        # Retry the original test
                        retry_result = await agent.run_task(subtask.task, full_context)
                        if retry_result.success:
                            subtask.result = retry_result
                            subtask.status = "done"
                            all_files_modified.extend(retry_result.files_modified)

            completed[subtask.id] = subtask

        # Summarize
        done = [s.id for s in plan if s.status == "done"]
        failed = [s.id for s in plan if s.status == "failed"]
        summary = f"Completed {len(done)}/{len(plan)} sub-tasks. Done: {done}. Failed: {failed}."

        success = len(failed) == 0
        await self.emit("COMPLETED" if success else "FAILED", {
            "task": task[:100],
            "summary": summary,
            "files_modified": all_files_modified,
        })

        return AgentResult(
            success=success,
            output=summary,
            files_modified=all_files_modified,
        )

    async def _plan_subtasks(self, task: str, context: str) -> list[SubTask]:
        """Use Claude to decompose a task into sub-tasks."""
        import json

        planning_task = f"""Break this task into sub-tasks for the agent system:

TASK: {task}

CONTEXT: {context[:500] if context else 'None'}

Return ONLY a JSON array (no markdown, no explanation):
[
  {{"id": "1", "agent": "coding|debugging|testing|docs", "task": "...", "context": "...", "depends_on": []}},
  ...
]"""

        result = await super().run_task(planning_task)
        try:
            # Extract JSON from the response
            text = result.output
            start = text.find("[")
            end = text.rfind("]") + 1
            if start == -1 or end == 0:
                return []
            subtasks_raw = json.loads(text[start:end])
            return [
                SubTask(
                    id=s["id"],
                    agent=s["agent"],
                    task=s["task"],
                    context=s.get("context", ""),
                    depends_on=s.get("depends_on", []),
                )
                for s in subtasks_raw
            ]
        except (json.JSONDecodeError, KeyError):
            return []
