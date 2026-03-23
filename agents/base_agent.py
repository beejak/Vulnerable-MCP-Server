"""
Base agent class with observability.

Every specialized agent inherits from BaseAgent. All interactions with
the Claude API are routed through run_task() which emits structured events
to the shared event bus before/after every operation.
"""
import asyncio
import json
import os
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any

import anthropic


@dataclass
class AgentResult:
    success: bool
    output: str
    error: str = ""
    files_modified: list[str] = field(default_factory=list)
    token_usage: dict = field(default_factory=dict)


@dataclass
class AgentEvent:
    ts: str
    agent: str
    event: str  # STARTED | THINKING | TOOL_CALL | TOOL_RESULT | RETRY | COMPLETED | FAILED
    data: dict

    def to_json(self) -> str:
        return json.dumps({
            "ts": self.ts,
            "agent": self.agent,
            "event": self.event,
            **self.data
        })


class BaseAgent(ABC):
    """
    Abstract base for all agents in the multi-agent build system.

    Subclasses must implement:
    - system_prompt: the agent's role/persona
    - tools: list of tool definitions available to this agent
    - handle_tool_call: executes tool calls and returns results
    """

    MAX_RETRIES = 3
    MAX_TOKENS = 8192

    def __init__(self, name: str, event_bus: asyncio.Queue, work_dir: str = None):
        self.name = name
        self.event_bus = event_bus
        self.work_dir = work_dir or os.path.join(
            os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
        )
        self.client = anthropic.Anthropic(api_key=os.environ.get("ANTHROPIC_API_KEY"))
        self.token_usage = {"input": 0, "output": 0}
        self._task_history: list[dict] = []

    @property
    @abstractmethod
    def system_prompt(self) -> str: ...

    @property
    @abstractmethod
    def tools(self) -> list[dict]: ...

    @abstractmethod
    async def handle_tool_call(self, tool_name: str, tool_input: dict) -> str: ...

    async def emit(self, event_type: str, data: dict) -> None:
        event = AgentEvent(
            ts=datetime.now(timezone.utc).isoformat(),
            agent=self.name,
            event=event_type,
            data=data,
        )
        await self.event_bus.put(event)

    async def run_task(self, task: str, context: str = "") -> AgentResult:
        """
        Run a task using the Claude API with tool use loop.
        Emits observability events throughout.
        """
        await self.emit("STARTED", {"task": task[:100]})

        messages = []
        if context:
            messages.append({"role": "user", "content": f"Context:\n{context}\n\nTask:\n{task}"})
        else:
            messages.append({"role": "user", "content": task})

        files_modified = []

        for attempt in range(1, self.MAX_RETRIES + 1):
            try:
                result = await self._run_agentic_loop(messages, files_modified)
                await self.emit("COMPLETED", {
                    "task": task[:100],
                    "output_preview": result.output[:200],
                    "files_modified": files_modified,
                    "tokens": self.token_usage,
                })
                return result

            except Exception as e:
                error_msg = f"{type(e).__name__}: {e}"
                if attempt < self.MAX_RETRIES:
                    await self.emit("RETRY", {
                        "attempt": attempt,
                        "error": error_msg,
                        "task": task[:100],
                    })
                    # Add error to messages so next attempt has context
                    messages.append({
                        "role": "assistant",
                        "content": f"Previous attempt failed: {error_msg}. Trying again."
                    })
                    messages.append({"role": "user", "content": "Please try again, fixing the error above."})
                else:
                    await self.emit("FAILED", {
                        "task": task[:100],
                        "error": error_msg,
                        "attempts": attempt,
                    })
                    return AgentResult(
                        success=False,
                        output="",
                        error=error_msg,
                        token_usage=self.token_usage,
                    )

        return AgentResult(success=False, output="", error="Max retries exceeded")

    async def _run_agentic_loop(self, messages: list, files_modified: list) -> AgentResult:
        """Core Claude API agentic loop with tool use."""
        final_output = ""

        while True:
            await self.emit("THINKING", {"message_count": len(messages)})

            response = self.client.messages.create(
                model=os.environ.get("AGENT_MODEL", "claude-sonnet-4-6"),
                max_tokens=self.MAX_TOKENS,
                system=self.system_prompt,
                tools=self.tools if self.tools else anthropic.NOT_GIVEN,
                messages=messages,
            )

            # Track token usage
            if hasattr(response, "usage"):
                self.token_usage["input"] += response.usage.input_tokens
                self.token_usage["output"] += response.usage.output_tokens

            # Collect text blocks
            for block in response.content:
                if hasattr(block, "text"):
                    final_output += block.text

            # Check stop reason
            if response.stop_reason == "end_turn":
                return AgentResult(
                    success=True,
                    output=final_output,
                    files_modified=files_modified,
                    token_usage=self.token_usage,
                )

            # Handle tool calls
            if response.stop_reason == "tool_use":
                tool_results = []
                for block in response.content:
                    if block.type != "tool_use":
                        continue

                    await self.emit("TOOL_CALL", {
                        "tool": block.name,
                        "input_preview": str(block.input)[:150],
                    })

                    try:
                        result = await self.handle_tool_call(block.name, block.input)
                        # Track file modifications
                        if block.name in ("write_file", "apply_patch") and "path" in block.input:
                            files_modified.append(block.input["path"])

                        await self.emit("TOOL_RESULT", {
                            "tool": block.name,
                            "success": True,
                            "output_preview": str(result)[:150],
                        })
                        tool_results.append({
                            "type": "tool_result",
                            "tool_use_id": block.id,
                            "content": str(result),
                        })
                    except Exception as e:
                        error = f"Tool error: {e}"
                        await self.emit("TOOL_RESULT", {
                            "tool": block.name,
                            "success": False,
                            "error": error,
                        })
                        tool_results.append({
                            "type": "tool_result",
                            "tool_use_id": block.id,
                            "content": error,
                            "is_error": True,
                        })

                # Add assistant response + tool results to messages
                messages.append({"role": "assistant", "content": response.content})
                messages.append({"role": "user", "content": tool_results})

            else:
                # Unknown stop reason — treat as done
                return AgentResult(
                    success=True,
                    output=final_output,
                    files_modified=files_modified,
                    token_usage=self.token_usage,
                )
