"""
Real-time agent observability dashboard.

Uses Rich (already available via mcp[cli] deps) to render a live
terminal dashboard showing all agent activity, token usage, event log,
and task queue.

Usage:
    python agents/dashboard.py                          # watch mode
    python agents/dashboard.py --run "Add OAUTH-001"   # run task + watch
"""
import asyncio
import json
import os
import time
from collections import deque

try:
    from rich import box
    from rich.console import Console
    from rich.layout import Layout
    from rich.live import Live
    from rich.panel import Panel
    from rich.table import Table
    from rich.text import Text
    RICH_AVAILABLE = True
except ImportError:
    RICH_AVAILABLE = False

from agents.base_agent import AgentEvent

STATUS_COLOR = {
    "STARTED": "cyan",
    "THINKING": "yellow",
    "TOOL_CALL": "blue",
    "TOOL_RESULT": "green",
    "RETRY": "orange1",
    "COMPLETED": "bright_green",
    "FAILED": "red",
}

AGENT_NAMES = ["ORCHESTRATOR", "CODING", "DEBUGGING", "TESTING", "DOCS"]


class AgentDashboard:
    """
    Live Rich TUI dashboard showing all agent activity.

    Subscribes to the shared event bus and renders updates every 100ms.
    """

    def __init__(self, event_bus: asyncio.Queue):
        self.event_bus = event_bus
        self.console = Console()
        self.agent_status: dict[str, str] = {a: "IDLE" for a in AGENT_NAMES}
        self.agent_task: dict[str, str] = {a: "" for a in AGENT_NAMES}
        self.agent_tokens: dict[str, dict] = {a: {"input": 0, "output": 0} for a in AGENT_NAMES}
        self.event_log: deque = deque(maxlen=50)
        self.task_queue: list[str] = []
        self.completed_tasks: list[str] = []
        self.start_time = time.time()
        self._running = True

    def _make_layout(self) -> Layout:
        layout = Layout()
        layout.split_column(
            Layout(name="header", size=3),
            Layout(name="main", ratio=1),
            Layout(name="footer", size=3),
        )
        layout["main"].split_row(
            Layout(name="agents", ratio=2),
            Layout(name="events", ratio=3),
        )
        layout["agents"].split_column(
            Layout(name="agent_grid"),
            Layout(name="tokens", size=8),
        )
        return layout

    def _render_header(self) -> Panel:
        uptime = int(time.time() - self.start_time)
        h, m, s = uptime // 3600, (uptime % 3600) // 60, uptime % 60
        title = Text()
        title.append("Vulnerable MCP Server", style="bold white")
        title.append(" — ", style="dim")
        title.append("Agent Build System", style="bold cyan")
        title.append(f"  [{h:02d}:{m:02d}:{s:02d}]", style="dim")
        return Panel(title, box=box.MINIMAL)

    def _render_agent_grid(self) -> Panel:
        table = Table(box=box.SIMPLE, expand=True, show_header=True, header_style="bold")
        table.add_column("Agent", width=14)
        table.add_column("Status", width=12)
        table.add_column("Current Task", ratio=1)

        for agent in AGENT_NAMES:
            status = self.agent_status.get(agent, "IDLE")
            task = self.agent_task.get(agent, "")[:60]
            color = STATUS_COLOR.get(status, "white")
            table.add_row(
                Text(agent, style="bold"),
                Text(f"● {status}", style=color),
                Text(task, style="dim"),
            )
        return Panel(table, title="[bold]Agents[/bold]", box=box.ROUNDED)

    def _render_tokens(self) -> Panel:
        table = Table(box=box.SIMPLE, expand=True, show_header=True, header_style="bold dim")
        table.add_column("Agent", width=14)
        table.add_column("Input", justify="right", width=10)
        table.add_column("Output", justify="right", width=10)
        table.add_column("Total", justify="right", width=10)

        total_in = total_out = 0
        for agent in AGENT_NAMES:
            tkns = self.agent_tokens.get(agent, {"input": 0, "output": 0})
            i, o = tkns["input"], tkns["output"]
            total_in += i
            total_out += o
            if i + o > 0:
                table.add_row(agent, f"{i:,}", f"{o:,}", f"{i+o:,}")

        table.add_row(
            Text("TOTAL", style="bold"), f"{total_in:,}", f"{total_out:,}",
            Text(f"{total_in+total_out:,}", style="bold cyan"), style="bold"
        )
        return Panel(table, title="[bold]Token Usage[/bold]", box=box.ROUNDED)

    def _render_events(self) -> Panel:
        lines = []
        for event in list(self.event_log)[-30:]:
            ts = event.get("ts", "")[-12:-4] if "ts" in event else ""
            agent = event.get("agent", "?")[:12]
            etype = event.get("event", "?")
            color = STATUS_COLOR.get(etype, "white")

            detail = ""
            for key in ("task", "tool", "error", "message", "output_preview", "summary"):
                if key in event:
                    detail = str(event[key])[:80]
                    break

            line = Text()
            line.append(f"{ts} ", style="dim")
            line.append(f"{agent:<13}", style="bold")
            line.append(f"{etype:<12}", style=color)
            line.append(detail, style="dim")
            lines.append(line)

        content = Text("\n").join(lines) if lines else Text("No events yet", style="dim")
        return Panel(content, title="[bold]Event Log[/bold]", box=box.ROUNDED)

    def _render_footer(self) -> Panel:
        done = len(self.completed_tasks)
        pending = len(self.task_queue)
        text = Text()
        text.append(f"Completed: {done}  ", style="green")
        text.append(f"Queued: {pending}  ", style="yellow")
        if self.completed_tasks:
            text.append(f"Last: {self.completed_tasks[-1]}", style="dim")
        return Panel(text, box=box.MINIMAL)

    async def consume_events(self) -> None:
        """Background task: drain event bus and update state."""
        while self._running:
            try:
                event: AgentEvent = await asyncio.wait_for(
                    self.event_bus.get(), timeout=0.1
                )
                event_dict = {
                    "ts": event.ts,
                    "agent": event.agent,
                    "event": event.event,
                    **event.data,
                }
                self.event_log.append(event_dict)

                # Update agent status
                agent = event.agent
                etype = event.event
                if agent in self.agent_status:
                    self.agent_status[agent] = etype
                    if "task" in event.data:
                        self.agent_task[agent] = event.data["task"]
                    if etype in ("COMPLETED", "FAILED"):
                        self.agent_task[agent] = ""
                        if etype == "COMPLETED" and "task" in event.data:
                            self.completed_tasks.append(event.data["task"][:50])

                # Track tokens
                if "tokens" in event.data:
                    tkns = event.data["tokens"]
                    if agent in self.agent_tokens:
                        self.agent_tokens[agent]["input"] += tkns.get("input", 0)
                        self.agent_tokens[agent]["output"] += tkns.get("output", 0)

            except asyncio.TimeoutError:
                pass
            except Exception:
                pass

    async def run(self) -> None:
        """Run the live dashboard."""
        if not RICH_AVAILABLE:
            # Fallback: plain text log
            print("[Dashboard] Rich not available. Logging events to stdout.")
            async for event in self._event_stream():
                print(json.dumps(event.data))
            return

        layout = self._make_layout()

        async def update_loop():
            while self._running:
                layout["header"].update(self._render_header())
                layout["agent_grid"].update(self._render_agent_grid())
                layout["tokens"].update(self._render_tokens())
                layout["events"].update(self._render_events())
                layout["footer"].update(self._render_footer())
                await asyncio.sleep(0.1)

        consumer = asyncio.create_task(self.consume_events())
        updater = asyncio.create_task(update_loop())

        with Live(layout, console=self.console, refresh_per_second=10, screen=True):
            try:
                await asyncio.gather(consumer, updater)
            except asyncio.CancelledError:
                pass
            finally:
                self._running = False
                consumer.cancel()
                updater.cancel()

    def stop(self) -> None:
        self._running = False


async def run_with_dashboard(task: str, work_dir: str = None) -> None:
    """
    Launch the orchestrator with the live dashboard attached.

    Args:
        task: High-level task for the orchestrator (e.g., "Implement OAUTH-001")
        work_dir: Project root directory
    """
    from agents.orchestrator import OrchestratorAgent

    event_bus: asyncio.Queue = asyncio.Queue()
    work_dir = work_dir or os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

    dashboard = AgentDashboard(event_bus)
    orchestrator = OrchestratorAgent(event_bus, work_dir)

    # Run orchestrator and dashboard concurrently
    async def run_orchestrator():
        result = await orchestrator.run_task(task)
        dashboard.stop()
        return result

    dashboard_task = asyncio.create_task(dashboard.run())
    orch_task = asyncio.create_task(run_orchestrator())

    result = await orch_task
    await asyncio.gather(dashboard_task, return_exceptions=True)

    print(f"\n{'='*60}")
    print(f"Result: {'SUCCESS' if result.success else 'FAILED'}")
    print(f"Output: {result.output}")
    if result.files_modified:
        print(f"Files modified: {', '.join(result.files_modified)}")


if __name__ == "__main__":
    import argparse

    parser = argparse.ArgumentParser(description="Agent build system dashboard")
    parser.add_argument("--run", type=str, help="Task to execute (e.g., 'Implement OAUTH-001')")
    parser.add_argument("--watch", action="store_true", help="Watch mode — just show dashboard")
    args = parser.parse_args()

    if args.run:
        asyncio.run(run_with_dashboard(args.run))
    elif args.watch:
        event_bus: asyncio.Queue = asyncio.Queue()
        dashboard = AgentDashboard(event_bus)
        print("Dashboard watching for events (start orchestrator separately)...")
        asyncio.run(dashboard.run())
    else:
        parser.print_help()
