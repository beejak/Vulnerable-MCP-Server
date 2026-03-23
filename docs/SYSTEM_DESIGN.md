# System Design
## Multi-Agent Development System + Vulnerable MCP Server

---

## Part 1: Vulnerable MCP Server Design

### Module Lifecycle

```
ServerConfig (env vars)
    ↓ require_training_mode() — hard exit if not set
    ↓
create_server()
    ↓ FastMCP(name, instructions)
    ↓
    for ModuleClass in ALL_MODULES:
        module = ModuleClass(app, config)
        module.register()        ← attaches tools/resources to app
    ↓
register_resources(app)          ← attaches MCP resources
    ↓
app.run(transport=config.transport)
```

### VulnerabilityModule Contract

```python
class VulnerabilityModule(ABC):
    def __init__(self, app: FastMCP, config: ServerConfig): ...

    @property
    @abstractmethod
    def metadata(self) -> list[VulnerabilityMeta]:
        # Returns challenge definitions (fed to YAML generator)
        ...

    @abstractmethod
    def register(self) -> None:
        # Attaches @app.tool() and @app.resource() decorators
        # All vulnerability logic lives here
        ...
```

### Adding a New Vulnerability (5 steps)

1. Create `vulnerabilities/my_vuln.py` extending `VulnerabilityModule`
2. Implement `register()` with the vulnerable tool using `@app.tool()`
3. Add challenge to `challenges/tier.yaml` with hints, CVE, remediation
4. Register in `vulnerabilities/__init__.py` → `ALL_MODULES` list
5. Add flag to `flags/flags.py`

### Sandbox Decision Tree

```
Tool called by client
    ↓
Is config.sandbox_mode True?
    ├── YES: Does input contain injection indicators?
    │           ├── YES: Return flag + educational message (no real execution)
    │           └── NO:  Return simulated output
    └── NO (Docker-isolated): Execute real operation, return actual output
```

---

## Part 2: Multi-Agent Development System Design

### Design Principles

- **Observability first**: Every agent action is a typed event published to a shared bus before and after execution
- **Fail loudly**: Agents report failures with full context; orchestrator decides retry vs escalate
- **Independent modules**: Each agent can run standalone or as part of the orchestrated pipeline
- **Token budget awareness**: Each agent tracks its token usage; orchestrator can throttle
- **Idempotent tasks**: Re-running a coding task overwrites the same file; re-running tests gives same results

### Agent Base Class

```python
class BaseAgent:
    def __init__(self, role: str, tools: list, event_bus: asyncio.Queue):
        self.client = anthropic.Anthropic()
        self.role = role
        self.tools = tools
        self.event_bus = event_bus
        self.token_usage = {"input": 0, "output": 0}

    async def emit(self, event_type: str, data: dict):
        await self.event_bus.put({
            "ts": datetime.utcnow().isoformat(),
            "agent": self.role,
            "event": event_type,
            "data": data
        })

    async def run_task(self, task: str) -> AgentResult:
        await self.emit("STARTED", {"task": task})
        # ... Claude API call with tool use loop ...
        await self.emit("COMPLETED", {"result": result})
        return result
```

### Agent Roles and Tools

| Agent | System Prompt Focus | Tools Available |
|-------|--------------------|-----------------|
| **Orchestrator** | Task decomposition, dependency management, progress tracking | read_file, write_file, list_files, create_task, assign_task, check_status |
| **Coding Agent** | Write modular, documented Python following existing patterns | read_file, write_file, list_files, run_python_check (syntax only) |
| **Debugging Agent** | Diagnose failures from test output, trace errors to root cause, apply minimal fixes | read_file, write_file, read_error_log, apply_patch |
| **Testing Agent** | Run exploit scripts, verify flags, check scanner output | read_file, run_mcp_client, submit_flag, run_scanner, check_exploit |
| **Docs Agent** | Keep YAML challenge definitions, README, and docstrings in sync with code | read_file, write_file, read_yaml, write_yaml |

### Event Types

```
STARTED     — agent begins a task
THINKING    — agent produced reasoning text (stream)
TOOL_CALL   — agent is about to call a tool (tool_name, input_preview)
TOOL_RESULT — tool returned (success/error, output_preview)
RETRY       — task failed, retrying (attempt N of 3)
COMPLETED   — task finished successfully
FAILED      — task exhausted retries, escalating to orchestrator
```

### Orchestrator Task Graph

```
Task: "Implement OAUTH-001 challenge"
    │
    ├─ [1] CODING: Write vulnerabilities/oauth.py
    │           implements OAuth metadata endpoint
    │           with CVE-2025-6514 injection vector
    │
    ├─ [2] CODING: Add OAUTH-001 to challenges/cve_accurate.yaml
    │
    ├─ [3] CODING: Add flag to flags/flags.py
    │
    ├─ [4] CODING: Register OAuthModule in vulnerabilities/__init__.py
    │
    ├─ [5] TESTING: Run test_oauth_001_exploitable()
    │           ↓ PASS → continue
    │           ↓ FAIL → DEBUGGING agent
    │                      ↓ patch applied
    │                      ↓ re-run step [5]
    │                      ↓ max 3 retries
    │
    ├─ [6] TESTING: Run mcp-scan, assert OAUTH-001 detected
    │
    └─ [7] DOCS: Update README challenge table
                 Update docs/ROADMAP.md Phase 1 checklist
```

### Dashboard Layout (Rich TUI)

```
╔══════════════════════════════════════════════════════════════════╗
║  Vulnerable MCP Server — Agent Build System                      ║
╠════════════════╦═════════════════╦═════════════════════════════╣
║  ORCHESTRATOR  ║  CODING AGENT   ║  TESTING AGENT              ║
║  Status: ACTIVE║  Status: BUSY   ║  Status: WAITING            ║
║  Task: OAUTH-01║  Writing:       ║                             ║
║  Progress: 3/7 ║  oauth.py       ║                             ║
╠════════════════╬═════════════════╬═════════════════════════════╣
║  DEBUGGING     ║  DOCS AGENT     ║  EVENT LOG                  ║
║  Status: IDLE  ║  Status: IDLE   ║  14:32:01 CODING STARTED    ║
║                ║                 ║  14:32:03 TOOL write_file   ║
║                ║                 ║  14:32:05 TOOL RESULT ok    ║
║                ║                 ║  14:32:06 CODING COMPLETED  ║
╠══════════════════════════════════╬══════════════════════════════╣
║  Token Usage                     ║  Task Queue (3 pending)      ║
║  Coding: 4,231 in / 812 out      ║  • Add OAUTH-002             ║
║  Testing: 1,102 in / 204 out     ║  • Write cve_accurate.yaml   ║
║  Total: 6,145 / 1,200            ║  • Run scanner compat tests  ║
╚══════════════════════════════════╩══════════════════════════════╝
```

### Failure Handling

```
Agent task fails
    ↓
emit(RETRY, {attempt: N, error: msg})
    ↓
Orchestrator sees RETRY event
    ↓
N < 3? → re-run task with error context appended to prompt
N = 3? → emit(FAILED, {task, error_history})
              ↓
         Debugging Agent gets full error history
              ↓
         Debugging Agent produces patch
              ↓
         Orchestrator re-runs original task from step 1
              ↓
         N = 3 again? → HALT, report to user
```

---

## Part 3: Observability Integration

### Trace Logger

`observability/trace_logger.py` hooks into FastMCP's tool execution pipeline via a middleware wrapper. It wraps every `@app.tool()` handler to log structured events before/after execution.

```python
# Applied at module registration time
def wrap_tool_handler(fn, tool_name: str, trace_logger):
    @functools.wraps(fn)
    async def wrapper(*args, **kwargs):
        trace_logger.log_call(tool_name, kwargs)
        result = await fn(*args, **kwargs)
        trace_logger.log_result(tool_name, result)
        return result
    return wrapper
```

Log output goes to:
- `stderr` (always, JSON lines format)
- `traces/session_{id}.jsonl` (when `MCP_TRACE=true`)
- `/metrics` HTTP endpoint (running totals)

### Metrics Endpoint

When `MCP_TRANSPORT=sse`, the server exposes `/metrics` at the same host/port:

```json
{
  "uptime_seconds": 342,
  "total_tool_calls": 47,
  "injection_attempts": 12,
  "flags_captured": 5,
  "challenges_solved": ["BEGINNER-002", "BEGINNER-003", "INTERMEDIATE-001"],
  "sandbox_blocks": 12,
  "top_tools": ["run_command", "query_users", "fetch_url"]
}
```
