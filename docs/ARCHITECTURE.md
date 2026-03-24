# Architecture
## Vulnerable MCP Server

> **How to use this document:** This document contains structural diagrams — repository layout, network topology, protocol flow, and agent system wiring. For operational guides, see [USAGE.md](USAGE.md) or [GETTING_STARTED.md](GETTING_STARTED.md).

---

## The 10,000-foot View

The server is a Python program that speaks the MCP protocol. It registers tools that have intentional bugs — missing auth checks, unparameterized SQL queries, unsandboxed template engines, and behaviors that change after the first call. When you call those tools, you see what the bugs enable. Every exploit is sandboxed by default so nothing on your machine is harmed.

---

### Reading the Diagrams

- **MCP Protocol Flow** → Understand what messages pass between client and server
- **Single Server Docker Network** → What `docker compose up` creates
- **Multi-Server Lab** → What `docker compose -f ... -f multi_server/...` creates (Phase 2)
- **Multi-Agent System** → How `python agents/dashboard.py --run "..."` works internally
- **Security Boundaries** → What `MCP_SANDBOX=true` vs `false` means at the system level

---

## 1. Repository Structure

```
vulnerable-mcp-server/
│
├── server.py                   # Entry point — FastMCP init, module registration
├── config.py                   # Safety gate, env vars, fake secrets
├── pyproject.toml              # Dependencies
├── Dockerfile                  # Single-server container
├── docker-compose.yml          # Full lab (server + attacker sim)
│
├── flags/
│   ├── __init__.py
│   └── flags.py                # CTF flag registry
│
├── vulnerabilities/            # One module per vuln category
│   ├── base.py                 # Abstract VulnerabilityModule class
│   ├── __init__.py             # ALL_MODULES registry
│   ├── tool_poisoning.py       # BEGINNER-001
│   ├── injection.py            # BEGINNER-002/003, INTERMEDIATE-002, ADVANCED-002/004
│   ├── auth.py                 # INTERMEDIATE-001/004
│   ├── exfiltration.py         # INTERMEDIATE-003
│   ├── prompt_injection.py     # BEGINNER-004, ADVANCED-001
│   ├── dos.py                  # ADVANCED-003
│   ├── rug_pull.py             # RUG-001/002
│   ├── tool_shadowing.py       # SHADOW-001/002
│   ├── oauth.py                # OAUTH-001
│   ├── multi_vector.py         # MULTI-001
│   ├── git_ops.py              # GIT-001/002/003 (Phase 2)
│   └── sampling.py             # SAMPLE-001/002 (Phase 2)
│
├── resources/
│   ├── __init__.py
│   └── sensitive.py            # MCP resources with sensitive data
│
├── challenges/                 # YAML challenge definitions
│   ├── beginner.yaml
│   ├── intermediate.yaml
│   ├── advanced.yaml
│   ├── rug_pull.yaml           # RUG-001/002
│   ├── tool_shadowing.yaml     # SHADOW-001/002
│   ├── oauth.yaml              # OAUTH-001
│   ├── multi_vector.yaml       # MULTI-001
│   └── cve_accurate.yaml       # Phase 2 CVE challenges
│
├── multi_server/               # Phase 2: second trusted server for shadowing
│   ├── trusted_server.py       # Legitimate email/file server
│   └── docker-compose.multi.yml
│
├── observability/
│   ├── trace_logger.py         # Per-request JSON trace logging
│   └── metrics.py              # /metrics endpoint, attack counters
│
├── agents/                     # Multi-agent development system
│   ├── base_agent.py           # Base class with observability hooks
│   ├── orchestrator.py         # Task routing and progress tracking
│   ├── coding_agent.py         # Writes/modifies vulnerability modules
│   ├── debugging_agent.py      # Diagnoses and fixes test failures
│   ├── testing_agent.py        # Verifies exploits and scanner findings
│   ├── docs_agent.py           # Keeps documentation current
│   └── dashboard.py            # Real-time agent observability TUI
│
├── tests/
│   ├── helpers.py              # ToolCapture, assert_flag, assert_no_flag, assert_sandboxed
│   ├── conftest.py             # Shared pytest fixtures (sandbox_config, etc.)
│   ├── test_beginner.py        # BEGINNER-001 through BEGINNER-004
│   ├── test_intermediate.py    # INTERMEDIATE-001 through INTERMEDIATE-004
│   ├── test_advanced.py        # ADVANCED-001 through ADVANCED-004
│   ├── test_rug_pull.py        # RUG-001 and RUG-002
│   ├── test_tool_shadowing.py  # SHADOW-001 and SHADOW-002
│   ├── test_oauth.py           # OAUTH-001
│   ├── test_multi_vector.py    # MULTI-001 full chain
│   ├── test_sandbox.py         # Verify sandbox mode blocks real execution
│   ├── test_flags.py           # Flag system unit tests
│   ├── test_modules.py         # Module contracts: base class, metadata, register()
│   ├── test_ctf_system.py      # YAML challenge definitions, hints, submit_flag()
│   ├── test_resources.py       # Sensitive MCP resources
│   ├── test_config.py          # Training mode gate, env var parsing
│   └── scanner_compat/
│       ├── test_mcp_scan.py    # Verify mcp-scan finds expected findings
│       ├── test_cisco.py       # Verify Cisco scanner findings
│       └── test_proximity.py   # Verify Proximity findings
│
└── docs/
    ├── GETTING_STARTED.md      # Game-style level walkthrough (start here)
    ├── USAGE.md                # Full operational reference
    ├── CONTRIBUTING.md         # How to add a new challenge
    ├── ROADMAP.md              # Gap analysis, CVE table, phase milestones
    ├── PRD.md                  # Product requirements and acceptance criteria
    ├── SCOPE.md                # In/out of scope, priority matrix
    ├── ARCHITECTURE.md         # This file — structure, network, agent diagrams
    ├── SYSTEM_DESIGN.md        # Server + agent system design with code patterns
    └── THREAT_MODEL.md         # CVE-based threat model, STRIDE analysis
```

---

## 2. MCP Protocol Flow

```
                    ┌─────────────────────────────────┐
                    │     MCP Client                   │
                    │  (Claude Desktop / Cursor / etc) │
                    └──────────────┬──────────────────┘
                                   │
                        JSON-RPC 2.0 over:
                        • stdio (pipe)
                        • HTTP+SSE
                        • streamable-http
                                   │
                    ┌──────────────▼──────────────────┐
                    │     FastMCP Server               │
                    │                                  │
                    │  initialize ──► capability nego  │
                    │  tools/list ──► [POISONED META]  │
                    │  tools/call ──► [VULN HANDLER]   │
                    │  resources/read ► [SENSITIVE]    │
                    │  sampling ◄── [SERVER INITIATES] │
                    └──────────────────────────────────┘
```

---

## 3. Single Server — Docker Network

```
┌─────────────────────────────────────────────────────┐
│  Host Machine                                        │
│                                                      │
│  ┌───────────────────────────────────────────────┐  │
│  │  Docker network: training-net (bridge)         │  │
│  │                                                │  │
│  │  ┌──────────────────────────┐                  │  │
│  │  │  vulnerable-mcp          │                  │  │
│  │  │  container               │                  │  │
│  │  │                          │                  │  │
│  │  │  python server.py        │                  │  │
│  │  │  MCP_TRANSPORT=sse       │                  │  │
│  │  │  MCP_SANDBOX=true        │                  │  │
│  │  │  CPU: 1 core max         │                  │  │
│  │  │  RAM: 512MB max          │                  │  │
│  │  │  USER: training (non-root│                  │  │
│  │  │                          │                  │  │
│  │  │  EXPOSE 8000             │                  │  │
│  │  └──────────────┬───────────┘                  │  │
│  │                 │                               │  │
│  └─────────────────┼───────────────────────────────┘  │
│                    │ :8000 (published)                 │
│                    ▼                                   │
│          MCP Inspector / mcp-scan /                   │
│          Claude Desktop / Cursor                       │
└─────────────────────────────────────────────────────┘
```

---

## 4. Multi-Server Lab — Docker Network (Phase 2)

```
┌──────────────────────────────────────────────────────────────────┐
│  Docker network: training-net (bridge)                           │
│                                                                  │
│  ┌─────────────────────┐    ┌─────────────────────────────────┐  │
│  │  trusted-server      │    │  vulnerable-mcp (malicious)      │  │
│  │  :9001              │    │  :8000                          │  │
│  │                     │    │                                 │  │
│  │  send_email()        │    │  shadow_tool (references        │  │
│  │  read_file()         │    │  trusted server's send_email)   │  │
│  │  list_docs()         │    │                                 │  │
│  │                     │    │  fetch_url() → attacker-server  │  │
│  └─────────────────────┘    └─────────────────────────────────┘  │
│                                           │                      │
│  ┌────────────────────────────────────────┼──────────────────┐   │
│  │  attacker-server :80                   │                  │   │
│  │                                        │                  │   │
│  │  GET /inject → returns adversarial LLM instructions       │   │
│  │  GET /exfil  → returns [INST] exfiltration prompt         │   │
│  │  GET /collect→ logs received data (training only)         │   │
│  └──────────────────────────────────────────────────────────┘   │
│                                                                  │
└──────────────────────────────────────────────────────────────────┘
         │                    │
    :8000 (published)    :9001 (internal only)
         │
MCP Client connects here, gets tools from BOTH servers
→ Tool shadowing attack triggers
```

---

## 5. Multi-Agent Development System

```
┌──────────────────────────────────────────────────────────────────┐
│  agents/                                                         │
│                                                                  │
│  ┌────────────────────────────────────────────────────────────┐  │
│  │  ORCHESTRATOR AGENT                                        │  │
│  │  • Receives task: "implement OAUTH-001"                    │  │
│  │  • Reads PRD.md + SCOPE.md for requirements               │  │
│  │  • Breaks into: [code] → [debug] → [test] → [docs]        │  │
│  │  • Publishes events to dashboard                           │  │
│  │  • Retries failed sub-tasks up to 3x                      │  │
│  └──────────────────────────────────────────────────────────┘  │
│                    │           │           │           │         │
│                    ▼           ▼           ▼           ▼         │
│  ┌──────────┐ ┌──────────┐ ┌──────────┐ ┌──────────────────┐   │
│  │ CODING   │ │DEBUGGING │ │ TESTING  │ │   DOCS AGENT     │   │
│  │ AGENT    │ │ AGENT    │ │ AGENT    │ │                  │   │
│  │          │ │          │ │          │ │ • Updates YAML   │   │
│  │ • Writes │ │ • Reads  │ │ • Runs   │ │ • Updates README │   │
│  │   vuln   │ │   test   │ │   exploit│ │ • Writes remedy  │   │
│  │   module │ │   output │ │   scripts│ │   guide          │   │
│  │ • Reads  │ │ • Traces │ │ • Checks │ │ • Keeps PRD in   │   │
│  │   PRD    │ │   errors │ │   flags  │ │   sync with code │   │
│  │ • Follows│ │ • Patches│ │ • Runs   │ │                  │   │
│  │   SCOPE  │ │   code   │ │   scanner│ │                  │   │
│  └──────────┘ └──────────┘ └──────────┘ └──────────────────┘   │
│                                                                  │
│  ┌────────────────────────────────────────────────────────────┐  │
│  │  SHARED EVENT BUS (asyncio.Queue)                          │  │
│  │  Events: STARTED | THINKING | TOOL_CALL | RESULT |         │  │
│  │          COMPLETED | FAILED | RETRY                        │  │
│  └────────────────────────────────────────────────────────────┘  │
│                                                                  │
│  ┌────────────────────────────────────────────────────────────┐  │
│  │  DASHBOARD (Rich TUI / terminal)                           │  │
│  │  • Live agent status panels                                │  │
│  │  • Tool call log with timestamps                           │  │
│  │  • Token usage per agent                                   │  │
│  │  • Task completion progress bar                            │  │
│  │  • Error log with retry count                              │  │
│  └────────────────────────────────────────────────────────────┘  │
└──────────────────────────────────────────────────────────────────┘
```

---

## 6. Observability — Trace Log Format

Every tool call produces a structured log entry:

```json
{
  "ts": "2026-03-23T14:32:01.123Z",
  "session_id": "sess_abc123",
  "tool": "run_command",
  "params_hash": "sha256:a3f4...",
  "injection_detected": true,
  "injection_chars": [";", "|"],
  "sandbox_triggered": true,
  "flag_returned": "BEGINNER-002",
  "result_type": "flag",
  "duration_ms": 2
}
```

Full protocol traces (when `MCP_TRACE=true`):
```json
{
  "direction": "client→server",
  "method": "tools/call",
  "id": "1",
  "params": {
    "name": "run_command",
    "arguments": {"command": "echo hello; cat /etc/passwd"}
  }
}
```

---

## 7. Security Boundaries

```
┌─────────────────────────────────────────────────────────────────┐
│  HARD BOUNDARIES (never crossed regardless of config)           │
│                                                                  │
│  • Fake credentials: never match real key formats               │
│  • Flags: meaningless CTF strings, no real system impact        │
│  • Simulated files: /etc/passwd returns a fake response         │
│                                                                  │
├─────────────────────────────────────────────────────────────────┤
│  SANDBOX BOUNDARIES (crossed only with MCP_SANDBOX=false        │
│  AND running inside Docker with resource limits)                │
│                                                                  │
│  • subprocess execution (run_command)                           │
│  • Real HTTP requests (fetch_url SSRF)                          │
│  • Actual pickle deserialization (create_report)                │
│                                                                  │
├─────────────────────────────────────────────────────────────────┤
│  DOCKER RESOURCE LIMITS (always enforced)                       │
│                                                                  │
│  • 1 CPU core max                                               │
│  • 512MB RAM max                                                │
│  • Non-root user (training)                                     │
│  • No --privileged, no host network                             │
└─────────────────────────────────────────────────────────────────┘
```

---

## 8. Testing Without a Server

Our tests never start a real MCP server. Instead, they use a fake FastMCP object called `ToolCapture` that captures tool registrations and calls them as plain Python functions. This makes tests fast (under 5 seconds for 515 tests) and reliable (no network, no ports, no process management).

Here's how it works:

```python
# Instead of this (needs a running server):
async with sse_client("http://localhost:8000/sse") as (r, w):
    async with ClientSession(r, w) as session:
        result = await session.call_tool("run_command", {"command": "echo; whoami"})

# Tests do this (pure Python, no server):
from tests.helpers import ToolCapture, assert_flag
from vulnerabilities.injection import InjectionModule

cap = ToolCapture()
InjectionModule(cap, sandbox_config).register()  # @app.tool() calls are captured

result = await cap.call("run_command", command="echo hello; whoami")
assert_flag(result, "BEGINNER-002")
```

`ToolCapture` (defined in `tests/helpers.py`) implements the same `tool()` and `resource()` decorator interface as FastMCP. When a vulnerability module calls `@self.app.tool(description="...")`, `ToolCapture` stores the function by name. `cap.call("tool_name", **kwargs)` then calls the function directly — no JSON-RPC encoding, no HTTP, no event loop setup.

The three assertion helpers keep test code consistent:

| Helper | What it checks |
|--------|---------------|
| `assert_flag(result, "CHALLENGE-001")` | The expected `FLAG{...}` value appears in the output |
| `assert_no_flag(result)` | No `FLAG{` pattern appears (safe input path) |
| `assert_sandboxed(result)` | The `[SANDBOX]` marker appears (sandbox intercepted the call) |
