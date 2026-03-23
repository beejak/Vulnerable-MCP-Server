# Architecture
## Vulnerable MCP Server

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
│   ├── oauth.py                # OAUTH-001/002 (Phase 2)
│   ├── git_ops.py              # GIT-001/002/003 (Phase 2)
│   ├── rug_pull.py             # RUG-001/002 (Phase 2)
│   ├── tool_shadowing.py       # SHADOW-001/002 (Phase 2)
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
│   ├── test_all_challenges.py  # End-to-end exploit verification
│   ├── test_sandbox.py         # Verify sandbox mode blocks real execution
│   ├── test_flags.py           # Flag system unit tests
│   └── scanner_compat/
│       ├── test_mcp_scan.py    # Verify mcp-scan finds expected findings
│       ├── test_cisco.py       # Verify Cisco scanner findings
│       └── test_proximity.py   # Verify Proximity findings
│
└── docs/
    ├── ROADMAP.md
    ├── PRD.md
    ├── SCOPE.md
    ├── ARCHITECTURE.md         # This file
    ├── SYSTEM_DESIGN.md
    └── THREAT_MODEL.md
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
