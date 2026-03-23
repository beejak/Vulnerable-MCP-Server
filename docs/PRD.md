# Product Requirements Document
## Vulnerable MCP Server — Security Training Platform

**Version:** 1.0
**Status:** Active
**Last Updated:** March 2026

---

## 1. Problem Statement

MCP servers are being integrated into production AI systems at scale. As of March 2026:
- 36.7% of public MCP servers have latent SSRF exposure (Wiz research)
- 23% of scanned MCP servers contain command injection vulnerabilities (mcp-scan data)
- 84.2% of tool poisoning attacks succeed when auto-approval is enabled (Invariant Labs)
- Multiple critical CVEs (9.6 CVSS) disclosed in widely deployed MCP packages

Security teams, developers, and researchers lack a realistic, hands-on target to:
1. Test MCP security scanners against known-vulnerable behavior
2. Learn MCP-specific attack patterns that differ from classical web vulns
3. Validate fixes by seeing both the vulnerable and secure versions

Existing projects (appsecco lab, damn-vulnerable-MCP-server) do not cover CVE-accurate scenarios, rug pull attacks, MCP sampling abuse, or cross-server tool shadowing with real PoCs. None are designed as scanner-compatible targets.

---

## 2. Goals

### Primary
- Provide a self-contained, exploitable MCP server that covers every major real-world attack class
- Be a named, compatible test target for mcp-scan, Cisco MCP Scanner, and Proximity
- Each challenge maps to a real CVE or published research (no made-up vulns)

### Secondary
- Teach the mechanism of each attack, not just that it works
- Support remediation mode (flip a config, attack fails, see why)
- Enable CTF organizers to run scored competitions

### Non-Goals
- Real credential theft from live systems
- Network exploitation beyond MCP protocol scope
- Browser-based or mobile MCP client vulnerabilities

---

## 3. Users

| User | Use Case | Key Need |
|------|----------|----------|
| Security researcher | Test mcp-scan accuracy against known-vuln server | Predictable, reproducible findings |
| Developer | Understand why their MCP server is flagged | Side-by-side vulnerable/secure code |
| Red teamer | Practice MCP-specific attack chains before engagement | Realistic multi-step chains |
| CTF organizer | Host a competition | Docker deployment, flag system, scoring |
| Security trainer | Teach MCP security in workshops | Progressive difficulty, hints, remediation guide |

---

## 4. Functional Requirements

### 4.1 Core Server

**FR-001**: Server runs in stdio transport (Claude Desktop integration) and HTTP+SSE transport (remote testing).

**FR-002**: `MCP_TRAINING_MODE=true` must be set to start. Server exits with clear message if not set.

**FR-003**: `MCP_SANDBOX=true` (default) simulates destructive operations and returns flags on detection. `MCP_SANDBOX=false` enables real execution (Docker-isolated only).

**FR-004**: `MCP_DIFFICULTY=beginner|intermediate|advanced|all` controls which vulnerability tier is active.

**FR-005**: All fake credentials/keys must be obviously fake (prefix `sk-fake`, `AKIAFAKE`, etc.) and must not accidentally match any real API key format that would trigger scanner false positives.

### 4.2 Vulnerability Modules

**FR-010**: Each vulnerability is in its own module file, independently loadable.

**FR-011**: Every vulnerability has: challenge ID, CVE reference (if applicable), CWE ID, CVSS score, 3-level hint system, exploitation steps, remediation guide, and a capturable flag.

**FR-012**: Flags follow the format `FLAG{...}` with challenge-specific encoded text.

**FR-013**: `submit_flag(challenge_id, flag)` validates and acknowledges correct submissions.

### 4.3 Phase 1 Vulnerabilities (MVP — existing)

| ID | Type | CWE |
|----|------|-----|
| BEGINNER-001 | Tool Poisoning (Unicode hidden instructions) | CWE-116 |
| BEGINNER-002 | Command Injection (shell=True) | CWE-78 |
| BEGINNER-003 | Path Traversal | CWE-22 |
| BEGINNER-004 | Indirect Prompt Injection | CWE-77 |
| INTERMEDIATE-001 | Auth Bypass (missing check) | CWE-862 |
| INTERMEDIATE-002 | SQL Injection (f-string) | CWE-89 |
| INTERMEDIATE-003 | Secret Leakage in descriptions | CWE-312 |
| INTERMEDIATE-004 | State Manipulation | CWE-372 |
| ADVANCED-001 | SSRF | CWE-918 |
| ADVANCED-002 | Template Injection (Jinja2 SSTI) | CWE-94 |
| ADVANCED-003 | DoS / Resource Exhaustion | CWE-400 |
| ADVANCED-004 | Pickle Deserialization RCE | CWE-502 |

### 4.4 Phase 2 Vulnerabilities (CVE-Accurate)

| ID | Maps To | Type |
|----|---------|------|
| OAUTH-001 | CVE-2025-6514 | OS command injection via OAuth `authorization_endpoint` |
| OAUTH-002 | CVE-2025-6515 | Session/token hijacking via OAuth state reuse |
| GIT-001 | CVE-2025-68145 | `--repository` flag path validation bypass |
| GIT-002 | CVE-2025-68143 | `git_init` targeting sensitive directories |
| GIT-003 | CVE-2025-68144 | Argument injection in `git_diff` |
| SDK-001 | CVE-2026-25536 | Cross-client response leak |
| RUG-001 | Invariant Labs research | Rug pull: dynamic tool definition mutation |
| SHADOW-001 | Invariant Labs research | Tool shadowing: cross-server email redirect |
| SAMPLE-001 | Unit42 research (Dec 2025) | Sampling abuse: server → client LLM manipulation |
| PROTO-001 | MCP spec analysis | JSON-RPC state machine violation |

### 4.5 CTF System

**FR-020**: `list_challenges()` returns all challenge IDs, titles, difficulty, points value, CWE, and CVE reference.

**FR-021**: `get_hint(challenge_id, level)` returns hints at levels 1 (vague), 2 (directional), 3 (near-solution).

**FR-022**: `get_challenge_details(challenge_id)` returns full description, exploitation steps, and remediation guide.

**FR-023**: `submit_flag(challenge_id, flag)` validates submission and returns success/failure with encouragement.

**FR-024**: Challenge completion is tracked per-session (in-memory; not persisted unless `MCP_CTF_MODE=true`).

### 4.6 Observability

**FR-030**: All tool calls are logged to stderr in JSON format: `{ts, tool, params_hash, result_type, injection_detected, sandbox_triggered}`.

**FR-031**: In `MCP_TRACE=true` mode, full request/response JSON-RPC messages are logged to a trace file.

**FR-032**: An HTTP endpoint `/metrics` (when transport=sse) exposes: total tool calls, injection attempts detected, flags submitted, challenges solved.

---

## 5. Non-Functional Requirements

**NFR-001 Safety**: Server must not be startable without `MCP_TRAINING_MODE=true`. Startup banner must clearly state the server is vulnerable by design.

**NFR-002 Isolation**: Docker deployment must use resource limits: 1 CPU core, 512MB RAM. `--cap-drop ALL` with only necessary capabilities restored.

**NFR-003 Reproducibility**: All flags, challenge IDs, and exploitation paths must be deterministic and documented. A researcher must be able to reproduce any finding.

**NFR-004 Scanner Compatibility**: Running `mcp-scan` against this server must return ≥ 8 findings matching documented vulnerabilities, within 5 minutes.

**NFR-005 Documentation**: Every vulnerability module must have a corresponding YAML challenge definition with: description, objective, steps, hints (3 levels), CVE reference, CWE, CVSS, and remediation.

**NFR-006 Python Version**: Must run on Python 3.11+. Tested against 3.11, 3.12, 3.14.

**NFR-007 Startup Time**: Server must be ready to accept connections within 3 seconds of start in stdio mode.

---

## 6. Technical Constraints

- MCP SDK: `mcp[cli] >= 1.0.0` (FastMCP)
- Transport: stdio (primary), HTTP+SSE (secondary), streamable-http (tertiary)
- No external database — in-memory SQLite only
- All file I/O during challenge exploitation stays within the project directory (sandbox) or is simulated
- No persistent state across server restarts unless explicitly configured

---

## 7. Acceptance Criteria

| Criterion | Test |
|-----------|------|
| All 12 MVP challenges exploitable | Run `tests/test_all_challenges.py` — 12/12 pass |
| Sandbox mode blocks real execution | `MCP_SANDBOX=true` + run attack → flag returned, no real command executed |
| Scanner finds expected findings | `mcp-scan` report ≥ 8 vulnerabilities |
| Training mode gate works | Start without `MCP_TRAINING_MODE=true` → immediate exit, clear message |
| Docker deployment clean | `docker compose up` → server healthy within 30s |
| Flag submission works | `submit_flag("BEGINNER-002", "FLAG{c0mm4nd_1nj3ct10n_sh3ll_tr00}")` → CORRECT |
