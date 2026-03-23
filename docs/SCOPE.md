# Scope Document
## Vulnerable MCP Server

---

## In Scope

### Vulnerability Categories (Current)
- **Tool Poisoning**: Unicode steganography, HTML comment injection, [INST]-format injection in tool descriptions
- **Injection**: OS command injection, path traversal, SQL injection, template injection (SSTI), pickle deserialization
- **Authentication**: Missing auth checks, state manipulation before initialization
- **Data Exfiltration**: Secrets in tool descriptions, unrestricted env var access, sensitive MCP resources
- **Network**: SSRF (simulated + real), indirect prompt injection via fetch_url
- **DoS**: Unbounded recursion, factorial blowup, request flooding

### Vulnerability Categories (Roadmap Phase 2)
- **CVE-Accurate Scenarios**: CVE-2025-6514 (OAuth injection), CVE-2025-68145/68143/68144 (Git RCE chain)
- **Rug Pull**: Dynamic tool definition mutation mid-session
- **Tool Shadowing**: Cross-server escalation PoC (email redirect)
- **Sampling Abuse**: Server → client LLM manipulation via `sampling/createMessage`
- **Protocol Attacks**: JSON-RPC state machine violations, oversized payloads

### Transport Modes
- `stdio` — Claude Desktop, Cursor, VS Code MCP integration
- `HTTP+SSE` — Remote testing, MCP Inspector, scanner compatibility
- `streamable-http` — Future transport testing

### Scanner Compatibility Targets
- Invariant mcp-scan
- Cisco MCP Scanner
- Proximity (open-source)
- mcpscan.ai
- Snyk agent-scan

### Docker Environments
- Single server (default)
- Multi-server lab (trusted server + malicious server for shadowing)
- Attacker simulation server (for offline prompt injection demos)

---

## Out of Scope

### What We Will NOT Build
- **Real credential theft**: All API keys, passwords, tokens are obviously fake values
- **Live network scanning**: No tools to scan external networks or probe live systems
- **Kernel exploits**: No privilege escalation beyond the training server process
- **Browser vulnerabilities**: No XSS, CSRF, or browser-specific attacks — MCP is not HTTP
- **Mobile clients**: No iOS/Android MCP client simulation
- **Real supply chain**: No code that actually pushes to npm/PyPI or modifies real packages
- **Cryptographic attacks**: No broken crypto, timing attacks, or certificate abuse
- **Social engineering**: No phishing simulations

### Technical Boundaries
- All destructive operations are either sandboxed (simulated) or Docker-isolated with hard resource limits
- No outbound internet connections in default deployment (`docker-compose.yml` internal-only mode available)
- No root execution — containers run as `training` user
- No persistence of exploits or flags outside the container lifetime

---

## Priority Matrix

| Vulnerability | Impact | Effort | Priority |
|--------------|--------|--------|----------|
| CVE-2025-6514 OAuth injection | Critical (maps to 9.6 CVSS real CVE) | Medium | P0 |
| Rug Pull mechanism | High (unique, no other lab has it) | High | P0 |
| Tool Shadowing PoC | High (84.2% success rate in research) | Medium | P0 |
| Git RCE chain (68145/43/44) | Critical (Anthropic official server CVE) | High | P1 |
| Sampling abuse | High (Unit42 research, novel attack) | Medium | P1 |
| Scanner compatibility tests | Medium (validates other tools) | Low | P1 |
| Cross-client leak (CVE-2026-25536) | Medium | Low | P2 |
| Protocol-level attacks | Medium | High | P2 |
| Web dashboard | Low (nice-to-have) | High | P3 |

---

## Definition of Done (per challenge)

A challenge is complete when:
1. The exploit works as documented in `challenges/*.yaml`
2. `submit_flag(challenge_id, flag)` returns CORRECT
3. `MCP_SANDBOX=true` safely simulates the attack without real damage
4. The challenge YAML has: description, objective, exploitation_steps, 3 hints, CVE/CWE, remediation
5. The remediation guide describes the actual code fix
6. At least one scanner in the compatibility suite detects the vulnerability
