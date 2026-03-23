# Roadmap — Vulnerable MCP Server

> Based on gap analysis of existing projects, disclosed CVEs, and published attack research (March 2026).

---

## Competitive Landscape

### Existing Projects

| Project | Challenges | Stack | Key Gaps |
|---------|-----------|-------|----------|
| [appsecco/vulnerable-mcp-servers-lab](https://github.com/appsecco/vulnerable-mcp-servers-lab) | 9 servers | JS/Python | No auth bypass, no DoS, no sampling abuse, no rug pull, no OAuth |
| [harishsg993010/damn-vulnerable-MCP-server](https://github.com/harishsg993010/damn-vulnerable-MCP-server) | 10 challenges | Python/Docker | No supply-chain simulation, no protocol-level attacks, no CVE-accurate scenarios |
| [kenhuangus/mcp-vulnerable-server-demo](https://github.com/kenhuangus/mcp-vulnerable-server-demo) | Demo only | Python | Proof-of-concept, not structured for learning |
| [vineethsai/vulnerablemcp](https://github.com/vineethsai/vulnerablemcp) | DB of ~50 vulns | Static DB | No interactive server, no exploitable challenges |

### What None of Them Cover

- CVE-accurate challenge scenarios (CVE-2025-6514, CVE-2025-68145/68143/68144 chain)
- Rug pull mechanism with dynamic tool mutation mid-session
- MCP Sampling abuse (server → client LLM manipulation)
- Cross-server tool shadowing with real PoC
- OAuth authorization flow injection (the CVE-2025-6514 attack vector)
- Multi-server cross-origin escalation
- Protocol-level attacks (malformed JSON-RPC, state manipulation)
- Compatibility with existing scanners (mcp-scan, Cisco scanner, Proximity) as a named target
- Observability into what each attack does to the protocol layer

---

## Threat Landscape (Real CVEs and Research)

### Disclosed CVEs (as of March 2026)

| CVE | CVSS | Product | Mechanism |
|-----|------|---------|-----------|
| CVE-2025-6514 | **9.6** | mcp-remote 0.0.5–0.1.15 | OS command injection via OAuth `authorization_endpoint` URL manipulation |
| CVE-2025-6515 | High | mcp-remote | Prompt hijacking / session hijacking in OAuth flow |
| CVE-2025-49596 | Critical | MCP Inspector (official dev tool) | Unauthenticated RCE via inspector–proxy architecture |
| CVE-2025-53967 | Critical | Framelink Figma MCP Server | RCE via unsanitized input |
| CVE-2025-68143 | High | Anthropic mcp-server-git | `git_init` accepts arbitrary paths → turn `~/.ssh` into a git repo |
| CVE-2025-68144 | High | Anthropic mcp-server-git | Argument injection in `git_diff` / `git_checkout` |
| CVE-2025-68145 | High | Anthropic mcp-server-git | `--repository` flag path validation bypass |
| CVE-2026-25536 | 7.1 | MCP TypeScript SDK 1.10.0–1.25.3 | Cross-client response leak across session boundaries |
| Unpatched | High | Microsoft MarkItDown MCP | SSRF to AWS EC2 metadata service (169.254.169.254) |

**Chained RCE (CVE-2025-68145 + 68143 + 68144):**
```
Prompt injection in README/issue
  → path bypass (68145) to reach outside --repository scope
  → git_init (68143) targets ~/.ssh directory
  → write malicious .git/config with shell hook via Filesystem MCP
  → git_diff (68144) triggers hook → arbitrary command execution
```

### Published Attack Techniques

| Attack | Source | Key Metric |
|--------|--------|-----------|
| Tool Poisoning | Invariant Labs (Apr 2025) | 84.2% success with auto-approval enabled |
| Tool Shadowing / Cross-Origin Escalation | Invariant Labs | Email redirect PoC: 100% of test runs exfiltrated |
| Rug Pull (dynamic mutation) | Multiple researchers | Undetectable if poisoned at first `tools/list` |
| MCP Sampling Abuse | Palo Alto Unit42 (Dec 2025) | Server becomes active prompt author; persistent session infection |
| SSRF prevalence | JFrog / Wiz | 36.7% of public MCP servers have latent SSRF exposure |
| Command injection prevalence | mcp-scan scan of 50+ servers | 23% contained some form of command injection |
| Confused Deputy / Indirect Exfil | arXiv 2302.12173 (Greshake et al.) | LLM uses legitimately granted tools to exfiltrate data via injected instructions in fetched content |
| CI/CD Poisoning via GitHub MCP | Invariant Labs / community research | PR-based injection targeting developer workflows; supply chain impact radius |

---

## Milestones

### Phase 0 — Foundation (DONE)
- [x] Basic server with 12 vulnerabilities (Tier 1/2/3)
- [x] CTF flag system (submit_flag, get_hint, list_challenges)
- [x] Sandbox mode + training mode gate
- [x] Docker + docker-compose
- [x] Multi-agent build system (orchestrator, coding, debugging, testing, docs agents)
- [x] Real-time agent observability dashboard (Rich TUI)
- [x] Game-style walkthrough docs (GETTING_STARTED.md, USAGE.md, CONTRIBUTING.md)
- [x] Threat model with CVE-accurate attack chains and arXiv references

### Phase 1 — CVE Accuracy (Q2 2026)

**Goal:** Each challenge maps to a real CVE or published PoC. Security researchers can use this to test scanner accuracy.

| Challenge | Maps To | What to Build |
|-----------|---------|---------------|
| OAUTH-001 | CVE-2025-6514 | OAuth metadata endpoint that returns malicious `authorization_endpoint` URL containing command injection payload |
| OAUTH-002 | CVE-2025-6515 | Session token hijacking via OAuth state parameter reuse |
| GIT-001 | CVE-2025-68145 | `git_ops` tool with `--repository` flag that doesn't validate path scope |
| GIT-002 | CVE-2025-68143 | `git_init` accepting `~/.ssh` as target directory |
| GIT-003 | CVE-2025-68144 | `git_diff` with unsanitized argument passthrough |
| SDK-001 | CVE-2026-25536 | Multi-session server where responses leak across client boundaries |
| SSRF-002 | MarkItDown unpatched | URL fetcher that reaches 169.254.169.254 metadata endpoint |

**Deliverables:**
- `vulnerabilities/oauth.py` — OAuth flow vulnerabilities
- `vulnerabilities/git_ops.py` — Git MCP server RCE chain
- `vulnerabilities/session.py` — Cross-client session leak
- Update challenge YAML files with CVE references
- CI test: verify each challenge flag is reachable

### Phase 2 — Advanced MCP-Specific Attacks (Q2-Q3 2026)

**Goal:** Cover attacks that are unique to MCP architecture (not generic web vulns).

| Challenge | Attack Type | Description |
|-----------|------------|-------------|
| RUG-001 | Rug Pull | Tool description mutates after `tools/list` is cached. Second invocation gets malicious instructions |
| RUG-002 | Rug Pull + Evasion | Tool hashes change only after a timed delay to evade initial scanner pass |
| SHADOW-001 | Tool Shadowing | Malicious MCP server registered alongside trusted email server; shadows `send_email` to redirect all mail |
| SHADOW-002 | Cross-Origin Escalation | Server B tool description references Server A's tool by name and modifies its behavior |
| SAMPLE-001 | Sampling Abuse | Server sends `sampling/createMessage` to client LLM with injected system prompt that persists across all subsequent requests |
| SAMPLE-002 | Resource Theft via Sampling | Sampling request causes client to generate content that consumes API credits on attacker's behalf |
| PROTO-001 | JSON-RPC State Manipulation | Call `tools/call` before `initialize` to trigger undefined behavior |
| PROTO-002 | Oversized Payload | Send 100MB JSON-RPC message to exhaust memory |
| MULTI-001 | Multi-Vector Chain | Combines SHADOW-001 + SAMPLE-001 + BEGINNER-004 in a single attack chain |
| CI-001 | CI/CD Poisoning via GitHub MCP | PR with injected README payload causes agent to modify `.github/workflows/deploy.yml`; demonstrates confused deputy + indirect prompt injection at supply chain scale |

**Deliverables:**
- `vulnerabilities/rug_pull.py` — dynamic tool mutation engine
- `vulnerabilities/tool_shadowing.py` — cross-server escalation
- `vulnerabilities/sampling.py` — sampling request abuse
- `vulnerabilities/protocol.py` — JSON-RPC protocol attacks
- `vulnerabilities/github_mcp.py` — CI/CD poisoning simulation
- `multi_server/` — second MCP server (trusted) for cross-origin demos

### Phase 3 — Scanner Compatibility (Q3 2026)

**Goal:** This server should be a named, known target for mcp-scan, Cisco scanner, Proximity, and mcpscan.ai. When you run any of these against our server, it should find the expected vulnerabilities.

| Scanner | Expected Findings | Our Server Must |
|---------|------------------|-----------------|
| mcp-scan (Invariant) | Prompt injection in descriptions, tool shadowing, rug pull | Have detectable patterns in tool descriptions that trigger Invariant Guardrails |
| Cisco MCP Scanner | YARA rule matches, LLM-as-judge flagging | Include known malicious patterns that Cisco's YARA rules match |
| Proximity | Tool/resource risk scoring | Expose tools with clear risk indicators per Proximity's scoring model |
| mcpscan.ai | SSRF, injection, excessive scope | Include all category types that mcpscan.ai reports on |

**Deliverables:**
- `tests/scanner_compat/` — test suite that runs each scanner and asserts expected findings
- `tests/scanner_compat/test_mcp_scan.py`
- `tests/scanner_compat/test_cisco_scanner.py`
- `tests/scanner_compat/test_proximity.py`
- Scanner compatibility badge in README

### Phase 4 — Observability and Learning (Q4 2026)

**Goal:** Make this a teaching tool, not just an exploit target.

| Feature | Description |
|---------|-------------|
| Protocol inspector | Side-by-side view of JSON-RPC messages during exploitation |
| Attack trace logger | Each tool call records: method, params, result, injection_detected |
| Remediation mode | Toggle a flag to fix each vulnerability and see how the attack fails |
| Score dashboard | Web UI showing which challenges have been completed |
| Learning mode | After each successful exploit, show the diff between vulnerable and secure code |

**Deliverables:**
- `observability/trace_logger.py` — per-request attack tracing
- `observability/protocol_inspector.py` — JSON-RPC introspection
- `web/` — React dashboard (challenges, scores, protocol traces)

---

## Out of Scope (Intentionally)

- Actual credential stealing from real systems (all credentials are fake)
- Network scanning or lateral movement (not MCP-specific)
- Exploits requiring kernel-level access
- Cryptographic implementation flaws
- Mobile MCP clients

---

## Success Metrics

1. **Scanner hit rate**: mcp-scan finds ≥ 8 of our 12 Tier 1/2 vulnerabilities
2. **CVE accuracy**: Each Phase 1 challenge is confirmed exploitable by the same technique as the real CVE
3. **GitHub stars**: Target 500 stars within 6 months of launch (comparable to appsecco lab)
4. **Community**: At least 5 external vulnerability contributions within 3 months
5. **CTF use**: Used in at least 2 external CTF events

---

## References

- [CVE-2025-6514 - JFrog Research](https://research.jfrog.com/vulnerabilities/mcp-remote-command-injection-rce-jfsa-2025-001290844/)
- [Tool Poisoning Attacks - Invariant Labs](https://invariantlabs.ai/blog/mcp-security-notification-tool-poisoning-attacks)
- [MCP Attack Vectors - Palo Alto Unit42](https://unit42.paloaltonetworks.com/model-context-protocol-attack-vectors/)
- [Anthropic Git MCP CVEs - The Hacker News](https://thehackernews.com/2026/01/three-flaws-in-anthropic-mcp-git-server.html)
- [VulnerableMCP Database](https://vulnerablemcp.info/)
- [MCP Security Checklist - SlowMist](https://github.com/slowmist/MCP-Security-Checklist)
- [Awesome MCP Security - Puliczek](https://github.com/Puliczek/awesome-mcp-security)
- [ETDI Paper (Rug Pull mitigation)](https://arxiv.org/abs/2506.01333v1)
- [Systematic Analysis of MCP Security - arxiv](https://arxiv.org/html/2508.12538v1)
