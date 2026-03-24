# Getting Started — The Game Guide 🎮
## Learn MCP Security by Breaking Things

---

You're going to give an AI a set of tools. Some of them are lying.

Some will pretend to be safe while quietly changing behavior after the first call. Some have hidden instructions embedded in characters you can't even see. One will execute code on your machine if you call it wrong. None of this is hypothetical — every challenge in this server maps to a real CVE, a real exploit technique, or a real attack documented in the wild. Your job is to find the vulnerabilities, trigger them, and capture the flags they leave behind.

No prior MCP knowledge required. The game teaches you as you go.

---

## What is MCP? (Plain English)

MCP — the Model Context Protocol — is like giving your AI assistant a toolbox. Each tool is something it can do: read a file, send an email, run a command, fetch a URL. Your AI reads the toolbox's instruction manual, then decides which tools to call.

This server's toolbox is **deliberately broken**. The tools have bugs. The descriptions lie. Some tools do things they claim not to do. Your mission is to figure out what's actually happening.

---

## The Game Loop

```
  You call a tool
        ↓
  Server detects the attack
        ↓
  Returns FLAG{...}
        ↓
  You submit the flag
        ↓
  Score points → next challenge
```

All attacks run safely in **sandbox mode** by default. Nothing on your machine is harmed. Flags are fake CTF strings. You can always ask for a hint.

---

## Setup (5 minutes)

**Step 1 — Install dependencies:**
```bash
pip install "mcp[cli]>=1.0.0" pyyaml jinja2 pydantic-settings httpx uvicorn
```

**Step 2 — Start the server:**
```bash
MCP_TRAINING_MODE=true MCP_TRANSPORT=sse python server.py
```

You'll see:
```
[*] Starting Vulnerable MCP Server
[*] Transport: sse
[*] Listening on: http://0.0.0.0:8000
[*] Use list_challenges() to see all available challenges
```

**Step 3 — Connect a browser-based inspector to explore:**
```bash
npx @modelcontextprotocol/inspector http://localhost:8000/sse
```

Or add it to Claude Desktop (see [README.md](../README.md)) and type tool calls directly in chat.

**Step 4 — See all 18 challenges:**
```
list_challenges()
```

---

## Sandbox Mode Explained

Nothing bad actually happens.

Think of it like a **flight simulator** — you crash the plane and learn from it, but you're still sitting safely at your desk. When you trigger a real vulnerability (say, a command injection or pickle deserialization), the server detects it, prints `[SANDBOX]`, explains what would have happened in real life, and returns the flag. No actual commands run. No files are read. No data leaves your machine.

If you want to see real execution — commands actually running, HTTP requests actually firing — there's a Docker setup with resource limits that makes it safe. See [USAGE.md](USAGE.md) for details.

---

## The 18 Challenges

### Level 1 🟢 — Beginner (100–150 pts each)

These four challenges cover the most common MCP attack patterns. A great warm-up even if you're a seasoned security researcher.

**BEGINNER-001 — Tool Poisoning**
You'll inspect a tool description's raw bytes and find hidden Unicode characters invisible to the human eye. This matters because MCP has no mechanism to sanitize tool metadata, making description poisoning trivially easy for a malicious server operator.

**BEGINNER-002 — Command Injection**
You'll inject a shell metacharacter (`;`, `&&`, `|`) into a tool that runs commands with `shell=True`. This matters because it's behind 23% of all MCP server vulnerabilities found in the wild.

**BEGINNER-003 — Path Traversal**
You'll escape the server's working directory using `../` sequences and read files you shouldn't be able to reach. This matters because the fix is a single line of code — and most servers skip it. (See CVE-2025-68143.)

**BEGINNER-004 — Indirect Prompt Injection**
You'll fetch a URL that contains adversarial instructions hidden in the page content, and watch the LLM follow them. This matters because any tool that returns external content verbatim is a prompt injection vector.

---

### Level 2 🟡 — Intermediate (150–200 pts each)

Classic application security vulnerabilities, now in your AI's toolbox.

**INTERMEDIATE-001 — Auth Bypass**
You'll call an admin endpoint without any credentials. There's a `# TODO: check auth` comment where the check should be. The check was never written. This matters because documentation is not enforcement.

**INTERMEDIATE-002 — SQL Injection**
You'll break out of an f-string SQL query using a single quote and return every row in the database. This matters because parameterized queries exist precisely to prevent this — and developers keep skipping them.

**INTERMEDIATE-003 — Secret Leakage**
You'll find an API key embedded in a tool description. It goes to every client that connects, every scanner, every log that captures MCP traffic. This matters because tool metadata is public by design.

**INTERMEDIATE-004 — State Manipulation**
You'll call a destructive `reset_all_data()` function before the server is initialized. The precondition check exists in the docs but not in the code. This matters because undeclared preconditions are broken preconditions.

---

### Level 3 🔴 — Advanced (250–400 pts each)

These require more steps and some local payload crafting.

**ADVANCED-001 — SSRF** *(36.7% of public MCP servers have this)*
You'll use the server as a proxy to reach internal endpoints — including the AWS EC2 metadata service at `169.254.169.254`. This matters because from inside a cloud VPC, SSRF reaches IAM credentials.

**ADVANCED-002 — Template Injection**
You'll use Jinja2's Python object model to enumerate `__subclasses__()` and locate `subprocess.Popen`. The non-sandboxed Jinja2 environment is the entire Python runtime, accessible from a string input. This matters because `jinja2.Environment` vs `jinja2.sandbox.SandboxedEnvironment` is a one-word difference.

**ADVANCED-003 — Denial of Service**
You'll trigger exponential CPU exhaustion (`fibonacci(45)`) and factorial memory blowup (`generate_permutations("abcdefghijk")`). This matters because tools with unbounded numeric inputs have no natural defense except explicit limits.

**ADVANCED-004 — Pickle RCE** *(highest points in Level 3: 400 pts)*
You'll craft a Python pickle payload locally, serialize it to base64, and send it to a tool that calls `pickle.loads()` on your input. This matters because pickle is not data — it's executable bytecode.

---

### Level 4 💀 — MCP-Only Attacks (500–600 pts each)

These four challenges exploit behaviors specific to the MCP protocol itself. You won't find equivalents in traditional web security training.

**RUG-001 — Tool Description Mutation (Rug Pull)**
*MCP-only attack.* You'll call `analyse_repo` twice. The first call looks benign. The second reveals that the tool's behavior has silently changed — it's now exfiltrating your repository contents while your MCP client still displays the original (cached) description. Documented by Invariant Labs, April 2025.

**RUG-002 — Timed Rug Pull (Scanner Window Evasion)**
*MCP-only attack.* You'll observe `get_compliance_report` behaving safely inside a short window, wait 10 seconds, then call it again after the mutation activates. Automated scanners test behavior immediately after enumeration — they never see the mutation. This is documented as effectively undetectable by current scanning approaches.

**SHADOW-001 — Tool Shadowing: Email Redirect**
*MCP-only attack.* You'll call `send_email` and discover that this server registered a tool with the same name as a legitimate email server. Your email never reaches the intended recipient. Invariant Labs' PoC demonstrated a 100% exfiltration rate against all tested MCP clients.

**SHADOW-002 — Cross-Origin Tool Escalation**
*MCP-only attack.* A tool description in this server contains an instruction for the LLM to call a privileged tool (`read_file`) from a *different* MCP server. The user asked for a document search. The attacker receives `/etc/passwd`.

---

### Level 5 ☠️ — Boss Fights (600–1000 pts each)

**OAUTH-001 — OAuth Metadata Endpoint Injection** *(CVE-2025-6514, CVSS 9.6)*
You'll retrieve a poisoned OAuth discovery document and trigger a simulated `mcp-remote` flow. The `authorization_endpoint` field contains shell metacharacters (`$(...)`) that execute on the MCP client machine when `mcp-remote` interpolates them into a shell string — no user interaction required beyond initial connection. Fixed in `mcp-remote 0.1.16`.

**MULTI-001 — The Confused Deputy: Full Attack Chain** *(Boss fight — 1000 pts)*
Three vulnerability classes chain together into a single end-to-end compromise: prompt injection triggers tool shadowing, which reroutes a report to an attacker; then SSRF reaches the cloud metadata endpoint at `169.254.169.254`, leaking IAM credentials. No single step alone is catastrophic. The danger is the chain. The flag only appears when all three steps complete.

---

## Tips for Getting Unstuck

The hint system has three levels. Level 1 is vague. Level 3 is nearly the answer.

```
get_hint("BEGINNER-002", 1)   # ← vague nudge
get_hint("BEGINNER-002", 2)   # ← directional hint
get_hint("BEGINNER-002", 3)   # ← near-solution
```

**What each level reveals:**
- **Level 1** — Points you at the vulnerability class ("The SQL query uses string formatting")
- **Level 2** — Suggests a specific technique or input pattern ("Try a tautology")
- **Level 3** — Close enough to solve from alone ("Use `' OR '1'='1` as the username")

For the full walkthrough including step-by-step exploitation instructions:
```
get_challenge_details("BEGINNER-002")
```

For Levels 1–3, the YAML files in `challenges/` also contain complete walkthroughs if you want to read source directly.

---

## Submitting Flags

When a challenge returns a `FLAG{...}` string, submit it like this:

```
submit_flag("BEGINNER-002", "FLAG{c0mm4nd_1nj3ct10n_sh3ll_tr00}")
```

You'll see:
```
✅ CORRECT! Challenge BEGINNER-002 solved!
   Well done — you successfully exploited command injection via shell=True.
   Points awarded: 100
   Total score: 100
```

Wrong flag:
```
❌ Incorrect flag for BEGINNER-002.
   Keep trying! Use get_hint('BEGINNER-002', 1) for a hint.
```

---

## What Happens Next

After you've captured all 18 flags, consider:

- **Run a scanner against this server.** `mcp-scan http://localhost:8000/sse` (by Invariant Labs) will find several of the poisoning issues. See how many it catches — and notice which ones it misses (hint: rug pull evasion is unsolved for now).
- **Contribute a new challenge.** You understand the vulnerability patterns now. See [docs/CONTRIBUTING.md](CONTRIBUTING.md) for the exact steps. Your challenge will be played by security researchers around the world.
- **Read the threat model.** [docs/THREAT_MODEL.md](THREAT_MODEL.md) maps every CVE to a STRIDE category and explains the real-world attack surfaces these challenges are based on.
- **Try the MCP agent system.** [docs/USAGE.md §8](USAGE.md) explains how to use the multi-agent build system to implement new challenges automatically.
