# Contributing
## Adding Vulnerability Challenges to the Vulnerable MCP Server

Adding a challenge is a fun creative exercise — and a meaningful one. Your challenge will be played by security researchers around the world. Make it educational, not just tricky. The goal isn't to stump people; it's to leave them saying "I never thought about that attack surface before."

---

## Before You Start

1. Read [docs/PRD.md](PRD.md) — understand what makes a good challenge (CVE reference, exploitation steps, 3-level hints, remediation)
2. Read [docs/SCOPE.md](SCOPE.md) — understand what's in and out of scope
3. Look at an existing module for patterns — `vulnerabilities/injection.py` is the most complete example

---

## The 6-Step Pattern

### Step 1 — Write the vulnerability module

*Why this step exists:* The module is where the actual vulnerability lives. It defines what the tool does, how attacks are detected in sandbox mode, and what the real (dangerous) execution path is.

Create `vulnerabilities/your_vuln.py`:

```python
"""
YOUR-001: Brief description of the vulnerability.
CWE-XXX | CVE-XXXX-XXXXX (if applicable)
"""
from vulnerabilities.base import VulnerabilityModule, VulnerabilityMeta
from flags.flags import get_flag


class YourVulnModule(VulnerabilityModule):
    """One-line description of what this module demonstrates."""

    @property
    def metadata(self) -> list[VulnerabilityMeta]:
        return [
            VulnerabilityMeta(
                challenge_id="YOURCAT-001",
                title="Your Vulnerability Title",
                cwe="CWE-XXX",
                cvss=8.0,
                cve="CVE-XXXX-XXXXX",  # optional
            )
        ]

    def register(self) -> None:
        """Attach vulnerable tools to the FastMCP app."""

        @self.app.tool(
            description=(
                "Brief description of what this tool does. "
                "Does NOT mention it's vulnerable — that's for players to discover."
            )
        )
        def my_vulnerable_tool(user_input: str) -> str:
            """
            Docstring explains legitimate use case.
            The vulnerability: [explain what's wrong here for code readers]
            """
            if self.config.sandbox_mode:
                # Detect attack indicators
                if _is_attack(user_input):
                    return (
                        f"[SANDBOX] Vulnerability triggered!\n"
                        f"In real execution this would: [explain impact]\n\n"
                        f"Flag: {get_flag('YOURCAT-001')}"
                    )
                # Simulate benign output
                return f"[SANDBOX] Safe simulated output for: {user_input}"

            # Real execution path (MCP_SANDBOX=false, Docker only)
            return _actually_dangerous(user_input)  # VULNERABLE LINE


def _is_attack(user_input: str) -> bool:
    """Detect injection indicators in user input."""
    indicators = ["indicator1", "indicator2"]
    return any(ind in user_input for ind in indicators)
```

**Key rules:**
- Always check `self.config.sandbox_mode` first
- In sandbox mode: detect attack pattern → return flag + educational message; otherwise return simulated output
- The vulnerable code path must be clearly marked with a `# VULNERABLE LINE` comment
- Tool descriptions should describe legitimate behavior, not hint at vulnerabilities

---

### Step 2 — Add the flag

*Why this step exists:* All flags live in one registry so `submit_flag()` and the test suite can validate them without parsing individual modules.

Open `flags/flags.py` and add to the `_FLAGS` dict:

```python
_FLAGS = {
    # ... existing flags ...
    "YOURCAT-001": "FLAG{your_custom_fl4g_here}",
}
```

**Flag naming conventions:**
- Format: `FLAG{lowercase_with_1337_speak}`
- Must be unique — check all existing flags before choosing
- Should hint at the attack type (e.g., `FLAG{sql_1nj3ct10n_f_str1ng}`)
- No real credentials, no personally identifiable strings

---

### Step 3 — Write the challenge YAML

*Why this step exists:* The YAML is what players see when they call `get_challenge_details()`. It's also the source of truth for `get_hint()` and `submit_flag()`. Get the YAML right and the game experience is self-contained.

Create or append to `challenges/yourcategory.yaml`:

```yaml
challenges:
  - id: YOURCAT-001
    title: "Your Challenge Title"
    category: your_category
    difficulty: intermediate          # beginner | intermediate | advanced
    cwe: CWE-XXX
    cvss: 8.0
    points: 200                       # 100 beginner, 150-200 intermediate, 250-400 advanced
    tools:
      - my_vulnerable_tool
    description: |
      Explain the vulnerability in 3-5 sentences. What is the vulnerable pattern?
      Why does it exist? What can an attacker do with it?
    objective: |
      What must the player do to solve this challenge? Be specific about the goal
      (not the steps — those are in exploitation_steps).
    exploitation_steps:
      - "Step 1: Call my_vulnerable_tool('normal_input') to understand baseline behavior"
      - "Step 2: Try the injection technique: my_vulnerable_tool('attack_indicator')"
      - "Step 3: Observe the sandbox detects it and returns the flag"
      - "Step 4: Submit the flag with submit_flag('YOURCAT-001', 'FLAG{...}')"
    hints:
      - level: 1
        text: "Conceptual hint — points toward the vulnerability class without giving it away"
      - level: 2
        text: "Directional hint — suggests a specific technique or input pattern"
      - level: 3
        text: "Near-solution hint — almost tells them exactly what to type"
    flag: "FLAG{your_custom_fl4g_here}"
    remediation: |
      - What the secure version of the code looks like (be specific)
      - Which library or Python builtin prevents this
      - Code snippet showing the fix
      - Any relevant secure-by-default alternative
```

**Quality bar for YAML:**
- Exploitation steps must be runnable as written — no vague "try something"
- Level 3 hint should be close enough that a player can solve the challenge from it alone
- Remediation must reference actual code (function names, library names), not just concepts

---

### Step 4 — Register the module

*Why this step exists:* `server.py` loads modules from `ALL_MODULES` at startup. Until your module is in this list, the server doesn't know it exists.

Open `vulnerabilities/__init__.py` and add your module to `ALL_MODULES`:

```python
from vulnerabilities.your_vuln import YourVulnModule

ALL_MODULES = [
    ToolPoisoningModule,
    InjectionModule,
    AuthModule,
    ExfiltrationModule,
    PromptInjectionModule,
    DoSModule,
    YourVulnModule,  # ← append here
]
```

Order doesn't matter for functionality, but keeping related modules together helps readability.

---

### Step 5 — Verify the challenge works

*Why this step exists:* It's easy to have a module that registers correctly but returns the wrong flag, or triggers on the wrong input, or doesn't appear in `list_challenges()`. This script checks all five things in one pass.

```bash
# Start the server
MCP_TRAINING_MODE=true MCP_TRANSPORT=sse python server.py &

# Run a quick verification script
python -c "
import asyncio
from mcp.client.sse import sse_client
from mcp import ClientSession

async def verify():
    async with sse_client('http://localhost:8000/sse') as (r, w):
        async with ClientSession(r, w) as s:
            await s.initialize()

            # 1. Verify tool appears in list
            tools = await s.list_tools()
            tool_names = [t.name for t in tools.tools]
            assert 'my_vulnerable_tool' in tool_names, 'Tool not registered'
            print('✓ Tool appears in tools/list')

            # 2. Verify normal input returns safe output
            result = await s.call_tool('my_vulnerable_tool', {'user_input': 'normal'})
            assert 'FLAG{' not in result.content[0].text, 'Flag should not appear for normal input'
            print('✓ Normal input does not trigger flag')

            # 3. Verify attack input returns flag
            result = await s.call_tool('my_vulnerable_tool', {'user_input': 'attack_indicator'})
            assert 'FLAG{your_custom_fl4g_here}' in result.content[0].text, 'Flag not returned for attack input'
            print('✓ Attack input returns correct flag')

            # 4. Verify flag submission works
            result = await s.call_tool('submit_flag', {
                'challenge_id': 'YOURCAT-001',
                'flag': 'FLAG{your_custom_fl4g_here}'
            })
            assert 'CORRECT' in result.content[0].text
            print('✓ Flag submission accepted')

            # 5. Verify hints are accessible
            result = await s.call_tool('get_hint', {'challenge_id': 'YOURCAT-001', 'hint_level': 1})
            assert 'not found' not in result.content[0].text
            print('✓ Hints accessible')

            print()
            print('All checks passed. Challenge is ready.')

asyncio.run(verify())
"
```

---

### Step 6 — Write Tests

*Why this step exists:* Tests are how future contributors know your challenge still works after a refactor. They also serve as living documentation — a new contributor reading your test class immediately understands the attack mechanics without running anything.

Every new challenge needs tests in the appropriate tier file (`tests/test_beginner.py`, `tests/test_intermediate.py`, `tests/test_advanced.py`) or a new file (e.g., `tests/test_yourcat.py`).

#### Full worked example

Here's a complete test class for a hypothetical `YOURCAT-001` SQL injection challenge:

```python
import pytest
from tests.helpers import ToolCapture, assert_flag, assert_no_flag, assert_sandboxed
from vulnerabilities.your_vuln import YourVulnModule


@pytest.fixture
def capture(sandbox_config):
    """
    sandbox_config comes from tests/conftest.py — it's a Config object
    with sandbox_mode=True and training_mode=True.
    ToolCapture is the fake FastMCP app that captures tool registrations.
    """
    cap = ToolCapture()
    YourVulnModule(cap, sandbox_config).register()
    return cap


class TestYOURCAT001:
    """
    Tests for YOURCAT-001 — My Vulnerability Title.

    Attack pattern: [describe in one sentence what the exploit does]
    Trigger: [what input causes the flag to appear]
    """

    def test_tool_registered(self, capture):
        """The tool must appear in the tool registry after register() is called."""
        assert capture.has_tool("my_vulnerable_tool")

    async def test_safe_input_no_flag(self, capture):
        """Normal input must never accidentally emit a FLAG{} string."""
        result = await capture.call("my_vulnerable_tool", user_input="normal_input")
        assert_no_flag(result)

    async def test_attack_triggers_sandbox(self, capture):
        """
        Attack input must be intercepted by the sandbox.
        [SANDBOX] in the output confirms the sandbox ran, not the real code path.
        """
        result = await capture.call("my_vulnerable_tool", user_input="attack_indicator")
        assert_sandboxed(result)

    async def test_attack_returns_correct_flag(self, capture):
        """
        The flag returned must match the one registered for YOURCAT-001.
        assert_flag() looks up the expected value from flags/flags.py automatically.
        """
        result = await capture.call("my_vulnerable_tool", user_input="attack_indicator")
        assert_flag(result, "YOURCAT-001")

    async def test_multiple_attack_variants(self, capture):
        """
        If your vulnerability has multiple exploit patterns,
        test each one — they should all trigger the flag.
        """
        variants = ["attack_indicator", "another_variant", "third_pattern"]
        for payload in variants:
            result = await capture.call("my_vulnerable_tool", user_input=payload)
            assert_flag(result, "YOURCAT-001"), f"Variant {payload!r} did not trigger flag"
```

#### How ToolCapture works

`ToolCapture` is a fake FastMCP app that captures `@app.tool()` registrations without starting a server:

```python
cap = ToolCapture()
mod = YourVulnModule(cap, config)
mod.register()                        # @app.tool() calls are captured here
result = await cap.call("tool_name", arg="value")  # calls the function directly
```

No network. No ports. No process management. The test suite runs 515 tests in under 5 seconds because of this pattern.

#### Required assertions

| Assertion | Purpose |
|-----------|---------|
| `assert_sandboxed(result)` | Confirms sandbox intercepted the call (`[SANDBOX]` in output) |
| `assert_no_flag(result)` | Safe input must never accidentally emit any `FLAG{}` string |
| `assert_flag(result, "YOURCAT-001")` | Attack input returns the correct flag for this challenge |

All three helpers are importable from `tests/helpers.py`.

#### Reusable attack payloads

`tests/fixtures/payloads.py` contains pre-built payloads for common vulnerability classes (SQL injection, path traversal, shell injection, SSTI, etc.). Use these instead of inline strings where possible — it keeps tests consistent and makes payloads easy to extend.

If your vulnerability type is new and no matching payloads exist, add them to `tests/fixtures/payloads.py` so future contributors can reuse them.

#### Run your tests

```bash
MCP_TRAINING_MODE=true MCP_SANDBOX=true python -m pytest tests/test_yourcat.py -v
```

---

## Challenge Quality Checklist

Before submitting a PR, verify all of these:

- [ ] Tool is registered in `vulnerabilities/__init__.py`
- [ ] Flag is in `flags/flags.py` and unique
- [ ] Challenge YAML has all required fields: id, title, category, difficulty, cwe, cvss, points, tools, description, objective, exploitation_steps, hints (3 levels), flag, remediation
- [ ] Sandbox mode: normal input returns simulated output (not a flag)
- [ ] Sandbox mode: attack input returns the flag
- [ ] `MCP_SANDBOX=false` path exists and is clearly marked
- [ ] Tool description does not leak that it's vulnerable
- [ ] All credentials/keys are obviously fake (prefix with `fake_`, `FAKE`, `training-`, etc.)
- [ ] Verification script passes all 5 checks
- [ ] Pytest unit tests written with at least: `test_tool_registered`, `test_safe_input_no_flag`, `test_attack_triggers_sandbox`, `test_attack_returns_correct_flag`
- [ ] `MCP_TRAINING_MODE=true MCP_SANDBOX=true python -m pytest tests/ -q` passes with no new failures
- [ ] Challenge maps to a real CWE
- [ ] CVE reference included if applicable
- [ ] Remediation guide references specific code/libraries (not just concepts)

---

## What Makes a Great Challenge

> **Has a real-world analogy.** What would this vulnerability look like in a production system? The best challenges make players think "I've seen this in real code" — not "I've seen this in a CTF." SQL injection via f-strings happens in production Python services daily. Rug pull attacks were confirmed against Claude Desktop. Make the scenario feel real.

> **Educational output.** When the sandbox triggers, the response should explain what happened and why it's dangerous. Don't just return a flag. Say: "In real execution, `subprocess.run(cmd, shell=True)` would have executed `whoami` on the server. This is the same class of vulnerability as CVE-2025-6514 (CVSS 9.6)." Players should feel smarter after reading the flag response.

> **Three hints that genuinely help without giving it away.** Level 1 should point at the vulnerability class. Level 2 should suggest a technique. Level 3 should be close enough to solve from alone. A bad Level 3 hint is "use SQL injection." A good Level 3 hint is: "Use `' OR '1'='1` as the username. The resulting WHERE clause will always be true."

> **Remediation that developers can actually implement.** Don't write "sanitize your inputs." Write: "Replace the f-string query with `cursor.execute('SELECT * FROM users WHERE username = ?', (username,))`. The `?` placeholder means the database driver handles escaping — user input never touches the SQL structure." Link to the library. Show the fixed code. Make the remediation copy-pasteable.

---

## CVE-Accurate Challenges

If your challenge maps to a real CVE, the implementation must reproduce the actual vulnerability mechanism (not just a similar class). Read the CVE advisory and linked PoC before implementing.

CVE-accurate challenges go in `challenges/cve_accurate.yaml` once created.

For Phase 2 CVE targets, see [docs/ROADMAP.md](ROADMAP.md#phase-1--cve-accuracy-q2-2026).

---

## Using the Agent System to Implement a Challenge

The coding agent can write the module for you:

```bash
python agents/dashboard.py --run "Implement OAUTH-001 challenge:
- OAuth metadata endpoint returning malicious authorization_endpoint URL
- Maps to CVE-2025-6514 (CVSS 9.6, mcp-remote command injection)
- See docs/PRD.md section 4.4 for requirements
- Follow VulnerabilityModule pattern in vulnerabilities/base.py"
```

The orchestrator will: plan → code → test → docs. You review the output and merge.

---

## Submitting a PR

1. Fork the repo
2. Create a branch: `git checkout -b add-YOURCAT-001`
3. Implement all 6 steps above
4. Run the verification script
5. Commit: `git commit -m "feat: add YOURCAT-001 (Your Vulnerability Title)"`
6. Open a PR with:
   - Challenge ID and title in PR title
   - CVE/CWE references
   - Screenshot or paste of the verification script passing
   - Brief explanation of what the vulnerability teaches
