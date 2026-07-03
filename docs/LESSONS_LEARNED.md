# Lessons Learned

A running log of concrete findings from working on this repo — positioning
mistakes, technical gotchas, and process decisions worth remembering before
repeating them. Entries are appended as new work surfaces them; nothing here
is retroactively edited except to fix a factual error.

Format: newest entries at the top. Each entry says what happened, why it
mattered, and what to do differently.

---

## 2026-07-03 — Unverifiable positioning claims erode credibility faster than missing features

**What happened:** The README claimed this was "the world's first deliberately
vulnerable MCP server" and that it was "designed to be a named test target"
for MCP security scanners. Neither claim was true or verifiable. Competitive
research found a competitor (`damn-vulnerable-MCP-server`) predating this
project by roughly a year with over 1,300 stars, and found no scanner
(mcp-scan, Cisco MCP Scanner, Proximity) publicly naming *any*
vulnerable-MCP-server project as a target.

**Why it mattered:** The exact audience this project targets — security
researchers — is the audience most likely to fact-check a claim like "world's
first" and lose trust in everything else the README says once it's found
false. A false claim costs more credibility than an honest, more modest one
gains in perceived prestige.

**What to do differently:** Before writing a superlative or a claim about
external validation ("first," "named target," "used by X"), verify it. If it
can't be verified, either drop it or phrase it as a stated goal, not a fact
("designed as a compatibility test target," not "is a named test target").

---

## 2026-07-03 — More content is not always the highest-leverage next step

**What happened:** The initial instinct (and the project's own ROADMAP.md)
was to keep adding challenges — a GIT CVE chain, MCP sampling abuse,
protocol-level attacks. Competitive research showed this niche has a real
ceiling (~1,300 stars for the market leader, itself stale for 7 months) and
is fragmenting across many small forks rather than consolidating around one
project. Meanwhile, no competitor had a working remediation/observability
layer — the thing the project's own Phase 4 backlog had already identified
but never built.

**Why it mattered:** Shipping the 19th–21st challenge would have been safe,
familiar work with very low marginal payoff. Shipping the untested
differentiator (Learning Mode / `show_fix()`) was the same amount of effort
for a much higher chance of mattering.

**What to do differently:** Before defaulting to "add more of what's already
here," check whether the next unit of the same thing is actually the
constraint, or whether it's a different, unbuilt capability. A quick
competitive scan is cheap; building the wrong thing well is not.

---

## 2026-07-03 — Don't reach into a dependency's private internals from tests

**What happened:** An early version of `tests/test_remediation.py` accessed
`app._tool_manager._tools` to grab tool callables directly out of a
`FastMCP` instance, bypassing the public API. A PR review (Greptile) flagged
this: `_tool_manager` and `_tools` are undocumented implementation details,
and if FastMCP ever reorganizes tool storage, every test using that fixture
fails with a confusing `AttributeError` instead of a meaningful message.

**Why it mattered:** The fix was easy once flagged, but it shouldn't have
needed flagging — `FastMCP` already exposes `list_tools()` and `call_tool()`
as public, documented, protocol-accurate ways to exercise a registered tool.

**What to do differently:** When a test needs to reach "one level deeper"
than a library's public API offers, that's a signal to check for an existing
public method first (often named `list_*`/`get_*`/`call_*`), not to reach
for the underscored attribute that happens to hold the same data.

---

## 2026-07-03 — Check the declared dependency floor, not just the installed version

**What happened:** The same test code above, once fixed to use
`app.call_tool()`, destructured its return value as `content, _ = await
app.call_tool(...)`. That only works for `mcp>=1.9.5`, which changed
`call_tool()`'s return shape from a plain `Sequence[ContentBlock]` to a
`(Sequence[ContentBlock], dict)` tuple. `pyproject.toml` only requires
`mcp[cli]>=1.0.0`, so any environment pinned to an older `mcp` version would
have failed every test in that class immediately, despite the locally
installed version (1.28.1) working fine.

**Why it mattered:** Testing against "whatever happens to be installed
locally" silently assumes the loosest declared constraint in `pyproject.toml`
is never actually exercised. It usually will be, eventually, by someone.

**What to do differently:** When writing code (or tests) against a
dependency's API, check the version range the project actually declares
(`pyproject.toml`, `requirements.txt`), not just what `pip show` reports
locally. If an API's behavior changed within that declared range, either
raise the floor deliberately (a real dependency decision, not a side effect
of a test) or handle both shapes defensively — whichever has the smaller
blast radius for the change at hand.

---

## 2026-07-03 — `yaml.safe_load()` returns `None` for empty/comment-only files

**What happened:** `_find_challenge()` (and, latently, the pre-existing
`get_hint()`/`get_challenge_details()` code it replaced) called
`data.get("challenges", [])` immediately after `yaml.safe_load(f)`. An empty
or comment-only YAML file makes `safe_load` return `None`, and `None.get(...)`
raises `AttributeError` — crashing the lookup for every challenge checked
after that file in iteration order, not just the empty one.

**Why it mattered:** This was a real, if narrow, robustness gap that existed
in the codebase before this change and was only caught because a new
function (`_find_challenge`) consolidated the pattern into one place a
reviewer could scrutinize closely. Extracting duplicated logic doesn't just
reduce line count — it concentrates latent bugs where they're easier to spot.

**What to do differently:** After any `yaml.safe_load()` (or similarly
permissive parse) on a file whose contents aren't fully controlled by the
calling code, guard with `isinstance(data, dict)` (or the expected type)
before calling methods on the result. Also: always pass `encoding="utf-8"`
explicitly to `open()` for files that may contain non-ASCII text — the
locale-default encoding (e.g. `cp1252` on Windows) is not guaranteed to match
the file's actual encoding.

---

## 2026-07-03 — Extract shared logic once it's duplicated a third time, not before

**What happened:** `server.py` had the same "loop over challenge YAML files,
parse each, find the entry with a matching ID" logic written out fully in
both `get_hint()` and `get_challenge_details()`. Adding `show_fix()` would
have made it a third copy. Instead, it was extracted into `_find_challenge()`
and all three tools were updated to call it.

**Why it mattered:** Two copies of ~8 lines is a defensible amount of
duplication — refactoring it earlier would have been premature abstraction
for a pattern that might not have repeated. A third copy is a different
signal: the duplication is now a real maintenance cost, and extracting it
made the (pre-existing) empty-YAML bug above visible in one place instead of
two silently duplicated exposures.

**What to do differently:** Don't reach for a shared helper the first time
logic repeats — but don't let it hit three copies unexamined either. Treat
the third occurrence of the same block as the trigger to consolidate, not a
number to remember, but a signal you'll cross when it's already right in
front of you.
