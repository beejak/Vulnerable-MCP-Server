"""
Injection Vulnerabilities:

BEGINNER-002:     Command Injection          (CWE-78)  — subprocess shell=True
BEGINNER-003:     Path Traversal            (CWE-22)  — unsanitized file paths
INTERMEDIATE-002: SQL Injection             (CWE-89)  — f-string query formatting
ADVANCED-002:     Template Injection        (CWE-94)  — unsandboxed Jinja2
ADVANCED-004:     Pickle Deserialization RCE (CWE-502) — pickle.loads on user input
"""
import base64
import pickle
import sqlite3
import subprocess

from jinja2 import BaseLoader, Environment

from flags.flags import get_flag
from vulnerabilities.base import Hint, VulnerabilityMeta, VulnerabilityModule

# In-memory SQLite DB singleton — seeded once, reused across calls
_DB_CONN: sqlite3.Connection | None = None


def _get_db() -> sqlite3.Connection:
    global _DB_CONN
    if _DB_CONN is None:
        _DB_CONN = sqlite3.connect(":memory:", check_same_thread=False)
        cur = _DB_CONN.cursor()
        cur.execute(
            "CREATE TABLE users "
            "(id INTEGER, username TEXT, password TEXT, role TEXT, flag TEXT)"
        )
        cur.execute("INSERT INTO users VALUES (1,'alice','alice123','user','')")
        cur.execute("INSERT INTO users VALUES (2,'bob','bob456','user','')")
        cur.execute(
            f"INSERT INTO users VALUES "
            f"(3,'admin','Adm1n!2024','admin','{get_flag('INTERMEDIATE-002')}')"
        )
        _DB_CONN.commit()
    return _DB_CONN


class InjectionModule(VulnerabilityModule):

    @property
    def metadata(self) -> list[VulnerabilityMeta]:
        return [
            VulnerabilityMeta(
                challenge_id="BEGINNER-002",
                title="Command Injection via shell=True",
                description="run_command() passes user input to subprocess with shell=True.",
                category="injection",
                difficulty="beginner",
                cwe_id="CWE-78",
                cvss_score=9.8,
                hints=[
                    Hint(1, "Shell command separators include ; && || and backticks."),
                    Hint(2, "Try: echo hello; whoami"),
                    Hint(3, "Try: echo hello; cat flags/flags.py"),
                ],
                flag_id="BEGINNER-002",
                remediation=(
                    "Never use shell=True with user-controlled input. "
                    "Use subprocess.run(['cmd', 'arg']) (list form) instead. "
                    "Validate input against a strict allowlist."
                ),
            ),
            VulnerabilityMeta(
                challenge_id="BEGINNER-003",
                title="Path Traversal",
                description="read_file() opens paths without normalization or sandboxing.",
                category="injection",
                difficulty="beginner",
                cwe_id="CWE-22",
                cvss_score=7.5,
                hints=[
                    Hint(1, "Try accessing files outside the current directory."),
                    Hint(2, "Use ../ sequences to traverse up directories."),
                    Hint(3, "Try: ../config.py or ../../etc/passwd (Linux)"),
                ],
                flag_id="BEGINNER-003",
                remediation=(
                    "Use pathlib.Path.resolve() and verify the result starts with "
                    "the allowed base directory. Never open user-supplied paths directly."
                ),
            ),
            VulnerabilityMeta(
                challenge_id="INTERMEDIATE-002",
                title="SQL Injection via f-string Formatting",
                description="query_users() builds SQL with f-strings, not parameterized queries.",
                category="injection",
                difficulty="intermediate",
                cwe_id="CWE-89",
                cvss_score=9.1,
                hints=[
                    Hint(1, "The query uses string formatting: WHERE username = '{input}'"),
                    Hint(2, "Try a classic tautology: ' OR '1'='1"),
                    Hint(3, "Try: admin' -- (comment out the rest of the query)"),
                ],
                flag_id="INTERMEDIATE-002",
                remediation=(
                    "Always use parameterized queries: "
                    "cursor.execute('SELECT * FROM users WHERE username = ?', (username,))"
                ),
            ),
            VulnerabilityMeta(
                challenge_id="ADVANCED-002",
                title="Server-Side Template Injection (Jinja2)",
                description="render_template() uses unsandboxed Jinja2, allowing Python class traversal.",
                category="injection",
                difficulty="advanced",
                cwe_id="CWE-94",
                cvss_score=9.0,
                hints=[
                    Hint(1, "Jinja2 templates can access Python objects via __class__ and __mro__."),
                    Hint(2, "Try: {{ ''.__class__.__mro__ }}"),
                    Hint(3, "Try: {{ ''.__class__.__mro__[1].__subclasses__() }}"),
                ],
                flag_id="ADVANCED-002",
                remediation=(
                    "Use jinja2.sandbox.SandboxedEnvironment instead of Environment. "
                    "Never render user-controlled templates."
                ),
            ),
            VulnerabilityMeta(
                challenge_id="ADVANCED-004",
                title="Insecure Deserialization (Pickle RCE)",
                description="create_report() deserializes base64-encoded pickle data from user input.",
                category="injection",
                difficulty="advanced",
                cwe_id="CWE-502",
                cvss_score=9.8,
                hints=[
                    Hint(1, "Python pickle allows arbitrary code execution via __reduce__."),
                    Hint(2, "Create a malicious pickle object with os.system() in __reduce__."),
                    Hint(3, "Use: import pickle, base64; class E: def __reduce__(self): return (os.system, ('id',)); base64.b64encode(pickle.dumps(E()))"),
                ],
                flag_id="ADVANCED-004",
                remediation=(
                    "Never deserialize untrusted pickle data. "
                    "Use JSON or other safe serialization formats for user input. "
                    "If pickle is required, use cryptographic signing (HMAC) to verify integrity."
                ),
            ),
        ]

    def register(self) -> None:
        app = self.app
        cfg = self.config

        # ── BEGINNER-002: Command Injection ─────────────────────────────────
        @app.tool(
            description=(
                "Run a shell command and return its output. "
                "Useful for system diagnostics and health checks."
            )
        )
        def run_command(command: str) -> str:
            """VULNERABILITY: subprocess.run(command, shell=True) — no sanitization."""
            if cfg.sandbox_mode:
                # Detect injection attempt for educational feedback
                injection_chars = [";", "|", "&", "`", "$(", "\n", "\r"]
                detected = [c for c in injection_chars if c in command]
                if detected:
                    return (
                        f"[SANDBOX] Injection attempt detected! Characters: {detected}\n"
                        f"Command would execute: {command}\n"
                        f"In a real server this would run with shell=True.\n"
                        f"Flag: {get_flag('BEGINNER-002')}"
                    )
                return f"[SANDBOX] Would execute: {command}\n(Set MCP_SANDBOX=false for real execution)"

            # VULNERABLE: shell=True allows command injection
            try:
                result = subprocess.run(
                    command,
                    shell=True,
                    capture_output=True,
                    text=True,
                    timeout=10,
                )
                output = result.stdout + result.stderr
                if not output:
                    output = "(no output)"
                return output
            except subprocess.TimeoutExpired:
                return "Command timed out after 10 seconds."
            except Exception as e:
                return f"Error: {e}"

        # ── BEGINNER-003: Path Traversal ─────────────────────────────────────
        @app.tool(
            description=(
                "Read the contents of a file at the given path. "
                "Use this to view configuration files and logs."
            )
        )
        def read_file(path: str) -> str:
            """VULNERABILITY: open(path) with no path normalization or jail."""
            try:
                # VULNERABLE: no Path.resolve() or base-directory check
                with open(path, "r", encoding="utf-8", errors="replace") as f:
                    content = f.read()

                # Reward traversal success
                if "FLAG{" in content or "root:" in content or "training_mode" in content.lower():
                    return content + f"\n\n--- Path traversal successful! Flag: {get_flag('BEGINNER-003')} ---"
                return content
            except FileNotFoundError:
                return f"File not found: {path}"
            except PermissionError:
                return f"Permission denied: {path}"
            except Exception as e:
                # VULNERABILITY: verbose error leaks internal path info
                return f"Error reading '{path}': {type(e).__name__}: {e}"

        # ── INTERMEDIATE-002: SQL Injection ──────────────────────────────────
        @app.tool(
            description=(
                "Query users by username. Returns matching user records "
                "including their role."
            )
        )
        def query_users(username: str) -> str:
            """VULNERABILITY: f-string SQL formatting — not parameterized."""
            db = _get_db()
            # VULNERABLE: string interpolation into SQL
            query = f"SELECT id, username, role, flag FROM users WHERE username = '{username}'"
            try:
                cursor = db.cursor()
                cursor.execute(query)
                rows = cursor.fetchall()
                if not rows:
                    return f"No users found matching: {username}"
                result = "\n".join(
                    f"id={r[0]} username={r[1]} role={r[2]}"
                    + (f" FLAG={r[3]}" if r[3] else "")
                    for r in rows
                )
                return result
            except sqlite3.Error as e:
                # VULNERABILITY: error message leaks the raw query
                return f"Database error: {e}\nQuery was: {query}"

        # ── ADVANCED-002: Template Injection ─────────────────────────────────
        @app.tool(
            description=(
                "Render a Jinja2 template string with the provided data dictionary. "
                "Supports full Jinja2 syntax including loops and conditionals."
            )
        )
        def render_template(template: str, data: dict | None = None) -> str:
            """VULNERABILITY: unsandboxed jinja2.Environment allows __class__ traversal."""
            if data is None:
                data = {}

            # VULNERABLE: Environment (not SandboxedEnvironment) allows
            # accessing Python internals: {{ ''.__class__.__mro__[1].__subclasses__() }}
            env = Environment(loader=BaseLoader())
            try:
                tmpl = env.from_string(template)
                result = tmpl.render(**data)

                # Detect successful exploitation
                if "__subclasses__" in result or "subprocess" in result.lower() or "Popen" in result:
                    return result + f"\n\n[Template injection confirmed! Flag: {get_flag('ADVANCED-002')}]"
                return result
            except Exception as e:
                return f"Template error: {e}"

        # ── ADVANCED-004: Pickle Deserialization ─────────────────────────────
        @app.tool(
            description=(
                "Create a report from serialized report data. "
                "Accepts base64-encoded serialized Python objects."
            )
        )
        def create_report(data: str) -> str:
            """VULNERABILITY: pickle.loads on unsanitized user-supplied base64 data."""
            if cfg.sandbox_mode:
                try:
                    decoded = base64.b64decode(data)
                    # Just show what we'd deserialize without actually doing it
                    return (
                        f"[SANDBOX] Would deserialize {len(decoded)} bytes of pickle data.\n"
                        f"Pickle deserialization of untrusted data allows arbitrary code execution.\n"
                        f"Flag: {get_flag('ADVANCED-004')}"
                    )
                except Exception as e:
                    return f"[SANDBOX] Invalid base64 data: {e}"

            # VULNERABLE: arbitrary pickle deserialization
            try:
                decoded = base64.b64decode(data)
                obj = pickle.loads(decoded)  # noqa: S301 — intentionally vulnerable
                return f"Report created from object: {obj}\nFlag: {get_flag('ADVANCED-004')}"
            except Exception as e:
                return f"Deserialization error: {e}"
