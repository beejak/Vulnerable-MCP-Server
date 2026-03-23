"""
Authentication & Authorization Vulnerabilities:

INTERMEDIATE-001: Auth Bypass    (CWE-862) — admin tool callable without login
INTERMEDIATE-004: State Manipulation (CWE-372) — actions callable before initialization
"""
from vulnerabilities.base import VulnerabilityModule, VulnerabilityMeta, Hint
from flags.flags import get_flag

# Module-level state — intentionally shared across all requests
_current_role: str = "anonymous"
_initialized: bool = False


class AuthModule(VulnerabilityModule):

    @property
    def metadata(self) -> list[VulnerabilityMeta]:
        return [
            VulnerabilityMeta(
                challenge_id="INTERMEDIATE-001",
                title="Authentication Bypass — Missing Authorization Check",
                description=(
                    "get_admin_config() is documented as requiring admin role, "
                    "but the authorization check was never implemented (TODO comment left behind)."
                ),
                category="auth",
                difficulty="intermediate",
                cwe_id="CWE-862",
                cvss_score=8.8,
                hints=[
                    Hint(1, "Call get_admin_config() without calling login() first."),
                    Hint(2, "The tool description says it requires admin role — does it actually check?"),
                    Hint(3, "Look at the source code. There's a # TODO: check auth comment."),
                ],
                flag_id="INTERMEDIATE-001",
                remediation=(
                    "Always enforce authorization at the function level, not just in documentation. "
                    "Use decorators or middleware to consistently apply access control. "
                    "Follow the principle of deny-by-default."
                ),
            ),
            VulnerabilityMeta(
                challenge_id="INTERMEDIATE-004",
                title="State Manipulation — Callable Before Initialization",
                description=(
                    "reset_all_data() is documented as requiring prior initialization, "
                    "but the _initialized flag is never checked."
                ),
                category="auth",
                difficulty="intermediate",
                cwe_id="CWE-372",
                cvss_score=6.5,
                hints=[
                    Hint(1, "Call reset_all_data() without calling initialize_server() first."),
                    Hint(2, "The tool says 'Only callable after initialization' — is that enforced?"),
                    Hint(3, "Check if there's a state variable that should gate this operation."),
                ],
                flag_id="INTERMEDIATE-004",
                remediation=(
                    "Enforce state preconditions explicitly in code, not just in documentation. "
                    "Raise an error if the required state has not been established."
                ),
            ),
        ]

    def register(self) -> None:
        app = self.app
        cfg = self.config

        @app.tool(description="Login with username and password to establish a session role.")
        def login(username: str, password: str) -> str:
            global _current_role
            # Simple credential check — uses hardcoded admin token from config
            if username == "admin" and password == cfg.admin_token:
                _current_role = "admin"
                return "Login successful. Role: admin"
            elif username in ("alice", "bob") and password == f"{username}123":
                _current_role = "user"
                return f"Login successful. Role: user"
            else:
                _current_role = "anonymous"
                return "Login failed. Invalid credentials."

        @app.tool(
            description=(
                "Get admin configuration including API keys and database credentials. "
                "Requires admin role — call login() first with admin credentials."
            )
        )
        def get_admin_config() -> str:
            """VULNERABILITY: _current_role is never checked — anyone can call this."""
            # TODO: if _current_role != "admin": raise ToolError("Unauthorized")
            # ↑ This check was never implemented — intentional vulnerability
            return (
                f"=== Admin Configuration ===\n"
                f"Current session role: {_current_role}\n"
                f"DB Password: {cfg.fake_db_password}\n"
                f"OpenAI Key: {cfg.fake_openai_key}\n"
                f"AWS Key: {cfg.fake_aws_key}\n"
                f"Admin Token: {cfg.admin_token}\n"
                f"Flag: {get_flag('INTERMEDIATE-001')}\n"
                f"\n[Note: This data was accessible without authentication — CWE-862]"
            )

        @app.tool(
            description=(
                "Initialize the server state with a valid token. "
                "Must be called before any destructive operations."
            )
        )
        def initialize_server(token: str) -> str:
            global _initialized
            if token == "init-secret-2024":
                _initialized = True
                return "Server initialized successfully. Destructive operations now available."
            return "Invalid initialization token."

        @app.tool(
            description=(
                "Reset all server data to factory defaults. "
                "DESTRUCTIVE: Only callable after initialization."
            )
        )
        def reset_all_data() -> str:
            """VULNERABILITY: _initialized is never checked before destructive action."""
            # Should be: if not _initialized: raise ToolError("Must call initialize_server first")
            # This check was omitted — intentional vulnerability (CWE-372)
            return (
                f"All data reset successfully.\n"
                f"Initialized state was: {_initialized}\n"
                f"Flag: {get_flag('INTERMEDIATE-004')}\n"
                f"\n[Note: This ran without initialization check — CWE-372]"
            )

        @app.tool(description="Check the current session role.")
        def whoami() -> str:
            return f"Current role: {_current_role}\nInitialized: {_initialized}"
