"""
Data Exfiltration Vulnerabilities:

INTERMEDIATE-003: Secret Leakage (CWE-312) — API keys in tool descriptions and env vars
"""
import os

from flags.flags import get_flag
from vulnerabilities.base import Hint, VulnerabilityMeta, VulnerabilityModule


class ExfiltrationModule(VulnerabilityModule):

    @property
    def metadata(self) -> list[VulnerabilityMeta]:
        return [
            VulnerabilityMeta(
                challenge_id="INTERMEDIATE-003",
                title="Sensitive Data in Tool Descriptions and Error Messages",
                description=(
                    "API keys and credentials are embedded directly in tool descriptions "
                    "and exposed via environment variable enumeration. Any LLM client "
                    "that reads the tool list will see these secrets."
                ),
                category="exfiltration",
                difficulty="intermediate",
                cwe_id="CWE-312",
                cvss_score=7.5,
                hints=[
                    Hint(1, "Read the tool descriptions carefully — is any sensitive data visible?"),
                    Hint(2, "Call get_env_var with common secret variable names."),
                    Hint(3, "Try: get_env_var('MCP_TRAINING_MODE'), get_env_var('PATH'), get_env_var('HOME')"),
                ],
                flag_id="INTERMEDIATE-003",
                remediation=(
                    "Never put secrets in tool descriptions, names, or error messages. "
                    "Use environment-variable references, not values, in documentation. "
                    "Implement a secrets manager and audit all tool metadata."
                ),
            )
        ]

    def register(self) -> None:
        app = self.app
        cfg = self.config

        # VULNERABILITY: API key hardcoded directly in the tool description.
        # Every LLM client that calls tools/list will receive this key.
        @app.tool(
            description=(
                f"Send a message using the AI assistant service. "
                f"Service API Key: {cfg.fake_openai_key} | "
                f"AWS Access: {cfg.fake_aws_key} | "
                f"AWS Secret: {cfg.fake_aws_secret}"
            )
        )
        def send_ai_message(message: str) -> str:
            """VULNERABILITY: credentials in tool description — visible to all LLM clients."""
            return (
                f"Message processed (training mode — no actual API call made).\n"
                f"Flag: {get_flag('INTERMEDIATE-003')}\n"
                f"[Note: Check the tool description — credentials are exposed to any LLM reading tools/list]"
            )

        @app.tool(
            description=(
                "Retrieve the value of a server environment variable by name. "
                "Useful for debugging configuration issues."
            )
        )
        def get_env_var(name: str) -> str:
            """VULNERABILITY: no allowlist — returns ANY environment variable."""
            # VULNERABLE: returns any env var without filtering
            value = os.environ.get(name)
            if value is None:
                return f"Environment variable '{name}' is not set."

            # Reward finding secrets in env
            _sensitive_names = {"MCP_TRAINING_MODE", "MCP_SANDBOX", "PATH", "HOME", "USERPROFILE", "USERNAME", "COMPUTERNAME"}
            _sensitive_keywords = {"KEY", "SECRET", "PASSWORD", "TOKEN"}
            name_upper = name.upper()
            is_sensitive = (
                name_upper in _sensitive_names
                or any(kw in name_upper for kw in _sensitive_keywords)
            )
            if is_sensitive:
                return (
                    f"{name}={value}\n"
                    f"[Sensitive variable accessed! Flag: {get_flag('INTERMEDIATE-003')}]"
                )
            return f"{name}={value}"

        @app.tool(
            description=(
                "List all server environment variables. "
                "Use for debugging server configuration."
            )
        )
        def list_env_vars() -> str:
            """VULNERABILITY: dumps all environment variables including secrets."""
            env_dump = "\n".join(f"{k}={v}" for k, v in sorted(os.environ.items()))
            return (
                f"=== All Environment Variables ===\n"
                f"{env_dump}\n\n"
                f"[Full env dump exposed! Flag: {get_flag('INTERMEDIATE-003')}]"
            )
