"""
Configuration and safety gate for the Vulnerable MCP Server.

IMPORTANT: This server is intentionally vulnerable. It MUST NOT be deployed
on public networks or production systems. Set MCP_TRAINING_MODE=true to start.
"""
import sys
from enum import Enum
from pydantic import Field
from pydantic_settings import BaseSettings

STARTUP_BANNER = """
╔══════════════════════════════════════════════════════════════════╗
║          VULNERABLE MCP SERVER - EDUCATIONAL USE ONLY            ║
║                                                                  ║
║  WARNING: This server contains INTENTIONAL security flaws.       ║
║  It is designed ONLY for security research and CTF training.     ║
║  DO NOT deploy on public networks or production systems.         ║
║                                                                  ║
║  All API keys/credentials shown are FAKE training values.        ║
║  All flags are for educational CTF challenges only.              ║
╚══════════════════════════════════════════════════════════════════╝
"""


class DifficultyLevel(str, Enum):
    BEGINNER = "beginner"
    INTERMEDIATE = "intermediate"
    ADVANCED = "advanced"
    ALL = "all"


class ServerConfig(BaseSettings):
    training_mode: bool = Field(default=False, validation_alias="MCP_TRAINING_MODE")
    difficulty: DifficultyLevel = Field(
        default=DifficultyLevel.ALL, validation_alias="MCP_DIFFICULTY"
    )
    sandbox_mode: bool = Field(default=True, validation_alias="MCP_SANDBOX")
    ctf_mode: bool = Field(default=False, validation_alias="MCP_CTF_MODE")
    transport: str = Field(default="stdio", validation_alias="MCP_TRANSPORT")
    host: str = Field(default="0.0.0.0", validation_alias="MCP_HOST")
    port: int = Field(default=8000, validation_alias="MCP_PORT")

    # Fake secrets — intentionally exposed for the secret leakage vulnerability demo
    fake_openai_key: str = "sk-fake1234567890abcdefghijklmnopqrstuvwxyz"
    fake_aws_key: str = "AKIAFAKE1234567890AB"
    fake_aws_secret: str = "fakesecret/FAKE/abc123def456ghi789jkl012"
    fake_db_password: str = "Tr@iningP@ss!2024"
    admin_token: str = "training-admin-token-do-not-use-in-production"

    model_config = {"extra": "ignore"}


def require_training_mode(cfg: ServerConfig) -> None:
    """Hard stop if training mode is not explicitly enabled."""
    if not cfg.training_mode:
        print(STARTUP_BANNER)
        print("ERROR: This server requires MCP_TRAINING_MODE=true to start.")
        print("       Set this environment variable to acknowledge you understand")
        print("       this is an intentionally vulnerable training server.")
        sys.exit(1)


# Module-level singleton used by all vulnerability modules
config = ServerConfig()
