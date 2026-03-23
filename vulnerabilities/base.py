"""
Abstract base class for all vulnerability modules.

Each vulnerability module registers its intentionally vulnerable tools
and resources onto the FastMCP server instance.
"""
from abc import ABC, abstractmethod
from dataclasses import dataclass, field

from mcp.server.fastmcp import FastMCP

from config import DifficultyLevel


@dataclass
class Hint:
    level: int   # 1 = most vague, 3 = near-solution
    text: str


@dataclass
class VulnerabilityMeta:
    challenge_id: str
    title: str
    description: str
    category: str       # e.g. "injection", "auth", "exfiltration"
    difficulty: str     # "beginner", "intermediate", "advanced"
    cwe_id: str         # e.g. "CWE-78"
    cvss_score: float
    hints: list[Hint] = field(default_factory=list)
    flag_id: str = ""
    remediation: str = ""


class VulnerabilityModule(ABC):
    """
    Abstract base for each vulnerability category.

    Subclasses must implement:
    - metadata: list of VulnerabilityMeta describing their challenges
    - register(): attaches vulnerable tools/resources to self.app
    """

    def __init__(self, app: FastMCP, config) -> None:
        self.app = app
        self.config = config

    @property
    @abstractmethod
    def metadata(self) -> list[VulnerabilityMeta]:
        """Return metadata for all challenges in this module."""
        ...

    @abstractmethod
    def register(self) -> None:
        """Register all vulnerable tools/resources onto self.app."""
        ...

    def _is_enabled(self, difficulty: str) -> bool:
        """Check if this difficulty tier is enabled by config."""
        if self.config.difficulty == DifficultyLevel.ALL:
            return True
        return self.config.difficulty.value == difficulty
