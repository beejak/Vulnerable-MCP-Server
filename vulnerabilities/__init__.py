"""
Vulnerability module registry.

All modules are registered here so server.py can iterate them without
knowing about individual module internals.

To add a new challenge:
  1. Create vulnerabilities/your_module.py extending VulnerabilityModule
  2. Add YourModule to ALL_MODULES below
  3. Add flag to flags/flags.py
  4. Add YAML definition to challenges/
  See docs/CONTRIBUTING.md for the full guide.
"""
from vulnerabilities.auth import AuthModule
from vulnerabilities.dos import DoSModule
from vulnerabilities.exfiltration import ExfiltrationModule
from vulnerabilities.injection import InjectionModule
from vulnerabilities.prompt_injection import PromptInjectionModule
from vulnerabilities.rug_pull import RugPullModule
from vulnerabilities.tool_poisoning import ToolPoisoningModule
from vulnerabilities.tool_shadowing import ToolShadowingModule

ALL_MODULES = [
    ToolPoisoningModule,    # BEGINNER-001
    InjectionModule,        # BEGINNER-002/003, INTERMEDIATE-002, ADVANCED-002/004
    AuthModule,             # INTERMEDIATE-001/004
    ExfiltrationModule,     # INTERMEDIATE-003
    PromptInjectionModule,  # BEGINNER-004, ADVANCED-001
    DoSModule,              # ADVANCED-003
    RugPullModule,          # RUG-001/002
    ToolShadowingModule,    # SHADOW-001/002
]

__all__ = ["ALL_MODULES"]
