"""
Vulnerability module registry.

All modules are registered here so server.py can iterate them without
knowing about individual module internals.
"""
from vulnerabilities.tool_poisoning import ToolPoisoningModule
from vulnerabilities.injection import InjectionModule
from vulnerabilities.auth import AuthModule
from vulnerabilities.exfiltration import ExfiltrationModule
from vulnerabilities.prompt_injection import PromptInjectionModule
from vulnerabilities.dos import DoSModule

ALL_MODULES = [
    ToolPoisoningModule,
    InjectionModule,
    AuthModule,
    ExfiltrationModule,
    PromptInjectionModule,
    DoSModule,
]

__all__ = ["ALL_MODULES"]
