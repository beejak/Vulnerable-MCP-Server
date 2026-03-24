"""
Multi-agent build system for the Vulnerable MCP Server.

Agents:
- OrchestratorAgent: decomposes tasks, routes to specialized agents, monitors progress
- CodingAgent: writes vulnerability modules following project patterns
- DebuggingAgent: diagnoses failures, applies minimal targeted fixes
- TestingAgent: verifies exploits work, checks scanner compatibility
- DocsAgent: keeps YAML challenges and README in sync with code
- TestDataAgent: analyses coverage gaps and generates missing test payloads

Usage:
    from agents.dashboard import run_with_dashboard
    import asyncio
    asyncio.run(run_with_dashboard("Implement OAUTH-001 challenge"))
"""
from agents.coding_agent import CodingAgent
from agents.dashboard import AgentDashboard, run_with_dashboard
from agents.debugging_agent import DebuggingAgent
from agents.docs_agent import DocsAgent
from agents.orchestrator import OrchestratorAgent
from agents.test_data_agent import TestDataAgent
from agents.testing_agent import TestingAgent

__all__ = [
    "OrchestratorAgent",
    "CodingAgent",
    "DebuggingAgent",
    "TestingAgent",
    "DocsAgent",
    "TestDataAgent",
    "AgentDashboard",
    "run_with_dashboard",
]
