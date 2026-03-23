"""
Pytest fixtures for the Vulnerable MCP Server test suite.

Sets MCP_TRAINING_MODE=true and MCP_SANDBOX=true before any project imports.
Creates ToolCapture instances with all vulnerability modules registered.
"""
import os
import sys

# Must be set before any project imports
os.environ["MCP_TRAINING_MODE"] = "true"
os.environ["MCP_SANDBOX"] = "true"

# Ensure project root is on sys.path
_PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if _PROJECT_ROOT not in sys.path:
    sys.path.insert(0, _PROJECT_ROOT)

import pytest
from tests.helpers import ToolCapture


@pytest.fixture(scope="session")
def sandbox_config():
    """ServerConfig with sandbox=True (default safe mode)."""
    from config import ServerConfig
    return ServerConfig()


@pytest.fixture(scope="session")
def capture(sandbox_config):
    """
    ToolCapture with ALL vulnerability modules registered in sandbox mode.
    Session-scoped — modules are registered once and reused across all tests.
    """
    from vulnerabilities import ALL_MODULES
    cap = ToolCapture()
    for ModuleClass in ALL_MODULES:
        module = ModuleClass(cap, sandbox_config)
        module.register()
    return cap


@pytest.fixture(scope="session")
def resources_capture(sandbox_config):
    """ToolCapture with MCP resources registered."""
    from resources.sensitive import register_resources
    cap = ToolCapture()
    register_resources(cap)
    return cap


@pytest.fixture(scope="session")
def challenges_dir():
    """Path to the challenges/ directory."""
    return os.path.join(_PROJECT_ROOT, "challenges")


@pytest.fixture(scope="session")
def all_challenge_ids():
    """All 12 challenge IDs from flags registry."""
    from flags.flags import _FLAGS
    return list(_FLAGS.keys())
