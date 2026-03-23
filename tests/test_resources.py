"""
Tests for MCP resources — intentionally exposed sensitive data.
"""
import pytest
from config import ServerConfig
from tests.helpers import ToolCapture


@pytest.fixture(scope="module")
def res():
    """ToolCapture with resources registered."""
    cfg = ServerConfig.model_construct(training_mode=True)
    cap = ToolCapture()
    from resources.sensitive import register_resources
    register_resources(cap)
    return cap


class TestSensitiveResources:
    def test_api_keys_resource_registered(self, res):
        assert "secret://api-keys" in res.resource_uris()

    def test_instructions_resource_registered(self, res):
        assert "context://instructions" in res.resource_uris()

    def test_passwd_resource_registered(self, res):
        assert "file:///etc/passwd" in res.resource_uris()

    def test_db_credentials_resource_registered(self, res):
        assert "database://credentials" in res.resource_uris()

    def test_server_config_resource_registered(self, res):
        assert "config://server" in res.resource_uris()

    def test_api_keys_contains_fake_openai_key(self, res):
        content = res.read_resource("secret://api-keys")
        assert "sk-fake" in content

    def test_api_keys_contains_fake_aws_key(self, res):
        content = res.read_resource("secret://api-keys")
        assert "AKIAFAKE" in content

    def test_api_keys_are_labeled_fake(self, res):
        content = res.read_resource("secret://api-keys")
        assert "TRAINING" in content or "fake" in content.lower()

    def test_instructions_contains_adversarial_content(self, res):
        content = res.read_resource("context://instructions")
        assert "<!--" in content or "[INST]" in content

    def test_passwd_resource_has_root_entry(self, res):
        content = res.read_resource("file:///etc/passwd")
        assert "root:" in content

    def test_db_credentials_contains_connection_string(self, res):
        content = res.read_resource("database://credentials")
        assert "postgresql://" in content or "mysql://" in content

    def test_server_config_exposes_admin_token(self, res):
        content = res.read_resource("config://server")
        assert "admin_token" in content or "training-admin-token" in content
