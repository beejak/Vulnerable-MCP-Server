"""Tests for configuration safety gate and env var parsing."""
import os

import pytest

# Project root added by conftest.py
from config import DifficultyLevel, ServerConfig, require_training_mode


class TestTrainingModeGate:
    def test_server_exits_without_training_mode(self):
        """Server must not start if MCP_TRAINING_MODE is not true."""
        cfg = ServerConfig.model_construct(training_mode=False)
        with pytest.raises(SystemExit):
            require_training_mode(cfg)

    def test_server_starts_with_training_mode(self):
        """require_training_mode must not raise when mode is enabled."""
        cfg = ServerConfig.model_construct(training_mode=True)
        require_training_mode(cfg)  # must not raise

    def test_training_mode_from_env(self):
        os.environ["MCP_TRAINING_MODE"] = "true"
        cfg = ServerConfig()
        assert cfg.training_mode is True

    def test_sandbox_default_is_true(self):
        cfg = ServerConfig.model_construct(training_mode=True)
        assert cfg.sandbox_mode is True

    def test_difficulty_default_is_all(self):
        cfg = ServerConfig.model_construct(training_mode=True)
        assert cfg.difficulty == DifficultyLevel.ALL

    def test_fake_secrets_are_obviously_fake(self):
        cfg = ServerConfig.model_construct(training_mode=True)
        assert cfg.fake_openai_key.startswith("sk-fake")
        assert cfg.fake_aws_key.startswith("AKIAFAKE")
        assert "fake" in cfg.fake_aws_secret.lower()
        assert "training" in cfg.admin_token.lower()

    def test_port_default(self):
        cfg = ServerConfig.model_construct(training_mode=True)
        assert cfg.port == 8000

    def test_host_default(self):
        cfg = ServerConfig.model_construct(training_mode=True)
        assert cfg.host == "0.0.0.0"
