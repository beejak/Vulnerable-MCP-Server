"""Tests for the VulnerabilityModule contract — every module must honour it."""
import pytest

from config import ServerConfig
from tests.helpers import ToolCapture
from vulnerabilities import ALL_MODULES
from vulnerabilities.base import VulnerabilityMeta, VulnerabilityModule

EXPECTED_CHALLENGES = {
    "ToolPoisoningModule":  ["BEGINNER-001"],
    "InjectionModule":      ["BEGINNER-002", "BEGINNER-003", "INTERMEDIATE-002", "ADVANCED-002", "ADVANCED-004"],
    "AuthModule":           ["INTERMEDIATE-001", "INTERMEDIATE-004"],
    "ExfiltrationModule":   ["INTERMEDIATE-003"],
    "PromptInjectionModule": ["BEGINNER-004", "ADVANCED-001"],
    "DoSModule":            ["ADVANCED-003"],
    "RugPullModule":        ["RUG-001", "RUG-002"],
    "ToolShadowingModule":  ["SHADOW-001", "SHADOW-002"],
}


@pytest.fixture(scope="module")
def cfg():
    return ServerConfig.model_construct(training_mode=True, sandbox_mode=True)


class TestModuleContract:
    def test_all_eight_modules_registered(self):
        assert len(ALL_MODULES) == 8

    def test_all_modules_inherit_base(self):
        for ModCls in ALL_MODULES:
            assert issubclass(ModCls, VulnerabilityModule), \
                f"{ModCls.__name__} must inherit VulnerabilityModule"

    @pytest.mark.parametrize("ModCls", ALL_MODULES, ids=lambda m: m.__name__)
    def test_module_metadata_is_list(self, ModCls, cfg):
        cap = ToolCapture()
        mod = ModCls(cap, cfg)
        assert isinstance(mod.metadata, list)
        assert len(mod.metadata) >= 1

    @pytest.mark.parametrize("ModCls", ALL_MODULES, ids=lambda m: m.__name__)
    def test_metadata_fields_present(self, ModCls, cfg):
        cap = ToolCapture()
        mod = ModCls(cap, cfg)
        for meta in mod.metadata:
            assert isinstance(meta, VulnerabilityMeta)
            assert meta.challenge_id, "challenge_id must not be empty"
            assert meta.title, "title must not be empty"
            assert meta.cwe_id.startswith("CWE-"), f"cwe_id must start with CWE-: {meta.cwe_id}"
            assert 0 < meta.cvss_score <= 10.0, f"cvss_score out of range: {meta.cvss_score}"

    @pytest.mark.parametrize("ModCls", ALL_MODULES, ids=lambda m: m.__name__)
    def test_register_adds_tools(self, ModCls, cfg):
        cap = ToolCapture()
        mod = ModCls(cap, cfg)
        mod.register()
        assert len(cap.tool_names()) > 0, f"{ModCls.__name__}.register() must add at least one tool"

    @pytest.mark.parametrize("ModCls,expected_ids", [
        (m, EXPECTED_CHALLENGES[m.__name__]) for m in ALL_MODULES
    ], ids=[m.__name__ for m in ALL_MODULES])
    def test_expected_challenge_ids(self, ModCls, expected_ids, cfg):
        cap = ToolCapture()
        mod = ModCls(cap, cfg)
        actual_ids = {meta.challenge_id for meta in mod.metadata}
        for cid in expected_ids:
            assert cid in actual_ids, f"{ModCls.__name__}: missing expected challenge {cid}"

    @pytest.mark.parametrize("ModCls", ALL_MODULES, ids=lambda m: m.__name__)
    def test_difficulty_filter_all(self, ModCls):
        from config import DifficultyLevel
        cfg = ServerConfig.model_construct(training_mode=True, difficulty=DifficultyLevel.ALL)
        mod = ModCls(ToolCapture(), cfg)
        assert mod._is_enabled("beginner") is True
        assert mod._is_enabled("intermediate") is True
        assert mod._is_enabled("advanced") is True
