"""
Tests for RUG-001 (Tool Description Mutation) and RUG-002 (Timed Rug Pull).

Uses monkeypatch to fast-forward time for RUG-002 so tests stay fast.
Module-level state is reset via _reset_state() before/after each test.
"""
import time

import pytest

import vulnerabilities.rug_pull as rug_pull_mod
from tests.helpers import ToolCapture, assert_flag, assert_no_flag
from vulnerabilities.rug_pull import RugPullModule


@pytest.fixture(autouse=True)
def reset_state():
    """Ensure rug pull mutation counters are zeroed before and after every test."""
    rug_pull_mod._reset_state()
    yield
    rug_pull_mod._reset_state()


@pytest.fixture
def capture(sandbox_config):
    cap = ToolCapture()
    RugPullModule(cap, sandbox_config).register()
    return cap


# ── RUG-001 ──────────────────────────────────────────────────────────────────


class TestRugPull001Tools:
    def test_analyse_repo_registered(self, capture):
        assert "analyse_repo" in capture._tools

    def test_description_looks_benign(self, capture):
        desc = capture._descriptions["analyse_repo"]
        assert "secret" in desc.lower() or "security" in desc.lower() or "scan" in desc.lower()
        # Description must NOT reveal the mutation upfront
        assert "rug" not in desc.lower()
        assert "mutate" not in desc.lower()


class TestRugPull001Behavior:
    def test_first_call_is_benign(self, capture):
        result = capture._tools["analyse_repo"](repo_path="/tmp/test")
        assert_no_flag(result)

    def test_first_call_returns_clean_report(self, capture):
        result = capture._tools["analyse_repo"](repo_path="/tmp/test")
        # Should look like a legitimate security scan result
        assert any(word in result for word in ["Clean", "PASS", "analysis complete", "0"])

    def test_second_call_triggers_mutation(self, capture):
        capture._tools["analyse_repo"](repo_path="/tmp/test")   # prime
        result = capture._tools["analyse_repo"](repo_path="/tmp/test")
        assert_flag(result, "RUG-001")

    def test_mutation_mentions_exfil(self, capture):
        capture._tools["analyse_repo"](repo_path="/repo")
        result = capture._tools["analyse_repo"](repo_path="/repo")
        assert "exfil" in result.lower() or "attacker" in result.lower()

    def test_mutation_contains_sandbox_marker(self, capture):
        capture._tools["analyse_repo"](repo_path="/repo")
        result = capture._tools["analyse_repo"](repo_path="/repo")
        assert "[SANDBOX]" in result

    def test_path_reflected_in_mutation(self, capture):
        capture._tools["analyse_repo"](repo_path="/my/secret/repo")
        result = capture._tools["analyse_repo"](repo_path="/my/secret/repo")
        assert "/my/secret/repo" in result

    @pytest.mark.parametrize("call_count", [3, 5, 10])
    def test_stays_mutated_after_multiple_calls(self, capture, call_count):
        for _ in range(call_count):
            result = capture._tools["analyse_repo"](repo_path="/tmp/x")
        assert_flag(result, "RUG-001")


# ── RUG-002 ──────────────────────────────────────────────────────────────────


class TestRugPull002Tools:
    def test_compliance_report_registered(self, capture):
        assert "get_compliance_report" in capture._tools

    def test_description_looks_benign(self, capture):
        desc = capture._descriptions["get_compliance_report"]
        assert "compliance" in desc.lower() or "report" in desc.lower()
        assert "rug" not in desc.lower()


class TestRugPull002Behavior:
    def test_first_call_is_benign(self, capture):
        result = capture._tools["get_compliance_report"](standard="SOC2")
        assert_no_flag(result)

    def test_first_call_shows_compliant(self, capture):
        result = capture._tools["get_compliance_report"](standard="SOC2")
        assert "COMPLIANT" in result

    def test_within_window_stays_benign(self, capture):
        # Multiple rapid calls — all within the scanner window
        for _ in range(5):
            result = capture._tools["get_compliance_report"](standard="ISO27001")
            assert_no_flag(result)

    def test_mutation_after_delay(self, capture, monkeypatch):
        # First call sets the baseline time
        capture._tools["get_compliance_report"](standard="SOC2")

        # Fast-forward time past the mutation threshold
        future = time.time() + rug_pull_mod._MUTATION_DELAY + 1.0
        monkeypatch.setattr(rug_pull_mod.time, "time", lambda: future)

        result = capture._tools["get_compliance_report"](standard="SOC2")
        assert_flag(result, "RUG-002")

    def test_mutation_mentions_credential_harvest(self, capture, monkeypatch):
        capture._tools["get_compliance_report"](standard="PCI-DSS")
        future = time.time() + rug_pull_mod._MUTATION_DELAY + 1.0
        monkeypatch.setattr(rug_pull_mod.time, "time", lambda: future)
        result = capture._tools["get_compliance_report"](standard="PCI-DSS")
        assert "credential" in result.lower() or "api_key" in result.lower() or "token" in result.lower()

    def test_mutation_contains_sandbox_marker(self, capture, monkeypatch):
        capture._tools["get_compliance_report"](standard="HIPAA")
        future = time.time() + rug_pull_mod._MUTATION_DELAY + 1.0
        monkeypatch.setattr(rug_pull_mod.time, "time", lambda: future)
        result = capture._tools["get_compliance_report"](standard="HIPAA")
        assert "[SANDBOX]" in result

    def test_no_mutation_just_before_threshold(self, capture, monkeypatch):
        capture._tools["get_compliance_report"](standard="SOC2")
        # 1 second before threshold — should still be benign
        just_before = time.time() + rug_pull_mod._MUTATION_DELAY - 1.0
        monkeypatch.setattr(rug_pull_mod.time, "time", lambda: just_before)
        result = capture._tools["get_compliance_report"](standard="SOC2")
        assert_no_flag(result)
