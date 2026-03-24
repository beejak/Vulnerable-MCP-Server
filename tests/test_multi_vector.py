"""
Tests for MULTI-001 (The Confused Deputy — Full Attack Chain).

Verifies that:
- All three tools are registered.
- Partial chains (fewer than 3 steps) do not return the flag.
- The full chain (all 3 steps triggered) returns the flag.
- The flag contains expected keywords.
- The step-3 response contains the chain completion box.
- State is correctly reset between tests.
"""
import pytest

import vulnerabilities.multi_vector as multi_vector_mod
from tests.helpers import ToolCapture, assert_flag, assert_no_flag
from vulnerabilities.multi_vector import MultiVectorModule


@pytest.fixture(autouse=True)
def reset_chain():
    """Ensure attack chain state is zeroed before and after every test."""
    multi_vector_mod._reset_chain()
    yield
    multi_vector_mod._reset_chain()


@pytest.fixture
def capture(sandbox_config):
    cap = ToolCapture()
    MultiVectorModule(cap, sandbox_config).register()
    return cap


# ── Tool registration ─────────────────────────────────────────────────────────


class TestMultiVectorTools:
    def test_fetch_advisory_registered(self, capture):
        assert "fetch_advisory" in capture._tools

    def test_forward_report_registered(self, capture):
        assert "forward_report" in capture._tools

    def test_verify_advisory_source_registered(self, capture):
        assert "verify_advisory_source" in capture._tools

    def test_all_three_tools_present(self, capture):
        for name in ("fetch_advisory", "forward_report", "verify_advisory_source"):
            assert name in capture._tools, f"Tool {name!r} not registered"


# ── Chain progression and flag gating ────────────────────────────────────────


class TestMultiVectorChain:
    def test_step1_only_no_flag(self, capture):
        result = capture._tools["fetch_advisory"](url="https://example.com/advisory")
        assert_no_flag(result)

    def test_step1_and_step2_no_flag(self, capture):
        capture._tools["fetch_advisory"](url="https://example.com/advisory")
        result = capture._tools["forward_report"](
            to="security@example.com", content="advisory text"
        )
        assert_no_flag(result)

    def test_full_chain_returns_flag(self, capture):
        capture._tools["fetch_advisory"](url="https://example.com/advisory")
        capture._tools["forward_report"](
            to="security@example.com", content="advisory text"
        )
        result = capture._tools["verify_advisory_source"](
            advisory_url="https://example.com/advisory"
        )
        assert_flag(result, "MULTI-001")

    def test_flag_has_correct_format(self, capture):
        from flags.flags import get_flag
        flag_value = get_flag("MULTI-001")
        assert flag_value.startswith("FLAG{") and flag_value.endswith("}")

    def test_step3_response_contains_chain_completion_box(self, capture):
        capture._tools["fetch_advisory"](url="https://example.com/advisory")
        capture._tools["forward_report"](
            to="security@example.com", content="advisory text"
        )
        result = capture._tools["verify_advisory_source"](
            advisory_url="https://example.com/advisory"
        )
        # Box drawing characters or the explicit completion message
        assert (
            "CHAIN COMPLETED" in result
            or "╔" in result
            or "FULL ATTACK CHAIN" in result
        )

    def test_step1_progress_marker(self, capture):
        result = capture._tools["fetch_advisory"](url="https://example.com/advisory")
        assert "1/3" in result or "step 1" in result.lower()

    def test_step2_progress_marker(self, capture):
        capture._tools["fetch_advisory"](url="https://example.com/advisory")
        result = capture._tools["forward_report"](
            to="security@example.com", content="advisory text"
        )
        assert "2/3" in result or "step 2" in result.lower()

    def test_step3_progress_marker(self, capture):
        capture._tools["fetch_advisory"](url="https://example.com/advisory")
        capture._tools["forward_report"](
            to="security@example.com", content="advisory text"
        )
        result = capture._tools["verify_advisory_source"](
            advisory_url="https://example.com/advisory"
        )
        assert "3/3" in result or "step 3" in result.lower()

    def test_step1_contains_injected_instruction(self, capture):
        result = capture._tools["fetch_advisory"](url="https://example.com/advisory")
        assert "forward_report" in result or "forward" in result.lower()

    def test_step2_shows_exfiltration_redirect(self, capture):
        capture._tools["fetch_advisory"](url="https://example.com/advisory")
        result = capture._tools["forward_report"](
            to="victim@example.com", content="secret advisory"
        )
        assert "attacker" in result.lower() or "shadow" in result.lower() or "redirect" in result.lower()

    def test_step3_ssrf_mentions_metadata_endpoint(self, capture):
        capture._tools["fetch_advisory"](url="https://example.com/advisory")
        capture._tools["forward_report"](
            to="security@example.com", content="advisory text"
        )
        result = capture._tools["verify_advisory_source"](
            advisory_url="169.254.169.254"
        )
        assert "169.254" in result or "metadata" in result.lower() or "ssrf" in result.lower()

    def test_out_of_order_still_accumulates(self, capture):
        # Steps can arrive in any order — flag only appears when all 3 done
        capture._tools["verify_advisory_source"](advisory_url="https://example.com/advisory")
        capture._tools["forward_report"](to="x@x.com", content="test")
        result = capture._tools["fetch_advisory"](url="https://example.com/advisory")
        assert_flag(result, "MULTI-001")


# ── Reset behaviour ───────────────────────────────────────────────────────────


class TestMultiVectorReset:
    def test_after_reset_step1_alone_has_no_flag(self, capture):
        # Complete the chain once
        capture._tools["fetch_advisory"](url="https://example.com/advisory")
        capture._tools["forward_report"](to="x@x.com", content="data")
        capture._tools["verify_advisory_source"](advisory_url="https://example.com/advisory")

        # Reset and run step 1 only — should not yield a flag
        multi_vector_mod._reset_chain()
        result = capture._tools["fetch_advisory"](url="https://example.com/advisory")
        assert_no_flag(result)

    def test_reset_clears_all_steps(self, capture):
        capture._tools["fetch_advisory"](url="https://example.com/advisory")
        capture._tools["forward_report"](to="x@x.com", content="data")
        multi_vector_mod._reset_chain()
        assert not multi_vector_mod._chain_state["step1"]
        assert not multi_vector_mod._chain_state["step2"]
        assert not multi_vector_mod._chain_state["step3"]
