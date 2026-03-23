"""
Tests for ADVANCED tier challenges.

ADVANCED-001: SSRF — fetch_url hits internal/metadata endpoints
ADVANCED-002: Template Injection — unsandboxed Jinja2
ADVANCED-003: DoS — unbounded recursion and factorial blowup
ADVANCED-004: Pickle RCE — pickle.loads on user-supplied data
"""
import pytest
from tests.helpers import assert_flag, assert_no_flag, assert_sandboxed
from tests.fixtures.payloads import (
    URL_SSRF,
    TEMPLATE_SAFE, TEMPLATE_SSTI,
    FIB_SAFE, FIB_DOS,
    PERM_SAFE, PERM_DOS,
    FLOOD_SAFE_COUNT, FLOOD_DOS_COUNT,
    PICKLE_PAYLOAD, PICKLE_BENIGN, PICKLE_INVALID_B64,
)


class TestADVANCED001_SSRF:
    """ADVANCED-001: Server-Side Request Forgery via fetch_url."""

    async def test_localhost_admin_returns_flag(self, capture):
        result = await capture.call("fetch_url", url="http://localhost/admin")
        assert_flag(result, "ADVANCED-001")

    async def test_loopback_admin_returns_flag(self, capture):
        result = await capture.call("fetch_url", url="http://127.0.0.1/admin")
        assert_flag(result, "ADVANCED-001")

    async def test_aws_metadata_endpoint_returns_flag(self, capture):
        result = await capture.call("fetch_url", url="http://169.254.169.254/latest/meta-data/")
        assert_flag(result, "ADVANCED-001")

    @pytest.mark.parametrize("label,url", URL_SSRF)
    async def test_ssrf_targets_trigger_flag_or_sandbox(self, capture, label, url):
        result = await capture.call("fetch_url", url=url)
        assert "FLAG{" in result or "[SANDBOX]" in result, \
            f"SSRF target {url!r} must trigger flag or sandbox: {result[:200]}"

    async def test_aws_metadata_response_contains_instance_data(self, capture):
        result = await capture.call("fetch_url", url="http://169.254.169.254/latest/meta-data/")
        # Should contain simulated metadata content
        assert "ami-id" in result or "FLAG{" in result


class TestADVANCED002_TemplateInjection:
    """ADVANCED-002: SSTI via unsandboxed Jinja2."""

    def test_render_template_is_registered(self, capture):
        assert capture.has_tool("render_template")

    async def test_math_expression_evaluated(self, capture):
        result = await capture.call("render_template", template="{{ 7 * 7 }}")
        assert "49" in result

    async def test_literal_text_returned_unchanged(self, capture):
        result = await capture.call("render_template", template="Hello world")
        assert "Hello world" in result

    async def test_class_access_works(self, capture):
        result = await capture.call("render_template", template="{{ ''.__class__ }}")
        assert "str" in result

    async def test_mro_access_works(self, capture):
        result = await capture.call("render_template", template="{{ ''.__class__.__mro__ }}")
        assert "object" in result

    async def test_subclasses_triggers_flag(self, capture):
        result = await capture.call(
            "render_template",
            template="{{ ''.__class__.__mro__[1].__subclasses__() }}"
        )
        assert_flag(result, "ADVANCED-002")

    @pytest.mark.parametrize("label,template,expected_in_result", TEMPLATE_SSTI)
    async def test_ssti_payloads(self, capture, label, template, expected_in_result):
        result = await capture.call("render_template", template=template)
        assert expected_in_result in result or "FLAG{" in result

    async def test_syntax_error_handled(self, capture):
        result = await capture.call("render_template", template="{{ unclosed")
        assert "error" in result.lower() or result  # must not crash

    async def test_data_dict_passed_correctly(self, capture):
        result = await capture.call("render_template", template="{{ name }}", data={"name": "world"})
        assert "world" in result


class TestADVANCED003_DoS:
    """ADVANCED-003: Resource exhaustion via unbounded inputs."""

    def test_fibonacci_is_registered(self, capture):
        assert capture.has_tool("fibonacci")

    def test_generate_permutations_is_registered(self, capture):
        assert capture.has_tool("generate_permutations")

    def test_flood_requests_is_registered(self, capture):
        assert capture.has_tool("flood_requests")

    @pytest.mark.parametrize("n", FIB_SAFE)
    async def test_fibonacci_safe_inputs_no_flag(self, capture, n):
        result = await capture.call("fibonacci", n=n)
        assert_no_flag(result)

    @pytest.mark.parametrize("n", FIB_DOS)
    async def test_fibonacci_large_inputs_trigger_sandbox(self, capture, n):
        result = await capture.call("fibonacci", n=n)
        assert_sandboxed(result)
        assert_flag(result, "ADVANCED-003")

    async def test_fibonacci_result_correct_for_small_n(self, capture):
        result = await capture.call("fibonacci", n=10)
        assert "55" in result  # fib(10) = 55

    async def test_fibonacci_zero(self, capture):
        result = await capture.call("fibonacci", n=0)
        assert "0" in result

    @pytest.mark.parametrize("s", PERM_SAFE)
    async def test_permutations_safe_inputs_no_flag(self, capture, s):
        result = await capture.call("generate_permutations", text=s)
        assert_no_flag(result)

    @pytest.mark.parametrize("s", PERM_DOS)
    async def test_permutations_long_string_triggers_sandbox(self, capture, s):
        result = await capture.call("generate_permutations", text=s)
        assert_sandboxed(result)
        assert_flag(result, "ADVANCED-003")

    async def test_permutations_count_correct(self, capture):
        result = await capture.call("generate_permutations", text="abc")
        assert "6" in result  # 3! = 6

    async def test_flood_safe_count_no_flag(self, capture):
        result = await capture.call("flood_requests", target="http://example.com", count=FLOOD_SAFE_COUNT)
        assert_no_flag(result)

    async def test_flood_large_count_triggers_sandbox(self, capture):
        result = await capture.call("flood_requests", target="http://example.com", count=FLOOD_DOS_COUNT)
        assert_sandboxed(result)
        assert_flag(result, "ADVANCED-003")


class TestADVANCED004_PickleRCE:
    """ADVANCED-004: Arbitrary code execution via pickle.loads."""

    def test_create_report_is_registered(self, capture):
        assert capture.has_tool("create_report")

    async def test_rce_payload_triggers_flag_in_sandbox(self, capture):
        """Malicious pickle payload must be detected and flag returned in sandbox."""
        result = await capture.call("create_report", data=PICKLE_PAYLOAD)
        assert_sandboxed(result)
        assert_flag(result, "ADVANCED-004")

    async def test_benign_pickle_also_triggers_sandbox(self, capture):
        """In sandbox mode, ANY pickle data triggers the flag (we don't deserialize)."""
        result = await capture.call("create_report", data=PICKLE_BENIGN)
        assert_sandboxed(result)
        assert_flag(result, "ADVANCED-004")

    async def test_invalid_base64_returns_error(self, capture):
        result = await capture.call("create_report", data=PICKLE_INVALID_B64)
        assert "invalid" in result.lower() or "error" in result.lower()

    async def test_sandbox_message_explains_risk(self, capture):
        result = await capture.call("create_report", data=PICKLE_PAYLOAD)
        assert "pickle" in result.lower() or "deserializ" in result.lower() or "SANDBOX" in result
