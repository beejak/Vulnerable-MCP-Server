"""
Tests that verify sandbox mode behaviour.

Sandbox mode must:
1. Detect attack indicators in every vulnerable tool
2. Return the flag + educational message without executing for real
3. Never return real system output when sandbox=True
4. Return [SANDBOX] marker in all intercepted responses
"""
from tests.helpers import assert_flag, assert_sandboxed


class TestSandboxCommandInjection:
    async def test_semicolon_sandboxed(self, capture):
        result = await capture.call("run_command", command="echo x; whoami")
        assert_sandboxed(result)
        assert_flag(result, "BEGINNER-002")

    async def test_real_output_not_present(self, capture):
        """Sandbox must not pass the command to the OS."""
        result = await capture.call("run_command", command="echo REAL_EXEC_MARKER; id")
        assert "REAL_EXEC_MARKER" not in result or "[SANDBOX]" in result

    async def test_injection_chars_listed(self, capture):
        result = await capture.call("run_command", command="ls; cat /etc/passwd")
        assert ";" in result or "injection" in result.lower()


class TestSandboxPathTraversal:
    async def test_traversal_reads_config_appends_flag(self, capture):
        # config.py exists in CWD and contains "training_mode" → flag appended
        result = await capture.call("read_file", path="config.py")
        assert "FLAG{" in result

    async def test_traversal_reads_flags_file(self, capture):
        # flags/flags.py contains FLAG{ values → triggers the reward
        result = await capture.call("read_file", path="flags/flags.py")
        assert "FLAG{" in result


class TestSandboxSQLInjection:
    async def test_tautology_flagged(self, capture):
        result = await capture.call("query_users", username="' OR '1'='1")
        assert_flag(result, "INTERMEDIATE-002")


class TestSandboxSSRF:
    async def test_localhost_sandboxed(self, capture):
        result = await capture.call("fetch_url", url="http://localhost/admin")
        assert "FLAG{" in result

    async def test_metadata_sandboxed(self, capture):
        result = await capture.call("fetch_url", url="http://169.254.169.254/latest/meta-data/")
        assert "FLAG{" in result


class TestSandboxTemplateInjection:
    async def test_subclasses_flagged(self, capture):
        result = await capture.call(
            "render_template",
            template="{{ ''.__class__.__mro__[1].__subclasses__() }}"
        )
        assert_flag(result, "ADVANCED-002")


class TestSandboxDoS:
    async def test_large_fibonacci_sandboxed(self, capture):
        result = await capture.call("fibonacci", n=50)
        assert_sandboxed(result)

    async def test_large_permutations_sandboxed(self, capture):
        result = await capture.call("generate_permutations", text="abcdefghijk")
        assert_sandboxed(result)

    async def test_flood_sandboxed(self, capture):
        result = await capture.call("flood_requests", target="http://example.com", count=1000)
        assert_sandboxed(result)


class TestSandboxPickle:
    async def test_pickle_payload_sandboxed(self, capture):
        from tests.fixtures.payloads import PICKLE_PAYLOAD
        result = await capture.call("create_report", data=PICKLE_PAYLOAD)
        assert_sandboxed(result)
        assert_flag(result, "ADVANCED-004")
