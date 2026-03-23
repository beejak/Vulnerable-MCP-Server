"""
Denial of Service Vulnerabilities:

ADVANCED-003: Resource Exhaustion (CWE-400) — unbounded recursion and combinatorial explosion
"""
from vulnerabilities.base import VulnerabilityModule, VulnerabilityMeta, Hint
from flags.flags import get_flag


class DoSModule(VulnerabilityModule):

    @property
    def metadata(self) -> list[VulnerabilityMeta]:
        return [
            VulnerabilityMeta(
                challenge_id="ADVANCED-003",
                title="Denial of Service via Resource Exhaustion",
                description=(
                    "fibonacci() uses exponential-time recursion with no depth limit. "
                    "generate_permutations() has no input length limit. "
                    "Either call can exhaust CPU/memory."
                ),
                category="dos",
                difficulty="advanced",
                cwe_id="CWE-400",
                cvss_score=7.5,
                hints=[
                    Hint(1, "What happens when you call fibonacci with a very large number?"),
                    Hint(2, "Recursive fibonacci(n) has O(2^n) time complexity — n=50 takes years."),
                    Hint(3, "Try fibonacci(45) — or generate_permutations with a 12+ char string."),
                ],
                flag_id="ADVANCED-003",
                remediation=(
                    "Enforce input bounds: validate n < 40 for fibonacci, len(text) < 8 for permutations. "
                    "Use memoization or iterative algorithms. "
                    "Implement per-request CPU time limits and memory quotas."
                ),
            )
        ]

    def register(self) -> None:
        app = self.app
        cfg = self.config

        @app.tool(
            description=(
                "Calculate the nth Fibonacci number using recursive computation. "
                "Returns the exact integer value."
            )
        )
        def fibonacci(n: int) -> str:
            """VULNERABILITY: exponential recursion with no depth limit."""
            if cfg.sandbox_mode and n > 35:
                return (
                    f"[SANDBOX] n={n} would cause resource exhaustion.\n"
                    f"Recursive fibonacci(n) has O(2^n) time complexity.\n"
                    f"fibonacci(50) would require ~10^10 operations.\n"
                    f"Flag: {get_flag('ADVANCED-003')}"
                )

            # VULNERABLE: no memoization, no depth limit, exponential time
            def fib(x: int) -> int:
                if x <= 1:
                    return x
                return fib(x - 1) + fib(x - 2)  # O(2^n) — intentionally inefficient

            try:
                result = fib(n)
                return str(result)
            except RecursionError:
                return f"RecursionError: n={n} exceeded Python recursion limit. Flag: {get_flag('ADVANCED-003')}"

        @app.tool(
            description=(
                "Generate all permutations of the input string. "
                "Returns the count and all permutations."
            )
        )
        def generate_permutations(text: str) -> str:
            """VULNERABILITY: no length limit — 16 chars = 20 trillion permutations."""
            import itertools
            import math

            total = math.factorial(len(text))

            if cfg.sandbox_mode and len(text) > 8:
                return (
                    f"[SANDBOX] '{text}' (length={len(text)}) would generate {total:,} permutations.\n"
                    f"This would exhaust memory and CPU.\n"
                    f"Flag: {get_flag('ADVANCED-003')}"
                )

            # VULNERABLE: no length check — factorial blowup
            try:
                perms = list(itertools.permutations(text))
                perm_strings = ["".join(p) for p in perms[:100]]  # show first 100
                preview = ", ".join(perm_strings[:10])
                return (
                    f"Generated {len(perms):,} permutations of '{text}'.\n"
                    f"First 10: {preview}"
                )
            except MemoryError:
                return f"MemoryError: '{text}' caused memory exhaustion. Flag: {get_flag('ADVANCED-003')}"

        @app.tool(
            description=(
                "Ping a host to check connectivity. "
                "Returns round-trip time statistics."
            )
        )
        def flood_requests(target: str, count: int = 10) -> str:
            """VULNERABILITY: no upper bound on count — can flood target with requests."""
            if cfg.sandbox_mode and count > 10:
                return (
                    f"[SANDBOX] Would send {count} requests to {target}.\n"
                    f"No upper bound on count — potential DoS amplification.\n"
                    f"Flag: {get_flag('ADVANCED-003')}"
                )

            return (
                f"Sent {count} ping requests to {target}.\n"
                f"(Training mode — no actual network requests made)"
            )
