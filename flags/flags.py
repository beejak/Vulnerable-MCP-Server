"""
CTF flag registry for the Vulnerable MCP Server.

All flags are training-only values. They represent successful exploitation
of a specific vulnerability challenge.
"""

_FLAGS: dict[str, str] = {
    # Tier 1 - Beginner
    "BEGINNER-001": "FLAG{t00l_p0is0ning_h1dd3n_1nstruct10ns}",
    "BEGINNER-002": "FLAG{c0mm4nd_1nj3ct10n_sh3ll_tr00}",
    "BEGINNER-003": "FLAG{p4th_tr4v3rs4l_d0t_d0t_sl4sh}",
    "BEGINNER-004": "FLAG{1nd1r3ct_pr0mpt_1nj3ct10n_url}",
    # Tier 2 - Intermediate
    "INTERMEDIATE-001": "FLAG{4uth_byp4ss_n0_ch3ck}",
    "INTERMEDIATE-002": "FLAG{sql_1nj3ct10n_f_str1ng}",
    "INTERMEDIATE-003": "FLAG{s3cr3t_l34k_1n_d3scr1pt10n}",
    "INTERMEDIATE-004": "FLAG{st4t3_m4n1pul4t10n_un1n1t}",
    # Tier 3 - Advanced
    "ADVANCED-001": "FLAG{ssrf_1nt3rn4l_n3tw0rk}",
    "ADVANCED-002": "FLAG{t3mpl4t3_1nj3ct10n_3v4l}",
    "ADVANCED-003": "FLAG{d0s_r3s0urc3_3xh4ust10n}",
    "ADVANCED-004": "FLAG{p1ckl3_d3s3r14l1z4t10n_rce}",
}


def get_flag(challenge_id: str) -> str:
    """Return the flag for a given challenge ID."""
    return _FLAGS.get(challenge_id, "FLAG{unknown_challenge}")


def check_flag(challenge_id: str, submitted: str) -> bool:
    """Return True if the submitted flag matches the expected flag."""
    expected = _FLAGS.get(challenge_id, "")
    return bool(expected) and expected == submitted.strip()


def list_flags() -> dict[str, str]:
    """Return all challenge IDs (without flag values) for listing."""
    return {k: "FLAG{...}" for k in _FLAGS}


__all__ = ["get_flag", "check_flag", "list_flags"]
