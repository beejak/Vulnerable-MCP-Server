"""
Tests for the CTF helper tool system.

Tests the underlying data (YAML challenge files, flag registry) that powers
list_challenges(), get_hint(), get_challenge_details(), and submit_flag().
These functions are defined in server.py and tested here by calling the
YAML and flag modules directly.
"""
import os

import pytest
import yaml

from flags.flags import check_flag, get_flag

CHALLENGES_DIR = os.path.join(
    os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
    "challenges"
)

REQUIRED_YAML_FIELDS = {
    "id", "title", "category", "difficulty", "cwe", "cvss",
    "points", "tools", "description", "objective",
    "exploitation_steps", "hints", "flag", "remediation",
}

EXPECTED_CHALLENGE_IDS = {
    "BEGINNER-001", "BEGINNER-002", "BEGINNER-003", "BEGINNER-004",
    "INTERMEDIATE-001", "INTERMEDIATE-002", "INTERMEDIATE-003", "INTERMEDIATE-004",
    "ADVANCED-001", "ADVANCED-002", "ADVANCED-003", "ADVANCED-004",
}


def load_all_challenges() -> list[dict]:
    challenges = []
    for fname in sorted(os.listdir(CHALLENGES_DIR)):
        if not fname.endswith(".yaml"):
            continue
        with open(os.path.join(CHALLENGES_DIR, fname)) as f:
            data = yaml.safe_load(f)
        challenges.extend(data.get("challenges", []))
    return challenges


ALL_CHALLENGES = load_all_challenges()


class TestChallengeYAML:
    def test_yaml_files_exist(self):
        yamls = [f for f in os.listdir(CHALLENGES_DIR) if f.endswith(".yaml")]
        assert len(yamls) >= 3, "Expected at least beginner/intermediate/advanced YAML files"

    def test_all_twelve_challenges_present(self):
        ids = {ch["id"] for ch in ALL_CHALLENGES}
        missing = EXPECTED_CHALLENGE_IDS - ids
        assert not missing, f"Missing challenge IDs in YAML: {missing}"

    @pytest.mark.parametrize("challenge", ALL_CHALLENGES, ids=lambda c: c["id"])
    def test_required_fields_present(self, challenge):
        missing = REQUIRED_YAML_FIELDS - set(challenge.keys())
        assert not missing, f"{challenge['id']}: missing YAML fields: {missing}"

    @pytest.mark.parametrize("challenge", ALL_CHALLENGES, ids=lambda c: c["id"])
    def test_flag_matches_registry(self, challenge):
        yaml_flag = challenge["flag"]
        registry_flag = get_flag(challenge["id"])
        assert yaml_flag == registry_flag, (
            f"{challenge['id']}: YAML flag {yaml_flag!r} != "
            f"registry flag {registry_flag!r}"
        )

    @pytest.mark.parametrize("challenge", ALL_CHALLENGES, ids=lambda c: c["id"])
    def test_three_hints_present(self, challenge):
        hints = challenge.get("hints", [])
        levels = {h["level"] for h in hints}
        assert {1, 2, 3} == levels, (
            f"{challenge['id']}: must have hints at levels 1, 2, 3. Got: {levels}"
        )

    @pytest.mark.parametrize("challenge", ALL_CHALLENGES, ids=lambda c: c["id"])
    def test_exploitation_steps_not_empty(self, challenge):
        steps = challenge.get("exploitation_steps", [])
        assert len(steps) >= 2, f"{challenge['id']}: need at least 2 exploitation steps"

    @pytest.mark.parametrize("challenge", ALL_CHALLENGES, ids=lambda c: c["id"])
    def test_difficulty_valid(self, challenge):
        valid = {"beginner", "intermediate", "advanced"}
        assert challenge["difficulty"] in valid, \
            f"{challenge['id']}: difficulty must be one of {valid}"

    @pytest.mark.parametrize("challenge", ALL_CHALLENGES, ids=lambda c: c["id"])
    def test_cwe_format(self, challenge):
        assert challenge["cwe"].startswith("CWE-"), \
            f"{challenge['id']}: cwe must start with CWE-"

    @pytest.mark.parametrize("challenge", ALL_CHALLENGES, ids=lambda c: c["id"])
    def test_cvss_in_range(self, challenge):
        score = float(challenge["cvss"])
        assert 0 < score <= 10.0, f"{challenge['id']}: cvss must be 0–10"

    @pytest.mark.parametrize("challenge", ALL_CHALLENGES, ids=lambda c: c["id"])
    def test_points_positive(self, challenge):
        assert challenge["points"] > 0, f"{challenge['id']}: points must be positive"


class TestFlagSubmission:
    @pytest.mark.parametrize("challenge", ALL_CHALLENGES, ids=lambda c: c["id"])
    def test_correct_flag_accepted(self, challenge):
        cid = challenge["id"]
        flag = challenge["flag"]
        assert check_flag(cid, flag) is True

    @pytest.mark.parametrize("challenge", ALL_CHALLENGES, ids=lambda c: c["id"])
    def test_wrong_flag_rejected(self, challenge):
        cid = challenge["id"]
        assert check_flag(cid, "FLAG{definitely_wrong}") is False

    def test_empty_flag_rejected(self):
        assert check_flag("BEGINNER-001", "") is False

    def test_flag_with_leading_whitespace_accepted(self):
        flag = get_flag("BEGINNER-002")
        assert check_flag("BEGINNER-002", f"  {flag}  ") is True
