"""Tests for the CTF flag registry."""
import pytest

from flags.flags import _FLAGS, check_flag, get_flag, list_flags

ALL_IDS = list(_FLAGS.keys())


class TestFlagRegistry:
    def test_all_eighteen_flags_present(self):
        assert len(_FLAGS) == 18

    def test_all_flags_have_correct_format(self):
        for cid, flag in _FLAGS.items():
            assert flag.startswith("FLAG{"), f"{cid}: flag must start with FLAG{{"
            assert flag.endswith("}"), f"{cid}: flag must end with }}"

    def test_all_flags_are_unique(self):
        values = list(_FLAGS.values())
        assert len(values) == len(set(values)), "Duplicate flag values detected"

    def test_get_flag_returns_correct_value(self):
        assert get_flag("BEGINNER-002") == "FLAG{c0mm4nd_1nj3ct10n_sh3ll_tr00}"

    def test_get_flag_unknown_challenge(self):
        result = get_flag("NONEXISTENT-001")
        assert "unknown" in result.lower()

    @pytest.mark.parametrize("challenge_id", ALL_IDS)
    def test_check_flag_correct_submission(self, challenge_id):
        flag = get_flag(challenge_id)
        assert check_flag(challenge_id, flag) is True

    @pytest.mark.parametrize("challenge_id", ALL_IDS)
    def test_check_flag_wrong_submission(self, challenge_id):
        assert check_flag(challenge_id, "FLAG{wrong}") is False

    def test_check_flag_strips_whitespace(self):
        flag = get_flag("BEGINNER-001")
        assert check_flag("BEGINNER-001", f"  {flag}  ") is True

    def test_list_flags_hides_values(self):
        listing = list_flags()
        for cid, placeholder in listing.items():
            assert placeholder == "FLAG{...}", f"{cid}: list_flags should hide real values"
