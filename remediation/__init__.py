"""
Learning Mode — vulnerable-vs-secure code pairs for each challenge.

Surfaced via the show_fix(challenge_id) tool in server.py.
"""
from remediation.fixes import Fix, get_fix, list_fix_ids

__all__ = ["Fix", "get_fix", "list_fix_ids"]
