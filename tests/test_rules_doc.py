"""docs/rules.md against the code: the generated rule table, the rules hash and every number the
text quotes (PLAN.md Phase 6: "generated rule table with a drift test")."""

from __future__ import annotations

from secret_scanner.core import limits
from secret_scanner.core.detect import entropy, private_key
from secret_scanner.core.models import Detector
from secret_scanner.core.ruleinfo import rule_infos
from secret_scanner.services.loader import load_builtin_rules
from tests.doc_samples import RULES_TABLE_END, RULES_TABLE_START, rules_markdown_table
from tests.helpers import PROJECT_ROOT

DOC = (PROJECT_ROOT / "docs" / "rules.md").read_text(encoding="utf-8")
TEXT = " ".join(DOC.split())


def test_the_table_is_the_generated_one() -> None:
    start = DOC.index(RULES_TABLE_START) + len(RULES_TABLE_START)
    end = DOC.index(RULES_TABLE_END)
    assert DOC[start:end].strip("\n") == rules_markdown_table()
    assert DOC.count(RULES_TABLE_START) == DOC.count(RULES_TABLE_END) == 1


def test_the_table_lists_every_rule_and_detector_once() -> None:
    builtin = load_builtin_rules()
    infos = rule_infos(builtin.rules)
    rows = rules_markdown_table().splitlines()[2:]
    assert len(rows) == len(infos) == len(builtin.rules) + 3
    for info, row in zip(infos, rows, strict=True):
        assert row.startswith(f"| `{info.id}` | ")
        assert row.count("|") == 8, "a description or keyword may not hold a table separator"
    regex_rules = [info for info in infos if info.detector is Detector.RULE]
    assert f"{len(regex_rules)} token-format rules" in TEXT
    assert "the private key detector and the two entropy detectors" in TEXT


def test_the_rules_hash_is_the_one_the_tool_reports() -> None:
    assert f"`{load_builtin_rules().sha256}`" in DOC


def test_the_entropy_numbers_are_the_detectors() -> None:
    low, high = entropy.BASE64_THRESHOLD_BOUNDS
    hex_low, hex_high = entropy.HEX_THRESHOLD_BOUNDS
    length_low, length_high = entropy.MIN_LENGTH_BOUNDS
    token_limit = limits.MAX_ENTROPY_TOKEN_CHARS
    for sentence in (
        f"of {entropy.DEFAULT_MIN_LENGTH} to {token_limit} characters",
        f"runs of {entropy.HEX_MIN_LENGTH} to {token_limit} hex digits",
        f"{entropy.DEFAULT_BASE64_THRESHOLD} bits per character for base64",
        f"and {entropy.DEFAULT_HEX_THRESHOLD} for hex",
        f"(base64 {low} to {high}, hex {hex_low} to {hex_high})",
        f"the minimum length ({length_low} to {length_high})",
    ):
        assert sentence in TEXT, sentence


def test_the_private_key_numbers_are_the_detectors() -> None:
    assert f"at most {limits.MAX_KEY_LINES} body lines" in TEXT
    assert f"at least {private_key.MIN_BODY_CHARS} base64 characters of body" in TEXT


def test_the_document_holds_no_example_secret_and_is_ascii() -> None:
    assert DOC.isascii()
    assert "No example secret is listed here" in TEXT
