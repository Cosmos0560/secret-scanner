"""The `rules` command: it lists every built-in rule and detector, agrees with the rules file, and
prints no example of a secret (PLAN.md D4, drift test of the Phase 5 scope)."""

from __future__ import annotations

import dataclasses
import json
from collections.abc import Callable

import pytest
import yaml

from secret_scanner import __version__
from secret_scanner.app.rules import run_rules
from secret_scanner.cli import main as cli_main
from secret_scanner.core.detect.entropy import (
    DEFAULT_BASE64_THRESHOLD,
    DEFAULT_HEX_THRESHOLD,
    HEX_MIN_LENGTH,
)
from secret_scanner.core.detect.private_key import HEADER_KEYWORD
from secret_scanner.core.errors import UsageError
from secret_scanner.core.fakes import build_fake, fake_entropy_token, fake_private_key
from secret_scanner.core.models import Confidence, Detector, OutputFormat, Severity
from secret_scanner.core.ruleinfo import (
    DETECTOR_INFOS,
    PRIVATE_KEY_KEYWORD,
    RuleInfo,
    info_for_rule,
    rule_infos,
)
from secret_scanner.core.rules import ENTROPY_BASE64_ID, ENTROPY_HEX_ID, PRIVATE_KEY_ID
from secret_scanner.render.rules_out import (
    NO_KEYWORDS,
    RULE_FIELDS,
    SCHEMA,
    render_rules_json,
    render_rules_table,
    rules_document,
)
from secret_scanner.services.loader import load_builtin_rules
from tests.helpers import PROJECT_ROOT, public_prefix_length

RULES_FILE = PROJECT_ROOT / "src" / "secret_scanner" / "rules" / "builtin.yaml"
DETECTOR_IDS = [PRIVATE_KEY_ID, ENTROPY_BASE64_ID, ENTROPY_HEX_ID]


def raw_rules() -> list[dict[str, object]]:
    """The rules file read by plain `yaml.safe_load`, independently of the product's loader."""
    document = yaml.safe_load(RULES_FILE.read_text(encoding="utf-8"))
    return list(document["rules"])


def listing() -> dict[str, object]:
    document = json.loads(run_rules(OutputFormat.JSON))
    assert isinstance(document, dict)
    return document


def listed_rules() -> list[dict[str, object]]:
    rules = listing()["rules"]
    assert isinstance(rules, list)
    return rules


# -- agreement with the rules file --------------------------------------------------------------


def test_the_listing_has_every_rule_of_the_file_in_order_then_the_three_detectors() -> None:
    ids = [rule["id"] for rule in listed_rules()]
    assert ids == [rule["id"] for rule in raw_rules()] + DETECTOR_IDS


def test_each_listed_rule_equals_its_entry_in_the_rules_file() -> None:
    listed = {rule["id"]: rule for rule in listed_rules()}
    for raw in raw_rules():
        entry = listed[raw["id"]]
        assert entry["name"] == raw["name"]
        assert entry["description"] == raw["description"]
        assert entry["severity"] == raw["severity"]
        assert entry["confidence"] == raw["confidence"]
        assert entry["keywords"] == raw["keywords"]
        assert entry["detector"] == "rule"


def test_the_table_lists_every_rule_with_its_severity_confidence_and_keywords() -> None:
    lines = run_rules(OutputFormat.TABLE).splitlines()
    for raw in raw_rules():
        (row,) = [line for line in lines if line.startswith(f"{raw['id']} ")]
        cells = row.split()
        assert cells[1:3] == [raw["severity"], raw["confidence"]]
        assert cells[3] == "rule"
        keywords = raw["keywords"]
        assert isinstance(keywords, list)
        assert row.endswith(", ".join(keywords))
        assert "  " + str(raw["description"]) in lines
    for rule_id in DETECTOR_IDS:
        assert any(line.startswith(f"{rule_id} ") for line in lines)


def test_the_listing_agrees_with_the_loaded_rules_and_states_the_rules_file_hash() -> None:
    builtin = load_builtin_rules()
    assert listing()["rules_sha256"] == builtin.sha256
    assert len(listed_rules()) == len(builtin.rules) + 3
    assert run_rules(OutputFormat.TABLE).splitlines()[1] == f"rules file sha256 {builtin.sha256}"


def test_the_json_has_the_documented_shape() -> None:
    document = listing()
    assert list(document) == ["schema", "tool", "rules_sha256", "rules"]
    assert document["schema"] == SCHEMA
    assert document["tool"] == {"name": "secret-scanner", "version": __version__}
    for rule in listed_rules():
        assert tuple(rule) == RULE_FIELDS


def test_the_output_is_ascii_deterministic_and_newline_terminated() -> None:
    for fmt in (OutputFormat.TABLE, OutputFormat.JSON):
        text = run_rules(fmt)
        assert text == run_rules(fmt)
        assert text.isascii()
        assert text.endswith("\n")
        assert "\r" not in text


def test_other_formats_are_for_findings_and_are_refused() -> None:
    with pytest.raises(UsageError, match="table or json"):
        run_rules(OutputFormat.JSONL)


# -- the detectors' own entries ------------------------------------------------------------------


def test_the_detector_entries_match_the_detectors_constants() -> None:
    assert HEADER_KEYWORD.decode("ascii") == PRIVATE_KEY_KEYWORD
    by_id = {info.id: info for info in DETECTOR_INFOS}
    assert [info.id for info in DETECTOR_INFOS] == DETECTOR_IDS
    assert by_id[PRIVATE_KEY_ID].detector is Detector.PRIVATE_KEY
    assert by_id[PRIVATE_KEY_ID].severity is Severity.CRITICAL
    assert by_id[PRIVATE_KEY_ID].keywords == (PRIVATE_KEY_KEYWORD,)
    assert by_id[ENTROPY_BASE64_ID].detector is Detector.ENTROPY
    assert by_id[ENTROPY_BASE64_ID].confidence is Confidence.LOW
    assert by_id[ENTROPY_HEX_ID].confidence is Confidence.MEDIUM
    assert str(DEFAULT_BASE64_THRESHOLD) in by_id[ENTROPY_BASE64_ID].description
    assert str(DEFAULT_HEX_THRESHOLD) in by_id[ENTROPY_HEX_ID].description
    assert str(HEX_MIN_LENGTH) in by_id[ENTROPY_HEX_ID].description
    assert all(info.keywords == () for info in DETECTOR_INFOS[1:])
    assert NO_KEYWORDS in run_rules(OutputFormat.TABLE)


def test_a_rule_info_has_no_field_that_could_hold_a_pattern_or_a_fake() -> None:
    names = {field.name for field in dataclasses.fields(RuleInfo)}
    assert names == {"id", "name", "description", "detector", "severity", "confidence", "keywords"}
    rule = load_builtin_rules().rules[0]
    info = info_for_rule(rule)
    assert (info.id, info.severity, info.confidence) == (rule.id, rule.severity, rule.confidence)
    assert rule_infos([rule])[0] == info
    assert rule_infos([rule])[1:] == DETECTOR_INFOS


def test_the_renderers_check_every_string_they_are_given() -> None:
    bad = dataclasses.replace(DETECTOR_INFOS[0], description="line one\x1b[31m")
    with pytest.raises(ValueError, match="rule description"):
        render_rules_json([bad], version="1", rules_sha256="0" * 64)
    with pytest.raises(ValueError, match="rule description"):
        render_rules_table([bad], version="1", rules_sha256="0" * 64)
    assert rules_document([], version="1", rules_sha256="0" * 64)["rules"] == []


# -- no secret -----------------------------------------------------------------------------------


def test_no_rule_fake_appears_in_the_listing(assert_not_leaked: Callable[..., None]) -> None:
    outputs = [run_rules(OutputFormat.TABLE), run_rules(OutputFormat.JSON)]
    for rule in load_builtin_rules().rules:
        fake = build_fake(rule, "listing")
        for text in outputs:
            assert_not_leaked(text, fake, allowed_shown=public_prefix_length(rule))
    key = fake_private_key("listing")
    body = "".join(line for line in key.splitlines() if not line.startswith("-----"))
    for text in outputs:
        assert_not_leaked(text, body)
        assert_not_leaked(text, fake_entropy_token("listing"))
        assert_not_leaked(text, fake_entropy_token("listing", kind="hex"))


# -- the command ----------------------------------------------------------------------------------


def test_the_command_prints_the_table_by_default_and_json_on_request(
    capsys: pytest.CaptureFixture[str],
) -> None:
    assert cli_main.main(["rules"]) == 0
    captured = capsys.readouterr()
    assert captured.out == run_rules(OutputFormat.TABLE)
    assert captured.err == ""
    assert cli_main.main(["rules", "--format", "json"]) == 0
    captured = capsys.readouterr()
    assert json.loads(captured.out)["schema"] == SCHEMA
    assert captured.err == ""


@pytest.mark.parametrize("argv", [["rules", "--format", "sarif"], ["rules", "--format", "jsonl"]])
def test_the_command_accepts_only_table_and_json(
    capsys: pytest.CaptureFixture[str], argv: list[str]
) -> None:
    assert cli_main.main(argv) == 2
    captured = capsys.readouterr()
    assert captured.out == ""
    assert "invalid choice" in captured.err


def test_the_command_takes_no_path_and_no_output_option(
    capsys: pytest.CaptureFixture[str],
) -> None:
    assert cli_main.main(["rules", "somewhere"]) == 2
    assert cli_main.main(["rules", "--output", "x"]) == 2
    assert capsys.readouterr().out == ""
