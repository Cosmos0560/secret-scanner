"""Configuration and baseline files (PLAN.md D9, D19): schema, bounds, round trip."""

from __future__ import annotations

from typing import Any

import pytest

from secret_scanner.core.detect.entropy import EntropyConfig
from secret_scanner.core.errors import ConfigError
from secret_scanner.core.limits import DEFAULT_LIMITS
from secret_scanner.core.models import Confidence, Severity, SuppressionEntry
from secret_scanner.core.suppress import baseline_document
from secret_scanner.services.config import (
    BASELINE_HEADER,
    ScanConfig,
    load_baseline,
    load_config,
    parse_config,
    serialize_baseline,
)
from secret_scanner.services.loader import dump_yaml, parse_yaml
from tests.test_suppress import finding

BUILTIN = frozenset({"aws-access-key-id", "npm-token"})


def good_rule() -> dict[str, Any]:
    return {
        "id": "custom-demo",
        "name": "Demo",
        "description": "A demo rule.",
        "regex": "demo_(?P<secret>[A-Za-z0-9]{24})",
        "keywords": ["demo_"],
        "severity": "high",
        "confidence": "high",
        "shown_chars": 0,
        "min_secret_bits": 100,
        "fake": [{"parts": ["demo", "_"]}, {"charset": "base62", "length": 24}],
    }


def parse(document: object) -> ScanConfig:
    return parse_config(document, builtin_rule_ids=BUILTIN)


# -- configuration ----------------------------------------------------------------------------


def test_the_minimal_document_gives_the_defaults() -> None:
    config = parse({"version": 1})
    assert config == ScanConfig()
    assert config.limits == DEFAULT_LIMITS
    assert config.entropy == EntropyConfig()


def test_a_full_document_is_parsed() -> None:
    config = parse(
        {
            "version": 1,
            "exclude": ["vendor/**", "**/*.lock"],
            "min_confidence": "low",
            "fail_on": "high",
            "entropy": {
                "enabled": False,
                "base64_threshold": 5,
                "hex_threshold": 3.5,
                "min_length": 24,
            },
            "disable_rules": ["npm-token"],
            "extra_rules": [good_rule()],
            "limits": {"max_files": 1000, "max_file_bytes": 1024},
        }
    )
    assert config.exclude == ("vendor/**", "**/*.lock")
    assert config.min_confidence is Confidence.LOW
    assert config.fail_on is Severity.HIGH
    assert config.entropy == EntropyConfig(False, 5.0, 3.5, 24)
    assert config.disable_rules == ("npm-token",)
    assert [rule.id for rule in config.extra_rules] == ["custom-demo"]
    assert (config.limits.max_files, config.limits.max_file_bytes) == (1000, 1024)


def test_null_sections_mean_not_set() -> None:
    config = parse(
        {"version": 1, "exclude": None, "entropy": None, "disable_rules": None, "limits": None}
    )
    assert config == ScanConfig()


REFUSED: list[tuple[object, str]] = [
    ([], "must be a mapping"),
    ({}, "version must be 1"),
    ({"version": 2}, "version must be 1"),
    ({"version": True}, "version must be 1"),
    ({"version": 1, "surprise": 1}, "unknown key"),
    ({"version": 1, "exclude": "vendor/**"}, "exclude: must be a list"),
    ({"version": 1, "exclude": [5]}, "every entry must be a string"),
    ({"version": 1, "exclude": ["/abs"]}, "must be relative"),
    ({"version": 1, "exclude": ["a"] * 257}, "more than 256"),
    ({"version": 1, "min_confidence": "certain"}, "min_confidence: must be one of"),
    ({"version": 1, "min_confidence": 3}, "min_confidence: must be one of"),
    ({"version": 1, "fail_on": "bad"}, "fail_on: must be one of"),
    ({"version": 1, "entropy": "on"}, "entropy: must be a mapping"),
    ({"version": 1, "entropy": {"surprise": 1}}, "unknown key"),
    ({"version": 1, "entropy": {"enabled": "yes"}}, "enabled: must be true or false"),
    ({"version": 1, "entropy": {"base64_threshold": "high"}}, "base64_threshold: must be a number"),
    ({"version": 1, "entropy": {"hex_threshold": True}}, "hex_threshold: must be a number"),
    ({"version": 1, "entropy": {"min_length": 20.5}}, "min_length: must be an integer"),
    ({"version": 1, "entropy": {"min_length": True}}, "min_length: must be an integer"),
    ({"version": 1, "entropy": {"base64_threshold": 3.0}}, "between 3.5 and 6"),
    ({"version": 1, "entropy": {"base64_threshold": 6.5}}, "between 3.5 and 6"),
    ({"version": 1, "entropy": {"hex_threshold": 2.0}}, "between 2.5 and 4"),
    ({"version": 1, "entropy": {"min_length": 8}}, "between 16 and 64"),
    ({"version": 1, "entropy": {"min_length": 200}}, "between 16 and 64"),
    ({"version": 1, "disable_rules": ["no-such-rule"]}, "unknown rule id"),
    (
        {"version": 1, "disable_rules": ["npm-token", "npm-token"]},
        "duplicate rule id",
    ),
    ({"version": 1, "extra_rules": "x"}, "must be a list"),
    ({"version": 1, "extra_rules": []}, "must hold 1 to"),
    ({"version": 1, "limits": "x"}, "limits: must be a mapping"),
    ({"version": 1, "limits": {"max_nothing": 1}}, "unknown limit"),
    ({"version": 1, "limits": {"max_files": 0}}, "at least 1"),
    ({"version": 1, "limits": {"max_files": 10_000_000}}, "hard ceiling"),
    ({"version": 1, "limits": {"max_files": 200_001}}, "can only be lowered"),
    ({"version": 1, "limits": {"max_files": "many"}}, "must be an integer"),
]


@pytest.mark.parametrize(("document", "reason"), REFUSED)
def test_malformed_configurations_are_refused(document: object, reason: str) -> None:
    with pytest.raises(ConfigError, match=reason):
        parse(document)


def test_extra_rule_ids_need_the_custom_prefix() -> None:
    rule = good_rule()
    rule["id"] = "npm-token"
    with pytest.raises(ConfigError, match="must start with 'custom-'"):
        parse({"version": 1, "extra_rules": [rule]})


def test_an_extra_rule_is_checked_against_the_lowered_limits() -> None:
    rule = good_rule()
    document = {"version": 1, "extra_rules": [rule], "limits": {"max_pattern_chars": 10}}
    with pytest.raises(ConfigError, match="regex"):
        parse(document)


def test_a_disabled_rule_may_be_a_custom_one() -> None:
    config = parse({"version": 1, "extra_rules": [good_rule()], "disable_rules": ["custom-demo"]})
    assert config.disable_rules == ("custom-demo",)


def test_load_config_goes_through_the_strict_loader() -> None:
    config = load_config(b"version: 1\nfail_on: medium\n", builtin_rule_ids=BUILTIN)
    assert config.fail_on is Severity.MEDIUM
    for text, reason in [
        (b"version: 1\nversion: 1\n", "duplicate key"),
        (b"version: &a 1\n", "anchors are not allowed"),
        (b"version: yes\n", "version must be 1"),  # a YAML 1.1 boolean, not the integer 1
        (b"\xff\xfe", "not valid UTF-8"),
        (b"version: 1\n" + b"# " + b"x" * 300_000, "larger than the limit"),
    ]:
        with pytest.raises(ConfigError, match=reason):
            load_config(text, builtin_rule_ids=BUILTIN)


# -- baseline ---------------------------------------------------------------------------------


def test_a_baseline_round_trips_through_the_file_format() -> None:
    findings = [
        finding("a" * 32, path_key="src/app.py", rule_id="npm-token"),
        finding(
            "b" * 32,
            path_key='odd/on yes 0755 #hash: "q"\'.txt',
            path='odd/on yes 0755 #hash: "q"\'.txt',
            rule_id="aws-access-key-id",
        ),
        finding(
            "c" * 32,
            path_key="uni/café.txt",
            path="uni/café.txt",
            rule_id="npm-token",
        ),
    ]
    document = baseline_document(findings, paths=["vendor/**", "**/*.snap"])
    data = serialize_baseline(document)
    assert data.startswith(BASELINE_HEADER.encode("ascii"))
    assert data.isascii()
    loaded = load_baseline(data)
    assert loaded.paths == ("vendor/**", "**/*.snap")
    # sorted by path: odd/..., src/app.py, uni/...
    assert [(e.fingerprint, e.rule, e.path) for e in loaded.entries] == [
        ("b" * 32, "aws-access-key-id", 'odd/on yes 0755 #hash: "q"\'.txt'),
        ("a" * 32, "npm-token", "src/app.py"),
        ("c" * 32, "npm-token", "uni/café.txt"),
    ]
    assert loaded.entries[1] == SuppressionEntry(
        "a" * 32, "npm-token", "src/app.py", "TODO: review"
    )


def test_an_empty_baseline_is_written_and_read() -> None:
    data = serialize_baseline(baseline_document([]))
    assert load_baseline(data).entries == ()


@pytest.mark.parametrize(
    ("text", "reason"),
    [
        (b"suppress: []\n", "version must be 1"),
        (b"version: 1\nsuppress:\n  - fingerprint: nothex\n", "lower-case hex"),
        (b"version: 1\nsuppress:\n  - fingerprint: " + b"a" * 32 + b"\n    x: 1\n", "unknown key"),
        (b"version: 1\nsurprise: 1\n", "unknown key"),
        (b"version: 1\nsuppress: &x []\n", "anchors are not allowed"),
        (b"version: 1\nsuppress: !!python/object {}\n", "explicit tags are not allowed"),
        (b"- not\n- a mapping\n", "must be a mapping"),
    ],
)
def test_a_malformed_baseline_is_refused(text: bytes, reason: str) -> None:
    with pytest.raises(ConfigError, match=reason):
        load_baseline(text)


def test_the_baseline_size_cap_is_enforced_before_parsing() -> None:
    limits = DEFAULT_LIMITS
    assert limits.max_baseline_bytes == 16 * 1024 * 1024
    big = b"version: 1\n# " + b"x" * (limits.max_baseline_bytes + 1)
    with pytest.raises(ConfigError, match="larger than the limit"):
        load_baseline(big)


def test_dump_yaml_round_trips_awkward_strings() -> None:
    data: dict[str, object] = {
        "plain": "text",
        "bool-like": ["yes", "no", "on", "off", "null", "~", "true"],
        "number-like": ["0755", "1e3", "1:30", "2026-01-01", "0x1f", "1_000"],
        "special": ["# not a comment", "key: value", "- dash", "'", '"', "\\", "a\\nb"],
        "unicode": ["café", "日本", "\U0001f600"],
        "empty": "",
    }
    text = dump_yaml(data)
    assert text.isascii()
    assert parse_yaml(text.encode("ascii"), max_bytes=10_000) == data
