"""The strict YAML loader (PLAN.md D19) and the rule schema (PLAN.md D4): every refusal, and the
built-in rules file itself."""

from __future__ import annotations

import copy
import hashlib
from dataclasses import replace
from importlib import resources
from typing import Any

import pytest

from secret_scanner.core.errors import ConfigError
from secret_scanner.core.limits import DEFAULT_LIMITS
from secret_scanner.core.models import Checksum, Confidence, Detector, Severity
from secret_scanner.core.rules import (
    CUSTOM_ID_PREFIX,
    RESERVED_IDS,
    is_kebab_case,
    parse_rule,
    parse_rule_list,
    parse_rules_document,
    rule_ids,
)
from secret_scanner.services import loader
from secret_scanner.services.loader import (
    load_builtin_rules,
    load_rules_from_bytes,
    parse_yaml,
)

BIG = 1_000_000


def _parse(text: str) -> object:
    return parse_yaml(text.encode("utf-8"), max_bytes=BIG)


def _refused(text: str) -> ConfigError:
    with pytest.raises(ConfigError) as caught:
        _parse(text)
    return caught.value


# -- the strict loader ------------------------------------------------------------------------


def test_plain_documents_load_as_plain_data() -> None:
    assert _parse("a: 1\nb: [x, y]\nc: {d: e}\n") == {"a": 1, "b": ["x", "y"], "c": {"d": "e"}}
    assert _parse("") is None
    assert _parse("# only a comment\n") is None
    assert _parse(chr(0xFEFF) + "a: 1\n") == {"a": 1}


def test_duplicate_keys_are_refused_without_naming_the_key() -> None:
    error = _refused("a: 1\nsecretkey: 2\nsecretkey: 3\n")
    assert "duplicate key" in str(error)
    assert "line 3" in str(error)
    assert "secretkey" not in str(error)
    assert "duplicate key" in str(_refused("outer:\n  a: 1\n  a: 2\n"))
    assert "duplicate key" in str(_refused("{a: 1, a: 2}"))


def test_distinct_keys_of_different_types_are_not_duplicates() -> None:
    assert _parse("1: a\n'1': b\n") == {1: "a", "1": "b"}


def test_aliases_and_anchors_are_refused() -> None:
    assert "aliases" in str(_refused("a: &x 1\nb: *x\n")) or "anchors" in str(
        _refused("a: &x 1\nb: *x\n")
    )
    assert "anchors" in str(_refused("a: &x [1, 2]\n"))
    assert "aliases" in str(_refused("a: [1]\nb: *missing\n"))
    bomb = "a: &a [x, x]\nb: &b [*a, *a]\nc: &c [*b, *b]\nd: [*c, *c]\n"
    assert isinstance(_refused(bomb), ConfigError)


def test_explicit_tags_are_refused() -> None:
    for text in [
        "a: !!python/object/apply:os.system ['x']\n",
        "a: !!str 5\n",
        "a: !custom value\n",
        "a: !!binary aGVsbG8=\n",
        "a: !!set {x}\n",
        "!!map {a: 1}\n",
        "a: !!seq [1]\n",
    ]:
        assert "explicit tags" in str(_refused(text)), text


def test_merge_keys_are_refused() -> None:
    assert "merge keys" in str(_refused("base: {a: 1}\nother:\n  <<: {a: 2}\n"))


def test_multiple_documents_are_refused() -> None:
    assert isinstance(_refused("a: 1\n---\nb: 2\n"), ConfigError)


def test_oversize_input_is_refused_before_parsing() -> None:
    with pytest.raises(ConfigError, match="larger than the limit"):
        parse_yaml(b"a: 1\n" * 100, max_bytes=10)
    assert parse_yaml(b"a: 1\n", max_bytes=5) == {"a": 1}


def test_invalid_utf8_and_utf16_are_refused() -> None:
    with pytest.raises(ConfigError, match="not valid UTF-8"):
        parse_yaml(b"a: \xff\xfe\n", max_bytes=BIG)
    with pytest.raises(ConfigError, match="not valid UTF-8"):
        parse_yaml("a: 1\n".encode("utf-16"), max_bytes=BIG)


def test_syntax_errors_carry_a_position_and_no_content() -> None:
    error = _refused("a: [1, 2\nb: topsecretvalue: x\n")
    assert "invalid YAML" in str(error)
    assert "line" in str(error)
    assert "topsecretvalue" not in str(error)


def test_control_characters_are_refused() -> None:
    assert isinstance(_refused("a: \x00\n"), ConfigError)
    assert isinstance(_refused("a: \x07bell\n"), ConfigError)


@pytest.mark.parametrize(
    "depth",
    [
        # Any depth past the interpreter's recursion limit takes the same path. 600 levels are
        # enough and cheap; 3000 (about 3 s under coverage) runs in the full gate and CI.
        pytest.param(600, id="600"),
        pytest.param(3_000, id="3000", marks=pytest.mark.slow),
    ],
)
def test_deep_nesting_is_refused_not_a_crash(depth: int) -> None:
    assert "nested too deeply" in str(_refused("[" * depth))


def test_sane_nesting_still_loads() -> None:
    assert isinstance(_parse("a: " + "[" * 100 + "]" * 100), dict)


def test_yaml_1_1_surprises_come_back_as_non_strings() -> None:
    data = _parse("a: yes\nb: 0755\nc: 1:30\nd: 2026-01-01\ne: 1_000\nf: ~\ng: on\n")
    assert isinstance(data, dict)
    assert not isinstance(data["d"], str)  # a date object
    assert {key: value for key, value in data.items() if key != "d"} == {
        "a": True,
        "b": 493,
        "c": 90,
        "e": 1000,
        "f": None,
        "g": True,
    }


def test_loader_never_uses_the_unsafe_apis() -> None:
    import ast
    import inspect

    tree = ast.parse(inspect.getsource(loader))
    banned = {"load", "load_all", "unsafe_load", "full_load", "FullLoader", "UnsafeLoader"}
    used = {n.attr for n in ast.walk(tree) if isinstance(n, ast.Attribute) and n.attr in banned}
    assert used == set()


# -- the built-in rules -----------------------------------------------------------------------


def test_builtin_rules_load_with_their_hash() -> None:
    ruleset = load_builtin_rules()
    raw = resources.files("secret_scanner").joinpath("rules", "builtin.yaml").read_bytes()
    assert ruleset.sha256 == hashlib.sha256(raw).hexdigest()
    assert len(ruleset.rules) == 13
    assert len(ruleset.rules) <= DEFAULT_LIMITS.max_rules


def test_builtin_rule_ids_are_the_planned_set_and_none_is_reserved() -> None:
    ids = set(rule_ids(load_builtin_rules().rules))
    assert ids == {
        "aws-access-key-id",
        "aws-secret-access-key",
        "github-token",
        "github-fine-grained-pat",
        "gitlab-pat",
        "slack-token",
        "slack-webhook-url",
        "stripe-secret-key",
        "google-api-key",
        "npm-token",
        "pypi-token",
        "sendgrid-api-key",
        "azure-storage-account-key",
    }
    assert ids.isdisjoint(RESERVED_IDS)


def test_every_builtin_rule_is_within_the_guard_and_the_schema_promises() -> None:
    for rule in load_builtin_rules().rules:
        assert rule.detector is Detector.RULE
        assert rule.pattern.cost <= DEFAULT_LIMITS.max_pattern_cost, rule.id
        assert rule.pattern.width_max <= DEFAULT_LIMITS.max_match_chars, rule.id
        assert len(rule.pattern.source) <= DEFAULT_LIMITS.max_pattern_chars, rule.id
        assert 64 <= rule.min_secret_bits <= rule.pattern.secret_bits, rule.id
        assert rule.shown_chars <= min(12, rule.pattern.secret_min_width // 4), rule.id
        assert rule.shown_chars <= rule.pattern.secret_public_chars, rule.id
        assert 1 <= len(rule.keywords) <= DEFAULT_LIMITS.max_keywords_per_rule, rule.id
        assert rule.keywords == tuple(k.lower() for k in rule.keywords), rule.id
        assert rule.fake, rule.id
        assert is_kebab_case(rule.id)


def test_checksum_and_context_rules_are_the_expected_ones() -> None:
    rules = {rule.id: rule for rule in load_builtin_rules().rules}
    assert [r.id for r in rules.values() if r.checksum] == ["github-token"]
    assert rules["github-token"].checksum is Checksum.GITHUB_CRC32
    assert [r.id for r in rules.values() if r.context] == ["aws-secret-access-key"]
    assert rules["aws-secret-access-key"].context == ("aws", "secret")
    assert rules["aws-secret-access-key"].confidence is Confidence.MEDIUM
    assert rules["slack-webhook-url"].severity is Severity.MEDIUM


# -- the schema -------------------------------------------------------------------------------


def _good_rule() -> dict[str, Any]:
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


def _document(*rules: dict[str, Any]) -> dict[str, Any]:
    return {"version": 1, "rules": list(rules)}


def _bad(mutate: Any, *, match: str) -> None:
    rule = _good_rule()
    mutate(rule)
    with pytest.raises(ConfigError, match=match):
        parse_rule(rule, "rules[0]")


def test_a_good_rule_parses() -> None:
    rule = parse_rule(_good_rule(), "rules[0]", id_prefix=CUSTOM_ID_PREFIX)
    assert rule.id == "custom-demo"
    assert rule.min_entropy is None
    assert rule.checksum is None
    assert rule.context == ()
    assert rule.pattern.search(b"demo_" + b"A" * 24) is not None


def test_optional_fields_parse() -> None:
    data = _good_rule()
    data.update({"min_entropy": 3, "context": ["token", "x"]})
    rule = parse_rule(data, "rules[0]")
    assert rule.min_entropy == 3.0
    assert rule.context == ("token", "x")
    long_fake = _good_rule()
    long_fake.update(
        {
            "regex": "ghx_(?P<secret>[A-Za-z0-9]{36})",
            "checksum": "github-crc32",
            "fake": [{"parts": ["ghx", "_"]}, {"charset": "base62", "length": 36}],
        }
    )
    assert parse_rule(long_fake, "rules[0]").checksum is Checksum.GITHUB_CRC32
    short_fake = _good_rule()
    short_fake["checksum"] = "github-crc32"
    with pytest.raises(ConfigError, match="too short for the checksum"):
        parse_rule(short_fake, "rules[0]")


@pytest.mark.parametrize(
    ("mutate", "match"),
    [
        (lambda r: r.update(extra="x"), "unknown key"),
        (lambda r: r.pop("id"), "missing key"),
        (lambda r: r.pop("fake"), "missing key"),
        (lambda r: r.update(id=5), "must be a string"),
        (lambda r: r.update(id=False), "must be a string"),
        (lambda r: r.update(id="Bad_Id"), "kebab-case"),
        (lambda r: r.update(id="-x"), "kebab-case"),
        (lambda r: r.update(id="1abc"), "kebab-case"),
        (lambda r: r.update(id="a--b"), "kebab-case"),
        (lambda r: r.update(id="a" * 65), "1 to 64"),
        (lambda r: r.update(id="private-key"), "reserved"),
        (lambda r: r.update(id="entropy-hex"), "reserved"),
        (lambda r: r.update(name=""), "1 to 512"),
        (lambda r: r.update(name=12), "must be a string"),
        (lambda r: r.update(description="x" * 513), "1 to 512"),
        (lambda r: r.update(regex=1), "must be a string"),
        (lambda r: r.update(regex="demo_(?P<secret>[A-Za-z0-9]+)"), "unbounded-quantifier"),
        (lambda r: r.update(regex="demo_[A-Za-z0-9]{24}"), "secret-group"),
        (lambda r: r.update(keywords=[]), "1 to 16"),
        (lambda r: r.update(keywords="demo_"), "list"),
        (lambda r: r.update(keywords=["Demo_"]), "lower-case"),
        (lambda r: r.update(keywords=["café"]), "lower-case"),
        (lambda r: r.update(keywords=["a", "a"]), "duplicate"),
        (lambda r: r.update(keywords=[5]), "must be a string"),
        (lambda r: r.update(keywords=["x"] * 17), "1 to 16"),
        (lambda r: r.update(severity="severe"), "one of"),
        (lambda r: r.update(severity=True), "must be a string"),
        (lambda r: r.update(confidence="certain"), "one of"),
        (lambda r: r.update(shown_chars="4"), "integer"),
        (lambda r: r.update(shown_chars=True), "integer"),
        (lambda r: r.update(shown_chars=-1), "between 0 and 12"),
        (lambda r: r.update(shown_chars=13), "between 0 and 12"),
        (lambda r: r.update(shown_chars=2), "fixed public prefix"),
        (lambda r: r.update(min_secret_bits=63), "between 64"),
        (lambda r: r.update(min_secret_bits="64"), "integer"),
        (lambda r: r.update(min_secret_bits=1000), "only guarantees"),
        (lambda r: r.update(min_entropy="3"), "must be a number"),
        (lambda r: r.update(min_entropy=True), "must be a number"),
        (lambda r: r.update(min_entropy=9), "between 0 and 8"),
        (lambda r: r.update(min_entropy=-1), "between 0 and 8"),
        (lambda r: r.update(checksum="luhn"), "one of"),
        (lambda r: r.update(context=[]), "1 to 4"),
        (lambda r: r.update(context=["A"]), "lower-case"),
        (lambda r: r.update(context=["a", "b", "c", "d", "e"]), "1 to 4"),
        (lambda r: r.update(fake=[]), "1 to 16"),
        (lambda r: r.update(fake="x"), "list"),
        (lambda r: r.update(fake=[{"charset": "nope", "length": 5}]), "unknown charset"),
        (lambda r: r.update(fake=[{"charset": "base62", "length": 0}]), "between 1"),
        (lambda r: r.update(fake=[{"charset": "base62", "length": True}]), "integer"),
        (lambda r: r.update(fake=[{"charset": "base62"}]), "missing key"),
        (lambda r: r.update(fake=[{"parts": []}]), "1 to 8"),
        (lambda r: r.update(fake=[{"parts": ["café"]}]), "printable ASCII"),
        (lambda r: r.update(fake=[{"parts": ["a"], "charset": "base62"}]), "unknown key"),
        (lambda r: r.update(fake=["x"]), "must be a mapping"),
        (lambda r: r.update(fake=[{"charset": "base62", "length": 256}] * 5), "match width"),
        (lambda r: r.update(fake=[{"parts": ["nothing"]}]), "does not match"),
    ],
)
def test_rule_schema_refusals(mutate: Any, match: str) -> None:
    _bad(mutate, match=match)


def test_rule_must_be_a_mapping_with_string_keys() -> None:
    with pytest.raises(ConfigError, match="must be a mapping"):
        parse_rule(["not", "a", "mapping"], "rules[0]")
    with pytest.raises(ConfigError, match="keys must be strings"):
        parse_rule({1: "x"}, "rules[0]")


def test_custom_rules_need_the_custom_prefix() -> None:
    data = _good_rule()
    data["id"] = "demo"
    with pytest.raises(ConfigError, match="must start with 'custom-'"):
        parse_rule(data, "rules[0]", id_prefix=CUSTOM_ID_PREFIX)
    assert parse_rule(data, "rules[0]").id == "demo"


def test_rule_lists_and_documents() -> None:
    other = _good_rule()
    other["id"] = "custom-other"
    assert rule_ids(parse_rules_document(_document(_good_rule(), other))) == (
        "custom-demo",
        "custom-other",
    )
    with pytest.raises(ConfigError, match="duplicate rule id"):
        parse_rule_list([_good_rule(), _good_rule()], "rules")
    with pytest.raises(ConfigError, match="must be a list"):
        parse_rule_list({}, "rules")
    with pytest.raises(ConfigError, match="1 to"):
        parse_rule_list([], "rules")
    with pytest.raises(ConfigError, match="version must be 1"):
        parse_rules_document({"version": 2, "rules": [_good_rule()]})
    with pytest.raises(ConfigError, match="version must be 1"):
        parse_rules_document({"version": True, "rules": [_good_rule()]})
    with pytest.raises(ConfigError, match="unknown key"):
        parse_rules_document({"version": 1, "rules": [_good_rule()], "extra": 1})
    with pytest.raises(ConfigError, match="missing key"):
        parse_rules_document({"version": 1})


def test_rule_count_is_bounded_by_the_limit() -> None:
    limits = replace(DEFAULT_LIMITS, max_rules=2)
    rules = []
    for index in range(3):
        rule = copy.deepcopy(_good_rule())
        rule["id"] = f"custom-r{index}"
        rules.append(rule)
    assert len(parse_rule_list(rules[:2], "rules", limits)) == 2
    with pytest.raises(ConfigError, match="1 to 2"):
        parse_rule_list(rules, "rules", limits)


def test_keyword_count_is_bounded_by_the_limit() -> None:
    limits = replace(DEFAULT_LIMITS, max_keywords_per_rule=1)
    data = _good_rule()
    data["keywords"] = ["demo_", "other"]
    with pytest.raises(ConfigError, match="1 to 1"):
        parse_rule(data, "rules[0]", limits)


def test_kebab_case_helper() -> None:
    assert is_kebab_case("a")
    assert is_kebab_case("aws-access-key-id")
    assert is_kebab_case("a1-b2")
    assert not is_kebab_case("")
    assert not is_kebab_case("A")
    assert not is_kebab_case("a_b")
    assert not is_kebab_case("a-")
    assert not is_kebab_case("é")
    assert not is_kebab_case("9a")


# -- rules from YAML text: schema errors through the loader -----------------------------------

GOOD_YAML = """\
version: 1
rules:
  - id: custom-demo
    name: Demo
    description: A demo rule.
    regex: 'demo_(?P<secret>[A-Za-z0-9]{24})'
    keywords: [demo_]
    severity: high
    confidence: high
    shown_chars: 0
    min_secret_bits: 100
    fake:
      - parts: [demo, _]
      - {charset: base62, length: 24}
"""


def test_rules_load_from_yaml_bytes_with_a_hash() -> None:
    ruleset = load_rules_from_bytes(GOOD_YAML.encode(), id_prefix="custom-")
    assert rule_ids(ruleset.rules) == ("custom-demo",)
    assert ruleset.sha256 == hashlib.sha256(GOOD_YAML.encode()).hexdigest()


@pytest.mark.parametrize(
    ("old", "new", "match"),
    [
        ("id: custom-demo", "id: no", "must be a string"),
        ("id: custom-demo", "id: 0755", "must be a string"),
        ("description: A demo rule.", "description: 12:30", "must be a string"),
        ("name: Demo", "name: yes", "must be a string"),
        ("severity: high", "severity: 1", "must be a string"),
        ("shown_chars: 0", "shown_chars: '0'", "integer"),
        ("min_secret_bits: 100", "min_secret_bits: 100.0", "integer"),
        ("keywords: [demo_]", "keywords: [no]", "must be a string"),
        ("version: 1", "version: '1'", "version must be 1"),
        ("severity: high\n", "severity: high\n    severity: low\n", "duplicate key"),
        ("regex: 'demo_(?P<secret>[A-Za-z0-9]{24})'", "regex: &r 'x'", "anchors"),
        ("min_secret_bits: 100", "min_secret_bits: !!float 100", "explicit tags"),
    ],
)
def test_yaml_surprises_and_duplicates_are_refused(old: str, new: str, match: str) -> None:
    text = GOOD_YAML.replace(old, new)
    assert text != GOOD_YAML
    with pytest.raises(ConfigError, match=match):
        load_rules_from_bytes(text.encode())


def test_rules_file_size_is_capped() -> None:
    limits = replace(DEFAULT_LIMITS, max_rules_file_bytes=100)
    with pytest.raises(ConfigError, match="larger than the limit"):
        load_rules_from_bytes(GOOD_YAML.encode(), limits=limits)


def test_a_rules_file_that_is_not_a_mapping_is_refused() -> None:
    with pytest.raises(ConfigError, match="must be a mapping"):
        load_rules_from_bytes(b"- a\n- b\n")
    with pytest.raises(ConfigError, match="must be a mapping"):
        load_rules_from_bytes(b"")


def test_a_key_that_cannot_be_hashed_is_refused_not_a_crash() -> None:
    with pytest.raises(ConfigError, match="invalid YAML"):
        _parse("? [a, b]\n: value\n")


def test_shown_chars_beyond_a_quarter_of_the_minimum_length_is_refused() -> None:
    rule = _good_rule()
    rule["regex"] = "(?P<secret>demo_[A-Za-z0-9]{12})"
    rule["min_secret_bits"] = 64
    rule["shown_chars"] = 5  # the prefix is public, but 5 is more than a quarter of 17
    rule["fake"] = [{"parts": ["demo", "_"]}, {"charset": "base62", "length": 12}]
    with pytest.raises(ConfigError, match="quarter of the minimum secret length"):
        parse_rule(rule, "rules[0]")
    rule["shown_chars"] = 4
    assert parse_rule(rule, "rules[0]").shown_chars == 4


def test_the_built_in_rules_are_parsed_once_per_limits_value() -> None:
    from secret_scanner.core.limits import DEFAULT_LIMITS
    from secret_scanner.services.loader import load_builtin_rules

    assert load_builtin_rules() is load_builtin_rules()
    assert load_builtin_rules() is load_builtin_rules(DEFAULT_LIMITS)
    lowered = DEFAULT_LIMITS.with_overrides({"max_rules": 100})
    other = load_builtin_rules(lowered)
    assert other is not load_builtin_rules()
    assert other.sha256 == load_builtin_rules().sha256
