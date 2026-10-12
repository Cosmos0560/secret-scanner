"""Every built-in rule, table-driven (PLAN.md D4, D16).

One entry per rule id; a completeness test fails when a rule is added without an entry. Every
value is a runtime-generated fake placed in a temporary string: nothing below writes one to disk
and every comparison goes through `assert_not_leaked`.
"""

from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass, field

import pytest

from secret_scanner.core.checksums import github_token_checksum_valid
from secret_scanner.core.detect.engine import Engine
from secret_scanner.core.detect.entropy import EntropyConfig
from secret_scanner.core.fakes import build_fake
from secret_scanner.core.limits import DEFAULT_LIMITS
from secret_scanner.core.models import Confidence, FakeSegment, Rule
from secret_scanner.core.redact import redact_secret
from secret_scanner.core.regex_guard import compile_pattern
from secret_scanner.services.loader import load_builtin_rules

RULES: dict[str, Rule] = {rule.id: rule for rule in load_builtin_rules().rules}
SEEDS = ("alpha", "bravo", "charlie", "delta")
ENGINE = Engine(list(RULES.values()), entropy=EntropyConfig(enabled=False))
UNFILTERED = Engine(list(RULES.values()), entropy=EntropyConfig(enabled=False), use_prefilter=False)


def _swap_prefix(fake: str, old: str, new: str) -> str:
    assert fake.startswith(old)
    return new + fake[len(old) :]


@dataclass(frozen=True)
class RuleCase:
    key: str  # the key name placed before the value in the contexts
    secret_offset: int  # where the secret starts inside the fake (the fake may hold a prefix)
    negatives: Callable[[str], list[str]]
    expected_confidence: Confidence
    bare_needs_key: bool = False  # a context rule: the bare form still names the key
    keywords_in_value: bool = True
    extra: dict[str, str] = field(default_factory=dict)


def _glued(fake: str) -> str:
    return "x" + fake


RULE_CASES: dict[str, RuleCase] = {
    "aws-access-key-id": RuleCase(
        key="aws_key",
        secret_offset=0,
        expected_confidence=Confidence.HIGH,
        negatives=lambda f: [
            f[:-1],  # one character short
            f + "A",  # one character long, word-bounded
            _glued(f),
            f.lower(),  # prefix in the wrong case
            f[:4] + "1" + f[5:],  # a character outside the base32 alphabet
            f[:4] + "X" * 16,  # placeholder body
            f[:4] + "A" * 16,  # repeated character
            "<your-aws-access-key-id>",
            f[:3] + f[4:] + "Z",  # prefix broken
        ],
    ),
    "aws-secret-access-key": RuleCase(
        key="aws_secret_access_key",
        secret_offset=0,
        expected_confidence=Confidence.MEDIUM,
        bare_needs_key=True,
        keywords_in_value=False,
        negatives=lambda f: [
            f[:-1],
            f + "A",
            _glued(f),
            f[:20] + "!" + f[21:],  # a character outside the alphabet breaks the run
            "X" * 40,
            "<your-secret-access-key-goes-here>",
        ],
    ),
    "github-token": RuleCase(
        key="github_token",
        secret_offset=0,
        expected_confidence=Confidence.HIGH,
        negatives=lambda f: [
            f[:-1],
            f + "a",
            f + "_",
            _glued(f),
            "GHP_" + f[4:],  # prefix in the wrong case
            "ghx_" + f[4:],  # unknown token kind
            f[:4] + "!" + f[5:],
            f[:4] + "X" * 36,
            "<your-github-token>",
        ],
    ),
    "github-fine-grained-pat": RuleCase(
        key="github_pat",
        secret_offset=0,
        expected_confidence=Confidence.HIGH,
        negatives=lambda f: [
            f[:-1],
            f + "a",
            _glued(f),
            "GITHUB_PAT_" + f[11:],
            f[:11] + "X" * 22 + "_" + "X" * 59,
            f[:11] + f[11:33] + "-" + f[34:],  # the separator underscore replaced
        ],
    ),
    "gitlab-pat": RuleCase(
        key="gitlab_token",
        secret_offset=0,
        expected_confidence=Confidence.HIGH,
        negatives=lambda f: [
            f[:-1],  # 19 characters after the prefix: below the minimum
            "GLPAT-" + f[6:],
            _glued(f),
            f + "a" * 50,  # beyond the 64-character maximum, still word-bounded
            "glpat-" + "X" * 20,
            "glpat-" + "a" * 20,
            f[:6] + "!" + f[7:],
        ],
    ),
    "slack-token": RuleCase(
        key="slack_token",
        secret_offset=0,
        expected_confidence=Confidence.HIGH,
        negatives=lambda f: [
            f[:-30],  # the last segment too short
            _glued(f),
            "XOXB-" + f[5:],
            "xoxz-" + f[5:],
            f[:5] + "123-" + f[5:].split("-", 1)[1],  # the first segment too short
            f[:5] + "X" * 11 + "-" + f[5:].split("-", 1)[1],  # a non-digit segment
        ],
    ),
    "slack-webhook-url": RuleCase(
        key="slack_webhook",
        secret_offset=len("hooks.slack.com/services/"),
        expected_confidence=Confidence.HIGH,
        negatives=lambda f: [
            f[:-1],
            f + "a",
            f.replace("hooks.slack.com", "hooks.slack.org"),
            f.replace("/services/T", "/services/X"),
            f[:-24] + "X" * 24,
            "hooks.slack.com/services/",
        ],
    ),
    "stripe-secret-key": RuleCase(
        key="stripe_key",
        secret_offset=0,
        expected_confidence=Confidence.HIGH,
        negatives=lambda f: [
            f[:8] + "a" * 23,  # one below the minimum of 24
            f + "a" * 80,  # above the maximum of 99
            _glued(f),
            "SK_LIVE_" + f[8:],
            "sk_test_" + f[8:],
            f[:8] + "X" * 30,
            f[:8] + "!" + f[9:],
            "<your-stripe-key>",
        ],
    ),
    "google-api-key": RuleCase(
        key="google_key",
        secret_offset=0,
        expected_confidence=Confidence.HIGH,
        negatives=lambda f: [
            f[:-1],
            f + "a",
            _glued(f),
            "aiza" + f[4:],
            "AIZA" + f[4:],
            f[:4] + "!" + f[5:],
            f[:4] + "X" * 35,
        ],
    ),
    "npm-token": RuleCase(
        key="npm_token",
        secret_offset=0,
        expected_confidence=Confidence.HIGH,
        negatives=lambda f: [
            f[:-1],
            f + "a",
            f + "_",
            _glued(f),
            "NPM_" + f[4:],
            f[:4] + "!" + f[5:],
            f[:4] + "X" * 36,
        ],
    ),
    "pypi-token": RuleCase(
        key="pypi_token",
        secret_offset=0,
        expected_confidence=Confidence.HIGH,
        negatives=lambda f: [
            f[:-11],  # 49 characters after the header: below the minimum of 50
            f + "a" * 300,  # beyond the maximum
            _glued(f),
            "PYPI-" + f[5:],
            "pypi-" + "Z" + f[6:],  # a wrong macaroon header
            f[:20] + "X" * 60,
            f[:20] + "a" * 60,
        ],
    ),
    "sendgrid-api-key": RuleCase(
        key="sendgrid_key",
        secret_offset=0,
        expected_confidence=Confidence.HIGH,
        negatives=lambda f: [
            f[:-1],
            f + "a",
            _glued(f),
            "sg." + f[3:],
            f[:3] + "X" * 22 + "." + "X" * 43,
            f[:3] + f[3:25] + "," + f[26:],  # the separator is not a dot
        ],
    ),
    "azure-storage-account-key": RuleCase(
        key="storage_connection",
        secret_offset=len("AccountKey="),
        expected_confidence=Confidence.HIGH,
        negatives=lambda f: [
            f[:-3] + "=",  # 85 characters then padding
            f + "A",  # the secret is followed by more base64
            f.replace("AccountKey=", "accountkey="),
            f.replace("AccountKey=", "AccountKey:"),
            f[:-2],  # no padding
            "AccountKey=" + "X" * 86 + "==",
        ],
    ),
}


def _contexts(case: RuleCase, value: str) -> dict[str, str]:
    key = case.key
    return {
        "bare": f"{key} {value}" if case.bare_needs_key else value,
        "single-quoted": f"{key} = '{value}'",
        "double-quoted": f'{key} = "{value}"',
        "env": f"{key}={value}",
        "json": f'{{"{key}": "{value}"}}',
        "yaml": f"{key}: {value}",
        "url-query": f"https://example.invalid/path?{key}={value}&x=1",
        "crlf": f"{key}={value}\r\n",
    }


def _scan(text: str, engine: Engine = ENGINE) -> list:  # type: ignore[type-arg]
    return list(engine.scan(text.encode("utf-8")).matches)


def _only(rule_id: str, text: str, engine: Engine = ENGINE) -> list:  # type: ignore[type-arg]
    return [m for m in _scan(text, engine) if m.rule_id == rule_id]


# -- completeness -----------------------------------------------------------------------------


def test_every_builtin_rule_has_a_table_entry_and_the_table_has_no_extra() -> None:
    assert set(RULE_CASES) == set(RULES)
    for rule_id, case in RULE_CASES.items():
        fake = build_fake(RULES[rule_id], "completeness")
        assert len(case.negatives(fake)) >= 5, rule_id
        assert case.key
        assert case.key.lower() == case.key


# -- positives --------------------------------------------------------------------------------


@pytest.mark.parametrize("rule_id", sorted(RULE_CASES))
@pytest.mark.parametrize("seed", SEEDS)
def test_positive_in_every_context_gives_exactly_one_finding(
    rule_id: str, seed: str, assert_not_leaked: Callable[..., None]
) -> None:
    rule, case = RULES[rule_id], RULE_CASES[rule_id]
    fake = build_fake(rule, seed)
    secret = fake[case.secret_offset :].encode("ascii")
    contexts = _contexts(case, fake)
    assert set(contexts) == {
        "bare",
        "single-quoted",
        "double-quoted",
        "env",
        "json",
        "yaml",
        "url-query",
        "crlf",
    }
    for name, line in contexts.items():
        matches = _scan(line)
        assert [m.rule_id for m in matches] == [rule_id], name
        match = matches[0]
        column = line.index(fake) + case.secret_offset + 1
        assert (match.line, match.col_start, match.col_end) == (1, column, column + len(secret)), (
            name
        )
        assert match.confidence is case.expected_confidence, name
        assert match.severity is rule.severity
        redacted = redact_secret(match.secret, match.shown_chars)
        assert redacted.text == redact_secret(secret, rule.shown_chars).text, name
        assert_not_leaked(redacted.text, secret, allowed_shown=rule.shown_chars)


@pytest.mark.parametrize("rule_id", sorted(RULE_CASES))
def test_the_secret_is_found_on_a_later_line_of_a_larger_file(rule_id: str) -> None:
    rule, case = RULES[rule_id], RULE_CASES[rule_id]
    fake = build_fake(rule, "multiline")
    filler = "def f():\n    return 1\n\n# comment\n"
    text = filler + _contexts(case, fake)["env"] + "\n" + filler
    (match,) = _only(rule_id, text)
    assert match.line == 5


@pytest.mark.parametrize("rule_id", sorted(RULE_CASES))
def test_two_secrets_on_one_line_are_two_findings(rule_id: str) -> None:
    rule, case = RULES[rule_id], RULE_CASES[rule_id]
    one, two = build_fake(rule, "one"), build_fake(rule, "two")
    line = f"{case.key} {one} , {two} ;"
    assert len(_only(rule_id, line)) == 2


# -- negatives --------------------------------------------------------------------------------


@pytest.mark.parametrize("rule_id", sorted(RULE_CASES))
@pytest.mark.parametrize("seed", SEEDS[:2])
def test_near_misses_and_placeholders_do_not_match(rule_id: str, seed: str) -> None:
    rule, case = RULES[rule_id], RULE_CASES[rule_id]
    fake = build_fake(rule, seed)
    for index, negative in enumerate(case.negatives(fake)):
        assert negative != fake
        for name, line in _contexts(case, negative).items():
            assert _only(rule_id, line) == [], (index, name)


def test_context_rule_needs_its_context_keywords_on_the_line() -> None:
    rule = RULES["aws-secret-access-key"]
    fake = build_fake(rule, "context")
    assert _only(rule.id, fake) == []
    assert _only(rule.id, f"aws {fake}") == []  # `secret` missing
    assert _only(rule.id, f"secret {fake}") == []  # `aws` missing
    assert len(_only(rule.id, f"aws secret {fake}")) == 1
    assert len(_only(rule.id, f"AWS_SECRET_ACCESS_KEY={fake}")) == 1
    assert len(_only(rule.id, f"awsSecretKey: {fake}")) == 1
    assert _only(rule.id, f"aws\nsecret\n{fake}\n") == []  # the words are on other lines


def test_placeholders_built_from_the_fake_spec_are_rejected_by_min_entropy() -> None:
    for rule_id, rule in RULES.items():
        pieces: list[str] = []
        for segment in rule.fake:
            assert isinstance(segment, FakeSegment)
            if segment.parts:
                pieces.append("".join(segment.parts))
            else:
                pieces.append(("7" if segment.charset == "digits" else "X") * segment.length)
        placeholder = "".join(pieces)
        case = RULE_CASES[rule_id]
        assert rule.min_entropy is not None
        for line in _contexts(case, placeholder).values():
            assert _only(rule_id, line) == [], rule_id


def test_prefix_glued_to_a_word_character_never_matches_any_rule() -> None:
    for rule_id, rule in RULES.items():
        fake = build_fake(rule, "glue")
        assert _only(rule_id, "q" + fake) == [], rule_id


# -- pre-filter consistency -------------------------------------------------------------------


@pytest.mark.parametrize("rule_id", sorted(RULE_CASES))
def test_every_positive_contains_a_declared_keyword_and_the_prefilter_changes_nothing(
    rule_id: str,
) -> None:
    rule, case = RULES[rule_id], RULE_CASES[rule_id]
    fake = build_fake(rule, "prefilter")
    for line in _contexts(case, fake).values():
        assert any(keyword in line.lower() for keyword in rule.keywords), line[:0]
        filtered = [(m.rule_id, m.line, m.col_start, m.col_end) for m in _scan(line)]
        unfiltered = [(m.rule_id, m.line, m.col_start, m.col_end) for m in _scan(line, UNFILTERED)]
        assert filtered == unfiltered
    negatives = case.negatives(fake)
    for negative in negatives:
        assert _scan(negative) == _scan(negative, UNFILTERED)


# -- checksum rules ---------------------------------------------------------------------------


def test_github_token_confidence_follows_the_checksum() -> None:
    rule = RULES["github-token"]
    good = build_fake(rule, "sum")
    bad = build_fake(rule, "sum", valid_checksum=False)
    assert github_token_checksum_valid(good.encode())
    assert not github_token_checksum_valid(bad.encode())
    (valid,) = _only(rule.id, f"token={good}")
    (invalid,) = _only(rule.id, f"token={bad}")
    assert valid.confidence is Confidence.HIGH
    assert invalid.confidence is Confidence.LOW
    assert valid.severity is invalid.severity


@pytest.mark.parametrize("kind", ["p", "o", "u", "s", "r"])
def test_every_github_token_kind_is_recognised(kind: str) -> None:
    rule = RULES["github-token"]
    fake = build_fake(rule, "kinds")
    swapped = f"gh{kind}_" + fake[4:]
    (match,) = _only(rule.id, swapped)
    assert match.secret.startswith(f"gh{kind}_".encode())


@pytest.mark.parametrize("prefix", ["AK" + "IA", "AS" + "IA", "AB" + "IA", "AC" + "CA"])
def test_every_aws_access_key_prefix_is_recognised(prefix: str) -> None:
    rule = RULES["aws-access-key-id"]
    fake = prefix + build_fake(rule, "prefixes")[4:]
    assert len(_only(rule.id, f"id={fake}")) == 1


@pytest.mark.parametrize("kind", ["b", "p", "a", "r", "s"])
def test_every_slack_token_kind_and_both_shapes_are_recognised(kind: str) -> None:
    rule = RULES["slack-token"]
    fake = build_fake(rule, "slack")  # three segments after the prefix
    swapped = "xox" + kind + fake[4:]
    assert len(_only(rule.id, swapped)) == 1
    four = swapped.replace("-", "-1234567890-", 1)
    assert len(_only(rule.id, four)) == 1


def test_stripe_restricted_keys_are_recognised() -> None:
    rule = RULES["stripe-secret-key"]
    fake = build_fake(rule, "stripe")
    assert len(_only(rule.id, "r" + fake[1:])) == 1


# -- the guard --------------------------------------------------------------------------------


@pytest.mark.parametrize("rule_id", sorted(RULES))
def test_every_rule_regex_passes_the_guard_within_the_budget(rule_id: str) -> None:
    rule = RULES[rule_id]
    again = compile_pattern(rule.pattern.source, with_secret_group=True)
    assert again.cost == rule.pattern.cost
    assert again.cost <= DEFAULT_LIMITS.max_pattern_cost
    assert again.width_max <= DEFAULT_LIMITS.max_match_chars
    assert 64 <= rule.min_secret_bits <= again.secret_bits
