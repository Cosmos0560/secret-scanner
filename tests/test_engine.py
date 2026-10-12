"""The detection engine: overlap resolution, limits, encodings, columns, and the mixed and
negative corpora of the Phase 2 definition of done."""

from __future__ import annotations

import dataclasses
from collections.abc import Callable
from dataclasses import replace

import pytest

from secret_scanner.core.detect.engine import Engine, resolve_line
from secret_scanner.core.detect.entropy import EntropyConfig
from secret_scanner.core.detect.match import Match
from secret_scanner.core.fakes import build_fake, fake_entropy_token, fake_private_key
from secret_scanner.core.findings import to_finding
from secret_scanner.core.limits import DEFAULT_LIMITS
from secret_scanner.core.lines import TextKind
from secret_scanner.core.models import Confidence, Detector, Finding, Report, Severity
from secret_scanner.services.loader import load_builtin_rules

RULES = {rule.id: rule for rule in load_builtin_rules().rules}
ALL_RULES = list(RULES.values())
ENGINE = Engine(ALL_RULES)
RULES_ONLY = Engine(ALL_RULES, entropy=EntropyConfig(enabled=False))


def _fake(rule_id: str, seed: str = "engine") -> str:
    return build_fake(RULES[rule_id], seed)


def _ids(engine: Engine, text: str | bytes) -> list[tuple[str, int]]:
    data = text if isinstance(text, bytes) else text.encode("utf-8")
    return [(m.rule_id, m.line) for m in engine.scan(data).matches]


# -- kinds, encodings -------------------------------------------------------------------------


def test_binary_and_undecodable_buffers_are_reported_not_scanned() -> None:
    fake = _fake("github-token")
    binary = ENGINE.scan(b"\x00\x01" + fake.encode())
    assert (binary.kind, binary.matches, binary.lines) == (TextKind.BINARY, (), 0)
    undecodable = ENGINE.scan(b"\xff\xfe\x41")
    assert undecodable.kind is TextKind.UNDECODABLE
    assert undecodable.matches == ()


def test_a_secret_is_found_in_every_supported_encoding() -> None:
    fake = _fake("aws-access-key-id")
    line = f"id = {fake}\n"
    encoded = {
        "utf-8": line.encode("utf-8"),
        "utf-8-bom": b"\xef\xbb\xbf" + line.encode("utf-8"),
        "latin-1": ("café " + line).encode("latin-1"),
        "cp1252": ("€ " + line).encode("cp1252"),
        "utf-16-le": b"\xff\xfe" + line.encode("utf-16-le"),
        "utf-16-be": b"\xfe\xff" + line.encode("utf-16-be"),
        "utf-32-le": b"\xff\xfe\x00\x00" + line.encode("utf-32-le"),
        "utf-32-be": b"\x00\x00\xfe\xff" + line.encode("utf-32-be"),
    }
    for name, data in encoded.items():
        result = RULES_ONLY.scan(data)
        assert [m.rule_id for m in result.matches] == ["aws-access-key-id"], name
        assert result.matches[0].secret == fake.encode(), name


def test_invalid_utf8_around_a_secret_does_not_hide_it() -> None:
    fake = _fake("github-token")
    data = b"\x80\x81\xfd broken " + fake.encode() + b" \xff\xfe\n"
    assert _ids(RULES_ONLY, data) == [("github-token", 1)]


def test_utf16_without_a_bom_is_skipped_as_binary() -> None:
    fake = _fake("github-token")
    data = f"token = {fake}".encode("utf-16-le")
    assert ENGINE.scan(data).kind is TextKind.BINARY


# -- lines and columns ------------------------------------------------------------------------


def test_line_numbers_and_crlf() -> None:
    fake = _fake("npm-token")
    text = f"a\r\nb\r\nkey={fake}\r\nz\r\n"
    (match,) = RULES_ONLY.scan(text.encode()).matches
    assert (match.line, match.col_start) == (3, 5)
    assert match.secret == fake.encode()  # the \r is not part of it


def test_columns_count_code_points_not_bytes() -> None:
    fake = _fake("npm-token")
    prefix = "café 日本 \U0001f600 key="
    (match,) = RULES_ONLY.scan(f"{prefix}{fake}\n".encode()).matches
    assert match.col_start == len(prefix) + 1
    assert match.col_end == len(prefix) + len(fake) + 1


def test_columns_count_invalid_bytes_as_one_each() -> None:
    fake = _fake("npm-token")
    (match,) = RULES_ONLY.scan(b"\x80\x81\xfd " + fake.encode()).matches
    assert match.col_start == 5


def test_an_over_long_line_is_cut_listed_and_the_rest_of_the_file_is_scanned() -> None:
    limits = replace(DEFAULT_LIMITS, max_line_bytes=200)
    engine = Engine(ALL_RULES, entropy=EntropyConfig(enabled=False), limits=limits)
    fake = _fake("npm-token")
    inside = f"k={fake} " + "x" * 50
    beyond = "y" * 300 + f" k={fake}"
    text = f"{inside}\n{beyond}\nk={fake}\n"
    result = engine.scan(text.encode())
    assert result.long_lines == (2,)
    assert [(m.rule_id, m.line) for m in result.matches] == [("npm-token", 1), ("npm-token", 3)]
    assert result.lines == 3


def test_a_line_exactly_at_the_limit_is_not_listed() -> None:
    limits = replace(DEFAULT_LIMITS, max_line_bytes=100)
    engine = Engine(ALL_RULES, entropy=EntropyConfig(enabled=False), limits=limits)
    assert engine.scan(b"a" * 100 + b"\n").long_lines == ()
    assert engine.scan(b"a" * 101 + b"\n").long_lines == (1,)


# -- bounds -----------------------------------------------------------------------------------


def test_the_per_file_cap_drops_the_rest_and_says_so() -> None:
    limits = replace(DEFAULT_LIMITS, max_findings_per_file=3)
    engine = Engine(ALL_RULES, entropy=EntropyConfig(enabled=False), limits=limits)
    text = "".join(f"t={_fake('npm-token', str(n))}\n" for n in range(10))
    result = engine.scan(text.encode())
    assert len(result.matches) == 3
    assert result.capped
    assert [m.line for m in result.matches] == [1, 2, 3]


def test_exactly_the_cap_is_not_capped() -> None:
    limits = replace(DEFAULT_LIMITS, max_findings_per_file=3)
    engine = Engine(ALL_RULES, entropy=EntropyConfig(enabled=False), limits=limits)
    text = "".join(f"t={_fake('npm-token', str(n))}\n" for n in range(3))
    result = engine.scan(text.encode())
    assert len(result.matches) == 3
    assert not result.capped


def test_the_cap_counts_private_keys_too() -> None:
    limits = replace(DEFAULT_LIMITS, max_findings_per_file=1)
    engine = Engine(ALL_RULES, entropy=EntropyConfig(enabled=False), limits=limits)
    text = fake_private_key("a") + fake_private_key("b", label="EC")
    result = engine.scan(text.encode())
    assert len(result.matches) == 1
    assert result.capped


def test_an_empty_buffer_is_clean() -> None:
    result = ENGINE.scan(b"")
    assert (result.kind, result.matches, result.lines, result.capped) == (
        TextKind.TEXT,
        (),
        0,
        False,
    )


# -- overlap resolution -----------------------------------------------------------------------


def test_a_rule_wins_over_the_entropy_detector_on_the_same_span() -> None:
    fake = _fake("github-token", "overlap")
    assert _ids(ENGINE, f"token = {fake}\n") == [("github-token", 1)]
    only_entropy = Engine([], entropy=EntropyConfig())
    assert _ids(only_entropy, f"token = {fake}\n") == [("entropy-base64", 1)]


def test_a_rule_hit_next_to_an_entropy_token_leaves_both() -> None:
    fake = _fake("github-token", "next")
    other = fake_entropy_token("next")
    assert _ids(ENGINE, f"{fake} {other}\n") == [("github-token", 1), ("entropy-base64", 1)]


def _hit(rule_id: str, start: int, end: int, **fields: object) -> tuple[int, int, Match]:
    values: dict[str, object] = {
        "rule_id": rule_id,
        "detector": Detector.RULE,
        "severity": Severity.HIGH,
        "confidence": Confidence.HIGH,
        "line": 1,
        "col_start": start + 1,
        "col_end": end + 1,
        "secret": b"x" * (end - start),
        "shown_chars": 0,
    }
    values.update(fields)
    return (start, end, Match(**values))  # type: ignore[arg-type]


def test_overlapping_rule_hits_keep_the_higher_confidence() -> None:
    low = _hit("a", 0, 20, confidence=Confidence.LOW, severity=Severity.CRITICAL)
    high = _hit("b", 5, 15, confidence=Confidence.HIGH, severity=Severity.LOW)
    assert [m.rule_id for m in resolve_line([low, high], [], [])] == ["b"]


def test_then_the_higher_severity_then_the_longer_span_then_the_id() -> None:
    mid = _hit("a", 0, 20, severity=Severity.MEDIUM)
    top = _hit("b", 5, 15, severity=Severity.CRITICAL)
    assert [m.rule_id for m in resolve_line([mid, top], [], [])] == ["b"]
    short = _hit("a", 0, 10)
    long = _hit("b", 5, 25)
    assert [m.rule_id for m in resolve_line([short, long], [], [])] == ["b"]
    first = _hit("a", 0, 10)
    second = _hit("b", 0, 10)
    assert [m.rule_id for m in resolve_line([second, first], [], [])] == ["a"]


def test_non_overlapping_hits_are_ordered_by_position() -> None:
    later = _hit("a", 30, 40)
    earlier = _hit("b", 0, 10)
    assert [m.rule_id for m in resolve_line([later, earlier], [], [])] == ["b", "a"]


def test_adjacent_spans_do_not_overlap() -> None:
    left = _hit("a", 0, 10)
    right = _hit("b", 10, 20)
    assert len(resolve_line([left, right], [], [])) == 2


def test_protected_spans_remove_hits_they_touch() -> None:
    inside = _hit("a", 5, 15)
    outside = _hit("b", 40, 50)
    entropy = _hit("entropy-base64", 8, 12, detector=Detector.ENTROPY)
    result = resolve_line([inside, outside], [entropy], [(0, 20)])
    assert [m.rule_id for m in result] == ["b"]


def test_entropy_hits_overlapping_a_rule_hit_are_dropped_and_others_kept() -> None:
    rule = _hit("a", 0, 20)
    clash = _hit("entropy-base64", 10, 30, detector=Detector.ENTROPY)
    free = _hit("entropy-hex", 40, 80, detector=Detector.ENTROPY)
    result = resolve_line([rule], [clash, free], [])
    assert [m.rule_id for m in result] == ["a", "entropy-hex"]


# -- the mixed corpus and the negative corpus -------------------------------------------------


def _mixed_corpus() -> tuple[str, list[tuple[str, int]]]:
    lines: list[str] = ["# deployment notes", "import os", ""]
    expected: list[tuple[str, int]] = []

    def add(text: str, rule_id: str | None = None) -> None:
        lines.append(text)
        if rule_id is not None:
            expected.append((rule_id, len(lines)))

    contexts = {
        "aws-access-key-id": "AWS_KEY={v}",
        "aws-secret-access-key": 'aws_secret_access_key = "{v}"',
        "github-token": "export GITHUB_TOKEN={v}",
        "github-fine-grained-pat": "gh_pat: {v}",
        "gitlab-pat": "GITLAB_TOKEN='{v}'",
        "slack-token": '{{"slack": "{v}"}}',
        "slack-webhook-url": "curl -X POST https://{v}",
        "stripe-secret-key": "stripe.api_key = '{v}'",
        "google-api-key": "GOOGLE_API_KEY={v}",
        "npm-token": "//registry.example.invalid/:_authToken={v}",
        "pypi-token": "password: {v}",
        "sendgrid-api-key": "SENDGRID={v}",
        "azure-storage-account-key": "DefaultEndpointsProtocol=https;AccountName=a;{v}",
    }
    for index, (rule_id, template) in enumerate(contexts.items()):
        add(f"def helper_{index}(): return {index}")
        add(template.format(v=_fake(rule_id, f"mixed-{index}")), rule_id)
    add("plain = 'nothing to see'")
    for line in fake_private_key("mixed", label="OPENSSH").splitlines():
        lines.append(line)
    expected.append(("private-key", len(lines) - 4))  # the header line of the 5-line block
    add(f'api_key = "{fake_entropy_token("mixed-entropy")}"', "entropy-base64")
    add("last line")
    return "\n".join(lines) + "\n", expected


def test_the_engine_finds_every_generated_fake_in_a_mixed_corpus() -> None:
    text, expected = _mixed_corpus()
    result = ENGINE.scan(text.encode())
    found = [(m.rule_id, m.line) for m in result.matches]
    assert sorted(found) == sorted(expected)
    assert {rule_id for rule_id, _ in found} >= set(RULES) | {"private-key", "entropy-base64"}
    assert not result.capped
    assert result.long_lines == ()


def test_findings_built_from_the_mixed_corpus_hold_no_secret(
    assert_not_leaked: Callable[..., None],
) -> None:
    text, _ = _mixed_corpus()
    result = ENGINE.scan(text.encode())
    for match in result.matches:
        finding = to_finding(match, path_key="notes.txt", path="notes.txt")
        assert isinstance(finding, Finding)
        rendered = repr(finding)
        assert_not_leaked(rendered, match.secret, allowed_shown=match.shown_chars)


def _negative_corpus() -> str:
    """Near misses of every rule, placeholders, prose that mentions formats, ordinary code."""
    lines = ["# README", "Tokens look like prefix_ followed by random characters.", ""]
    for rule_id, rule in RULES.items():
        fake = build_fake(rule, "negative")
        found = rule.pattern.search(fake.encode())
        assert found is not None
        below_minimum = fake[: found.secret_start + rule.pattern.secret_min_width - 1]
        lines.append(f"short: {below_minimum}")
        lines.append(f"glued: q{fake}")
        lines.append(f"placeholder: <your-{rule_id}-here>")
    header = "-----BEGIN " + "RSA PRIVATE" + " KEY-----"
    lines += [
        "The first line of the file is " + header + " followed by base64.",
        header,
        "-----END " + "RSA PRIVATE" + " KEY-----",
        "id = 123e4567-e89b-12d3-a456-426614174000",
        "hash = " + "0123456789abcdef" * 4,
        'integrity="sha512-' + fake_entropy_token("sri", length=64) + '"',
        "path = usr/local/lib/python3/site-packages/aBcDeFgHiJkLmNoPqRsT",
        "version = 1.2.3-beta.4+build.5",
        "url = https://example.invalid/some/long/path/segment/without/a/secret",
        "def compute(a, b):",
        "    return a + b",
    ]
    return "\n".join(lines) + "\n"


def test_no_rule_and_no_private_key_fires_in_the_negative_corpus() -> None:
    result = RULES_ONLY.scan(_negative_corpus().encode())
    assert [(m.rule_id, m.line) for m in result.matches] == []


def test_the_negative_corpus_yields_at_most_low_confidence_entropy_hits() -> None:
    # A near miss of a token is still a random-looking string: the entropy detector may flag it,
    # but only at confidence low, which the default report level (medium) does not show.
    result = ENGINE.scan(_negative_corpus().encode())
    assert result.matches
    assert {m.rule_id for m in result.matches} == {"entropy-base64"}
    assert {m.confidence for m in result.matches} == {Confidence.LOW}


def test_ordinary_text_has_no_entropy_hits_at_all() -> None:
    quiet = [
        "id = 123e4567-e89b-12d3-a456-426614174000",
        "hash = " + "0123456789abcdef" * 4,
        'integrity="sha512-' + fake_entropy_token("sri", length=64) + '"',
        "path = usr/local/lib/python3/site-packages/aBcDeFgHiJkLmNoPqRsT",
        "version = 1.2.3-beta.4+build.5",
        "url = https://example.invalid/some/long/path/segment/without/a/secret",
        "def compute(a, b):",
        "    return a + b",
        "The quick brown fox jumps over the lazy dog, repeatedly and at length.",
    ]
    assert ENGINE.scan((chr(10).join(quiet) + chr(10)).encode()).matches == ()


# -- result shape -----------------------------------------------------------------------------


def test_matches_are_ordered_by_line_and_column() -> None:
    first, second = _fake("npm-token", "1"), _fake("github-token", "2")
    text = f"{second} {first}\nx\n{first}\n"
    result = RULES_ONLY.scan(text.encode())
    assert [(m.line, m.col_start) for m in result.matches] == sorted(
        (m.line, m.col_start) for m in result.matches
    )
    assert len(result.matches) == 3


def test_buffer_result_is_frozen() -> None:
    result = ENGINE.scan(b"x\n")
    with pytest.raises(dataclasses.FrozenInstanceError):
        result.capped = True  # type: ignore[misc]


def test_no_model_reachable_from_report_can_hold_a_match() -> None:
    import typing

    seen: set[type] = set()
    stack: list[type] = [Report]
    while stack:
        cls = stack.pop()
        if cls in seen or not dataclasses.is_dataclass(cls):
            continue
        seen.add(cls)
        hints = typing.get_type_hints(cls)
        for hint in hints.values():
            for part in typing.get_args(hint) or (hint,):
                stack.append(part if isinstance(part, type) else typing.get_origin(part) or object)
                stack.extend(a for a in typing.get_args(part) if isinstance(a, type))
    assert Match not in seen
    assert Finding in seen


# -- overlap resolution against a naive reference ----------------------------------------------


def _naive_resolve(
    rule_hits: list[tuple[int, int, Match]],
    entropy_hits: list[tuple[int, int, Match]],
    protected: list[tuple[int, int]],
) -> list[Match]:
    def free(hit: tuple[int, int, Match]) -> bool:
        return not any(hit[0] < hi and lo < hit[1] for lo, hi in protected)

    def priority(hit: tuple[int, int, Match]) -> tuple[int, int, int, str]:
        return (-hit[2].confidence.rank, -hit[2].severity.rank, -(hit[1] - hit[0]), hit[2].rule_id)

    kept: list[tuple[int, int, Match]] = []
    for hit in sorted([h for h in rule_hits if free(h)], key=priority):
        if not any(hit[0] < k[1] and k[0] < hit[1] for k in kept):
            kept.append(hit)
    for hit in entropy_hits:
        if free(hit) and not any(hit[0] < k[1] and k[0] < hit[1] for k in kept):
            kept.append(hit)
    kept.sort(key=lambda h: (h[0], h[1]))
    return [h[2] for h in kept]


def test_resolution_matches_a_naive_reference_on_random_spans() -> None:
    import random

    rng = random.Random(4242)
    confidences = list(Confidence)
    severities = list(Severity)
    for trial in range(200):
        rule_hits = []
        for index in range(rng.randint(0, 25)):
            start = rng.randint(0, 80)
            end = start + rng.randint(1, 25)
            rule_hits.append(
                _hit(
                    f"r{trial}-{index}",
                    start,
                    end,
                    confidence=rng.choice(confidences),
                    severity=rng.choice(severities),
                )
            )
        entropy_hits = []
        position = 0
        for index in range(rng.randint(0, 6)):
            start = position + rng.randint(0, 20)
            end = start + rng.randint(20, 30)
            entropy_hits.append(_hit(f"e{trial}-{index}", start, end, detector=Detector.ENTROPY))
            position = end + 1
        protected = [(rng.randint(0, 100), rng.randint(101, 140))] if rng.random() < 0.3 else []
        assert resolve_line(rule_hits, entropy_hits, protected) == _naive_resolve(
            rule_hits, entropy_hits, protected
        )


def test_a_line_with_thousands_of_hits_is_resolved_and_capped() -> None:
    limits = replace(DEFAULT_LIMITS, max_findings_per_file=50)
    engine = Engine(ALL_RULES, entropy=EntropyConfig(enabled=False), limits=limits)
    fake = _fake("npm-token")
    line = (fake + " ") * 5000
    result = engine.scan(line.encode() + b"\n")
    assert len(result.matches) == 50
    assert result.capped
    assert [m.col_start for m in result.matches] == [1 + n * (len(fake) + 1) for n in range(50)]
