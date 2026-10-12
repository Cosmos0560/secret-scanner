"""Baseline schema, suppression matching, stale counting and the written document (PLAN.md D9)."""

from __future__ import annotations

from typing import Any

import pytest

from secret_scanner.core.errors import ConfigError
from secret_scanner.core.limits import DEFAULT_LIMITS
from secret_scanner.core.models import (
    Confidence,
    Detector,
    Finding,
    Location,
    Redacted,
    Severity,
    SuppressedBy,
    SuppressionEntry,
    Suppressions,
)
from secret_scanner.core.suppress import (
    DEFAULT_REASON,
    apply_suppressions,
    baseline_document,
    count_stale,
    parse_baseline,
)

PRINT_A = "a" * 32
PRINT_B = "b" * 32
PRINT_C = "c" * 32


def finding(
    fingerprint: str = PRINT_A,
    *,
    rule_id: str = "npm-token",
    path_key: str = "src/app.py",
    path: str | None = None,
    line: int = 1,
) -> Finding:
    return Finding(
        rule_id=rule_id,
        detector=Detector.RULE,
        severity=Severity.HIGH,
        confidence=Confidence.HIGH,
        location=Location(
            path_key=path_key,
            path=path if path is not None else path_key,
            line=line,
            column=1,
            end_column=5,
        ),
        redacted=Redacted(shown="npm_", length=40, hash8="0" * 8, text="npm_... [40 chars]"),
        fingerprint=fingerprint,
    )


# -- parsing ----------------------------------------------------------------------------------


def test_a_full_document_is_parsed() -> None:
    parsed = parse_baseline(
        {
            "version": 1,
            "suppress": [
                {"fingerprint": PRINT_A, "rule": "npm-token", "path": "a.py", "reason": "why"},
                {"fingerprint": PRINT_B},
            ],
            "paths": ["tests/fixtures/**"],
        }
    )
    assert parsed.entries == (
        SuppressionEntry(PRINT_A, "npm-token", "a.py", "why"),
        SuppressionEntry(PRINT_B, None, None, None),
    )
    assert parsed.paths == ("tests/fixtures/**",)


@pytest.mark.parametrize(
    "document", [{"version": 1}, {"version": 1, "suppress": None, "paths": None}]
)
def test_suppress_and_paths_are_optional(document: dict[str, Any]) -> None:
    assert parse_baseline(document) == Suppressions()


def _entry(**changes: Any) -> dict[str, Any]:
    return {"version": 1, "suppress": [{"fingerprint": PRINT_A, **changes}]}


REFUSED = [
    ([], "must be a mapping"),
    ("text", "must be a mapping"),
    ({}, "version must be 1"),
    ({"version": 2}, "version must be 1"),
    ({"version": True}, "version must be 1"),
    ({"version": "1"}, "version must be 1"),
    ({"version": 1, "extra": 1}, "unknown key 'extra'"),
    ({"version": 1, "suppress": "x"}, "suppress: must be a list"),
    ({"version": 1, "paths": "x"}, "paths: must be a list"),
    ({"version": 1, "suppress": ["x"]}, "must be a mapping"),
    ({"version": 1, "suppress": [{}]}, "missing key 'fingerprint'"),
    ({"version": 1, "suppress": [{"fingerprint": "A" * 32}]}, "lower-case hex"),
    ({"version": 1, "suppress": [{"fingerprint": "a" * 31}]}, "lower-case hex"),
    ({"version": 1, "suppress": [{"fingerprint": "g" * 32}]}, "lower-case hex"),
    ({"version": 1, "suppress": [{"fingerprint": 5}]}, "lower-case hex"),
    (_entry(extra="x"), "unknown key 'extra'"),
    (_entry(rule="Not Kebab"), "kebab-case"),
    (_entry(rule=5), "must be a string"),
    (_entry(path="a\x00b"), "control character"),
    (_entry(path="p" * 4097), "longer than 4096"),
    (_entry(reason="r\nx"), "control character"),
    (_entry(reason="r" * 513), "longer than 512"),
    (
        {"version": 1, "suppress": [{"fingerprint": PRINT_A}, {"fingerprint": PRINT_A}]},
        "duplicate fingerprint",
    ),
    ({"version": 1, "paths": [5]}, "must be a string"),
    ({"version": 1, "paths": ["/abs"]}, "must be relative"),
    ({"version": 1, "paths": ["a\nb"]}, "control character"),
    ({"version": 1, "paths": ["x"] * 257}, "more than 256 globs"),
]


@pytest.mark.parametrize(("document", "reason"), REFUSED)
def test_malformed_documents_are_refused(document: object, reason: str) -> None:
    with pytest.raises(ConfigError, match=reason):
        parse_baseline(document)


def test_the_entry_count_is_bounded() -> None:
    limits = DEFAULT_LIMITS.with_overrides({"max_baseline_entries": 2})
    entries = [{"fingerprint": f"{n:032x}"} for n in range(3)]
    with pytest.raises(ConfigError, match="more than 2 entries"):
        parse_baseline({"version": 1, "suppress": entries}, limits)
    assert len(parse_baseline({"version": 1, "suppress": entries[:2]}, limits).entries) == 2


# -- matching ---------------------------------------------------------------------------------


def test_fingerprint_and_path_suppression_are_counted_apart() -> None:
    findings = [
        finding(PRINT_A, path_key="a.py"),
        finding(PRINT_B, path_key="tests/fixtures/x.py"),
        finding(PRINT_C, path_key="b.py"),
    ]
    result = apply_suppressions(
        findings,
        Suppressions(
            entries=(SuppressionEntry(PRINT_A, None, None, None),), paths=("tests/fixtures/**",)
        ),
    )
    assert [f.fingerprint for f in result.reported] == [PRINT_C]
    assert [(f.fingerprint, f.suppressed_by) for f in result.suppressed] == [
        (PRINT_A, SuppressedBy.FINGERPRINT),
        (PRINT_B, SuppressedBy.PATH),
    ]
    assert (result.by_fingerprint, result.by_path) == (1, 1)


def test_a_finding_matching_both_counts_under_the_fingerprint() -> None:
    result = apply_suppressions(
        [finding(PRINT_A, path_key="tests/x.py")],
        Suppressions(entries=(SuppressionEntry(PRINT_A, None, None, None),), paths=("tests/**",)),
    )
    assert (result.by_fingerprint, result.by_path) == (1, 0)


def test_an_entry_naming_another_rule_does_not_suppress() -> None:
    entry = SuppressionEntry(PRINT_A, "github-token", None, None)
    result = apply_suppressions([finding(PRINT_A, rule_id="npm-token")], Suppressions((entry,)))
    assert len(result.reported) == 1
    assert result.suppressed == ()
    matching = SuppressionEntry(PRINT_A, "npm-token", None, None)
    assert apply_suppressions([finding()], Suppressions((matching,))).by_fingerprint == 1


def test_two_occurrences_with_one_fingerprint_are_suppressed_together() -> None:
    findings = [finding(PRINT_A, line=1), finding(PRINT_A, line=9)]
    result = apply_suppressions(
        findings, Suppressions((SuppressionEntry(PRINT_A, None, None, None),))
    )
    assert result.by_fingerprint == 2
    assert result.reported == ()


def test_path_globs_match_the_exact_path_key_not_the_display_form() -> None:
    odd = finding(PRINT_A, path_key="d/\udcff.txt", path="d/\\udcff.txt")
    result = apply_suppressions([odd], Suppressions(paths=("d/*.txt",)))
    assert result.by_path == 1


def test_no_suppressions_reports_everything_in_order() -> None:
    findings = [finding(PRINT_B), finding(PRINT_A)]
    result = apply_suppressions(findings, Suppressions())
    assert result.reported == tuple(findings)
    assert result.suppressed == ()


# -- staleness --------------------------------------------------------------------------------


def test_stale_entries_are_those_no_detected_finding_matches() -> None:
    entries = [
        SuppressionEntry(PRINT_A, None, None, None),
        SuppressionEntry(PRINT_B, None, None, None),
        SuppressionEntry(PRINT_C, "github-token", None, None),
    ]
    detected = [finding(PRINT_A), finding(PRINT_C, rule_id="npm-token")]
    # A is live, B has no finding, C names a rule that did not produce that fingerprint.
    assert count_stale(entries, detected) == 2
    assert count_stale(entries, []) == 3
    assert count_stale([], detected) == 0


# -- the written document ---------------------------------------------------------------------


def test_baseline_document_is_sorted_deduplicated_and_round_trips() -> None:
    findings = [
        finding(PRINT_B, path_key="z.py", rule_id="npm-token"),
        finding(PRINT_A, path_key="a.py", rule_id="npm-token"),
        finding(PRINT_A, path_key="a.py", rule_id="npm-token", line=7),  # same fingerprint
    ]
    document = baseline_document(findings, paths=["vendor/**"])
    entries = document["suppress"]
    assert isinstance(entries, list)
    assert document["version"] == 1
    assert [entry["fingerprint"] for entry in entries] == [PRINT_A, PRINT_B]
    assert {entry["reason"] for entry in entries} == {DEFAULT_REASON}
    assert document["paths"] == ["vendor/**"]
    parsed = parse_baseline(document)
    assert [entry.fingerprint for entry in parsed.entries] == [PRINT_A, PRINT_B]
    assert apply_suppressions(findings, parsed).reported == ()


def test_baseline_document_of_nothing_is_valid() -> None:
    document = baseline_document([])
    assert document == {"version": 1, "suppress": [], "paths": []}
    assert parse_baseline(document) == Suppressions()
