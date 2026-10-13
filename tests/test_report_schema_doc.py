"""Drift tests: docs/report-schema.md and the code agree on fields, vocabularies, exit codes and the
examples (CLAUDE.md section 10)."""

from __future__ import annotations

import json
import re
from dataclasses import asdict
from enum import StrEnum

import pytest

from secret_scanner.core.errors import EXIT_PRECEDENCE, ExitCode
from secret_scanner.core.models import (
    Confidence,
    Detector,
    IssueKind,
    ScanIssue,
    ScanStats,
    Severity,
    SuppressedBy,
    Target,
)
from secret_scanner.render.json_out import SCHEMA, report_document
from secret_scanner.render.table import MAX_LISTED_ISSUES
from tests.helpers import PROJECT_ROOT, make_finding, make_report

DOC = (PROJECT_ROOT / "docs" / "report-schema.md").read_text(encoding="utf-8")


def section(heading: str) -> str:
    """The text under `heading` (a full heading line) up to the next heading of the same or a
    higher level."""
    level = len(heading) - len(heading.lstrip("#"))
    lines = DOC.splitlines()
    start = lines.index(heading)
    body: list[str] = []
    for line in lines[start + 1 :]:
        match = re.match(r"(#+) ", line)
        if match and len(match.group(1)) <= level:
            break
        body.append(line)
    return "\n".join(body)


def table_fields(heading: str) -> list[str]:
    """The backticked first cells of the table directly under `heading`, in order (a sub-heading
    ends it)."""
    own = section(heading).split("\n### ")[0]
    return re.findall(r"^\| `([a-z_0-9]+)` \|", own, flags=re.MULTILINE)


def sample() -> dict[str, object]:
    report = make_report(
        (make_finding(suppressed_by=SuppressedBy.PATH),),
        issues=(ScanIssue(IssueKind.UNREADABLE, "a.txt", "permission denied"),),
    )
    return report_document(report, "host")


def test_the_top_level_fields_are_documented_in_order() -> None:
    assert table_fields("## Top-level fields") == list(sample())


@pytest.mark.parametrize(
    ("heading", "path"),
    [
        ("### `counts`", ["counts"]),
        ("### `stats`", ["stats"]),
        ("### `findings[]`", ["findings", 0]),
        ("### `issues[]`", ["issues", 0]),
    ],
)
def test_nested_fields_are_documented_in_order(heading: str, path: list[str | int]) -> None:
    node: object = sample()
    for step in path:
        node = node[step]  # type: ignore[index]  # walking plain JSON-shaped data
    assert isinstance(node, dict)
    assert table_fields(heading) == list(node)


def test_stats_fields_are_the_scan_stats_model() -> None:
    assert table_fields("### `stats`") == list(asdict(ScanStats()))


@pytest.mark.parametrize(
    ("label", "vocabulary"),
    [
        ("Severity", Severity),
        ("Confidence", Confidence),
        ("Detector", Detector),
        ("Target", Target),
        ("Suppressed by", SuppressedBy),
        ("Issue kind", IssueKind),
    ],
)
def test_vocabularies_are_documented(label: str, vocabulary: type[StrEnum]) -> None:
    text = " ".join(section("## Vocabularies").split())
    match = re.search(rf"- {re.escape(label)}: (.*?)(?= - [A-Z]|$)", text)
    assert match is not None, label
    assert re.findall(r"`([a-z_]+)`", match.group(1)) == [member.value for member in vocabulary]


def test_by_severity_lists_every_severity_in_the_document() -> None:
    counts = sample()["counts"]
    assert isinstance(counts, dict)
    assert list(counts["by_severity"]) == [severity.value for severity in Severity]


def test_exit_codes_and_precedence_are_documented() -> None:
    rows = re.findall(r"^\| (\d) \|", section("## Exit codes"), flags=re.MULTILINE)
    assert [int(code) for code in rows] == [int(code) for code in sorted(ExitCode)]
    precedence = ", then ".join(str(int(code)) for code in EXIT_PRECEDENCE)
    assert f"Precedence when more than one applies: {precedence}." in " ".join(
        section("## Exit codes").split()
    )


def test_the_schema_name_is_documented() -> None:
    assert f"`{SCHEMA}`" in section("## Top-level fields")
    assert DOC.startswith(f"# Report schema `{SCHEMA}`")


def test_the_issue_listing_bound_is_documented() -> None:
    assert f"At most {MAX_LISTED_ISSUES} issues are listed in the table" in " ".join(DOC.split())


def _fenced(language: str, under: str) -> str:
    match = re.search(rf"```{language}\n(.*?)\n```", section(under), flags=re.DOTALL)
    assert match is not None
    return match.group(1)


def test_the_json_example_has_the_documented_shape_and_only_redacted_values() -> None:
    example = json.loads(_fenced("json", "## Example"))
    assert list(example) == list(sample())
    assert example["schema"] == SCHEMA
    assert example["counts"]["findings"] == len(example["findings"]) == 2
    assert list(example["counts"]) == list(sample()["counts"])  # type: ignore[call-overload]
    assert list(example["stats"]) == list(asdict(ScanStats()))
    redacted = re.compile(r"^[ -~]{0,12}\.\.\. \[\d+ chars, sha256:[0-9a-f]{8}\]$")
    for finding in example["findings"]:
        assert list(finding) == list(sample()["findings"][0])  # type: ignore[index]
        assert redacted.match(finding["redacted"]["text"])
        assert re.fullmatch(r"[0-9a-f]{32}", finding["fingerprint"])
    assert re.fullmatch(r"[0-9a-f]{64}", example["rules_sha256"])
    assert re.fullmatch(r"\d{4}-\d\d-\d\dT\d\d:\d\d:\d\dZ", example["generated_at"])


def test_the_table_example_has_the_documented_columns_and_summary() -> None:
    table = _fenced("", "## The table")
    lines = table.splitlines()
    header = next(line for line in lines if line.startswith("SEVERITY"))
    assert header.split() == ["SEVERITY", "CONFIDENCE", "RULE", "LOCATION", "REDACTED"]
    for label in ("files:", "skipped:", "findings:", "stale:", "issues:", "complete:"):
        assert any(line.strip().startswith(label) for line in lines), label
    assert "[suppressed: fingerprint]" in section("## The table")


def test_the_document_is_plain_ascii() -> None:
    assert DOC.isascii()
