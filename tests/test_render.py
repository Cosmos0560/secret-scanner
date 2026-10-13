"""The table and JSON renderers: layout, completeness statements, hostile names and the structural
promises of the `secret-report/1` document (PLAN.md D11)."""

from __future__ import annotations

import json

import pytest

from secret_scanner.core.models import (
    Confidence,
    IssueKind,
    ScanIssue,
    ScanStats,
    Severity,
    SuppressedBy,
    Target,
)
from secret_scanner.core.sanitize import sanitize
from secret_scanner.render.json_out import SCHEMA, render_json, report_document
from secret_scanner.render.table import MAX_LISTED_ISSUES, render_table
from tests.helpers import HASH8, make_finding, make_report

HOSTILE_NAME = "dir\x1b[31m\nname\u202eevil\u200b\r.txt\\x"
HOSTILE_SHOWN = sanitize(HOSTILE_NAME)


def issue(kind: IssueKind = IssueKind.UNREADABLE, path: str | None = "a.txt") -> ScanIssue:
    return ScanIssue(kind, path, "permission denied")


# -- table ------------------------------------------------------------------------------------


def test_table_lists_findings_with_location_and_a_complete_summary() -> None:
    report = make_report(
        (
            make_finding(path="src/app.py", line=3, column=9),
            make_finding(
                rule_id="aws-access-key-id",
                path="conf/.env",
                line=1,
                column=5,
                severity=Severity.CRITICAL,
                confidence=Confidence.MEDIUM,
                fingerprint="f" * 32,
            ),
        ),
        stats=ScanStats(files_seen=5, files_scanned=4, bytes_scanned=99, skipped_binary=1),
    )
    text = render_table(report)
    lines = text.splitlines()
    assert lines[0] == "secret-scanner 0.1.0 - scan of project"
    header = next(line for line in lines if line.startswith("SEVERITY"))
    assert header.split() == ["SEVERITY", "CONFIDENCE", "RULE", "LOCATION", "REDACTED"]
    assert any(
        line.split()[:5] == ["high", "high", "npm-token", "src/app.py:3:9", "npm_..."]
        for line in lines
    )
    assert f"[40 chars, sha256:{HASH8}]" in text
    assert "  files:     4 scanned of 5 seen (99 bytes)" in lines
    assert "  skipped:   binary 1" in lines
    assert "  findings:  2 reported, 0 suppressed (0 by fingerprint, 0 by path)" in lines
    assert "  stale:     0" in lines
    assert "  complete:  yes" in lines
    assert "RESULT: INCOMPLETE" not in text
    assert text.endswith("\n")


def test_table_columns_line_up() -> None:
    report = make_report(
        (
            make_finding(rule_id="a", path="x", fingerprint="1" * 32),
            make_finding(rule_id="long-rule-name", path="deep/path/file.txt", fingerprint="2" * 32),
        )
    )
    rows = [line for line in render_table(report).splitlines() if "npm_..." in line]
    assert len(rows) == 2
    assert rows[0].index("npm_...") == rows[1].index("npm_...")


def test_table_without_findings_says_so() -> None:
    text = render_table(make_report())
    assert "No findings." in text
    assert "  skipped:   none" in text.splitlines()


def test_table_marks_suppressed_findings_and_counts_them() -> None:
    report = make_report(
        (make_finding(suppressed_by=SuppressedBy.FINGERPRINT),),
        by_fingerprint=1,
        by_path=2,
    )
    text = render_table(report)
    assert "[suppressed: fingerprint]" in text
    assert (
        "  findings:  0 reported, 3 suppressed (1 by fingerprint, 2 by path)" in text.splitlines()
    )


def test_an_incomplete_run_is_announced_above_the_findings_and_in_the_summary() -> None:
    report = make_report(
        (make_finding(),),
        issues=(issue(IssueKind.TOO_LARGE, "big.bin"),),
        stale=None,
    )
    lines = render_table(report).splitlines()
    banner = next(i for i, line in enumerate(lines) if line.startswith("RESULT: INCOMPLETE"))
    header = next(i for i, line in enumerate(lines) if line.startswith("SEVERITY"))
    assert banner < header
    assert "  complete:  NO" in lines
    assert "  stale:     not judged (the run was incomplete)" in lines
    assert "  too_large  big.bin: permission denied" in lines


def test_a_truncated_report_says_findings_are_missing() -> None:
    text = render_table(make_report(truncated=True, issues=(issue(IssueKind.FINDINGS_CAP, None),)))
    assert "report limit was reached" in text


def test_issue_listing_is_bounded() -> None:
    many = tuple(issue(path=f"f{i}.txt") for i in range(MAX_LISTED_ISSUES + 7))
    text = render_table(make_report(issues=many))
    assert text.count("  unreadable  ") == MAX_LISTED_ISSUES
    assert "... and 7 more (see --format json)" in text


def test_table_for_a_git_target_shows_commits_and_the_location_commit() -> None:
    report = make_report(
        (make_finding(commit="a" * 40),),
        target=Target.GIT,
        stats=ScanStats(commits=12, blobs_scanned=30, blobs_from_cache=4),
        history_complete=True,
    )
    text = render_table(report)
    assert "history of project" in text.splitlines()[0]
    assert "src/app.py:3:9@" + "a" * 12 in text
    assert "a" * 13 not in text
    assert "  history:   12 commits, 30 blobs scanned, 4 from cache" in text.splitlines()
    assert "  history complete: yes" in text.splitlines()
    unknown = render_table(make_report(target=Target.GIT, history_complete=None))
    assert "  history complete: unknown" in unknown.splitlines()
    shallow = render_table(make_report(target=Target.GIT, history_complete=False))
    assert "  history complete: no" in shallow.splitlines()


def test_hostile_names_cannot_break_rows_or_reach_the_terminal() -> None:
    report = make_report(
        (make_finding(path=HOSTILE_SHOWN, path_key=HOSTILE_NAME),),
        issues=(issue(path=HOSTILE_SHOWN),),
        target_display=HOSTILE_SHOWN,
    )
    text = render_table(report)
    bad = [ch for ch in text if ch != "\n" and (ord(ch) < 0x20 or ord(ch) == 0x7F)]
    assert bad == []
    assert not any(0x202A <= ord(ch) <= 0x202E or 0x2066 <= ord(ch) <= 0x2069 for ch in text)
    assert "\u200b" not in text
    # one logical row per finding: the escaped newline did not start a new line
    assert sum(1 for line in text.splitlines() if "npm_..." in line) == 1


def test_a_value_that_skipped_the_sanitiser_is_refused_without_echoing_it() -> None:
    report = make_report((make_finding(rule_id="bad\nrule"),))
    with pytest.raises(ValueError, match="rule id is not escaped") as caught:
        render_table(report)
    assert "bad" not in str(caught.value)


# -- JSON -------------------------------------------------------------------------------------


def test_json_document_has_the_schema_keys_in_order() -> None:
    report = make_report(
        (
            make_finding(),
            make_finding(
                rule_id="private-key",
                path="k.pem",
                severity=Severity.CRITICAL,
                suppressed_by=SuppressedBy.PATH,
                fingerprint="e" * 32,
            ),
        ),
        by_path=1,
    )
    document = json.loads(render_json(report, "ci-host"))
    assert list(document) == [
        "schema",
        "tool",
        "generated_at",
        "host",
        "rules_sha256",
        "target",
        "complete",
        "truncated",
        "history_complete",
        "counts",
        "stats",
        "findings",
        "issues",
    ]
    assert document["schema"] == SCHEMA == "secret-report/1"
    assert document["tool"] == {"name": "secret-scanner", "version": "0.1.0"}
    assert document["host"] == "ci-host"
    assert document["target"] == {"kind": "fs", "path": "project"}
    assert document["complete"] is True
    assert document["history_complete"] is None
    counts = document["counts"]
    assert counts["findings"] == 1  # reported only
    assert counts["by_severity"] == {"info": 0, "low": 0, "medium": 0, "high": 1, "critical": 0}
    assert counts["suppressed_by_path"] == 1
    assert counts["stale"] == 0
    first, second = document["findings"]
    assert list(first) == [
        "rule_id",
        "detector",
        "severity",
        "confidence",
        "file",
        "line",
        "column",
        "end_column",
        "commit",
        "commit_time",
        "redacted",
        "fingerprint",
        "suppressed_by",
    ]
    assert first["suppressed_by"] is None
    assert second["suppressed_by"] == "path"
    assert first["redacted"] == {
        "shown": "npm_",
        "length": 40,
        "hash8": HASH8,
        "text": f"npm_... [40 chars, sha256:{HASH8}]",
    }
    assert document["stats"]["files_scanned"] == 3


def test_json_for_an_incomplete_run_carries_issues_and_a_null_stale() -> None:
    report = make_report(issues=(issue(IssueKind.TIME_BUDGET, None),), stale=None)
    document = json.loads(render_json(report, "h"))
    assert document["complete"] is False
    assert document["counts"]["stale"] is None
    assert document["counts"]["issues"] == 1
    assert document["issues"] == [
        {"kind": "time_budget", "path": None, "detail": "permission denied"}
    ]


def test_json_is_ascii_valid_and_round_trips_hostile_names() -> None:
    report = make_report(
        (make_finding(path=HOSTILE_SHOWN, path_key=HOSTILE_NAME),),
        issues=(issue(path=HOSTILE_SHOWN),),
        target_display=HOSTILE_SHOWN,
    )
    text = render_json(report, "build-host")
    assert text.isascii()
    assert not any(ord(ch) < 0x20 for ch in text if ch != "\n")
    document = json.loads(text)
    assert document["findings"][0]["file"] == HOSTILE_SHOWN
    assert document["target"]["path"] == HOSTILE_SHOWN
    assert "\x1b" not in text
    assert "\u202e" not in text


def test_json_encodes_printable_non_ascii_names_as_escapes() -> None:
    name = "café/日本.txt"
    report = make_report((make_finding(path=name, path_key=name),))
    text = render_json(report, "h")
    assert text.isascii()
    assert json.loads(text)["findings"][0]["file"] == name


def test_json_output_is_deterministic() -> None:
    report = make_report((make_finding(),))
    assert render_json(report, "h") == render_json(report, "h")
    assert report_document(report, "h") == json.loads(render_json(report, "h"))


def test_json_refuses_an_unescaped_value() -> None:
    with pytest.raises(ValueError, match="host label is not escaped"):
        render_json(make_report(), "host\nname")
    with pytest.raises(ValueError, match="rule id is not escaped"):
        render_json(make_report((make_finding(rule_id="x\ny"),)), "h")
