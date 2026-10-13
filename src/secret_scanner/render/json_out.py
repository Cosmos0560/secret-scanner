"""The JSON report, schema `secret-report/1` (PLAN.md D11, documented in docs/report-schema.md).

One document, ASCII only (`ensure_ascii`), with a fixed key order, so two runs over the same input
are byte-identical apart from `generated_at`. Strings are the display-escaped forms the models
already hold; they are checked again here, and the encoder then turns every remaining non-ASCII
character into a `\\uXXXX` escape, so the output is valid JSON whatever the file names contained.
"""

from __future__ import annotations

import json
from dataclasses import asdict

from secret_scanner.core.models import Finding, Report, ScanIssue, Severity
from secret_scanner.core.sanitize import require_display_safe

SCHEMA = "secret-report/1"
TOOL_NAME = "secret-scanner"


def _text(value: str, what: str) -> str:
    return require_display_safe(value, what)


def _optional(value: str | None, what: str) -> str | None:
    return None if value is None else require_display_safe(value, what)


def _finding(finding: Finding) -> dict[str, object]:
    location = finding.location
    redacted = finding.redacted
    return {
        "rule_id": _text(finding.rule_id, "rule id"),
        "detector": finding.detector.value,
        "severity": finding.severity.value,
        "confidence": finding.confidence.value,
        "file": _text(location.path, "location path"),
        "line": location.line,
        "column": location.column,
        "end_column": location.end_column,
        "commit": _optional(location.commit, "commit"),
        "commit_time": location.commit_time,
        "redacted": {
            "shown": _text(redacted.shown, "redacted prefix"),
            "length": redacted.length,
            "hash8": redacted.hash8,
            "text": _text(redacted.text, "redacted value"),
        },
        "fingerprint": _text(finding.fingerprint, "fingerprint"),
        "suppressed_by": None if finding.suppressed_by is None else finding.suppressed_by.value,
    }


def _issue(issue: ScanIssue) -> dict[str, object]:
    return {
        "kind": issue.kind.value,
        "path": _optional(issue.path, "issue path"),
        "detail": _text(issue.detail, "issue detail"),
    }


def report_document(report: Report, host: str) -> dict[str, object]:
    """The report as plain data, in the key order of the schema."""
    reported = [f for f in report.findings if f.suppressed_by is None]
    by_severity = {severity.value: 0 for severity in Severity}
    for finding in reported:
        by_severity[finding.severity.value] += 1
    return {
        "schema": SCHEMA,
        "tool": {"name": TOOL_NAME, "version": _text(report.tool_version, "tool version")},
        "generated_at": _text(report.generated_at, "timestamp"),
        "host": _text(host, "host label"),
        "rules_sha256": _text(report.rules_sha256, "rules hash"),
        "target": {
            "kind": report.target.value,
            "path": _text(report.target_display, "target"),
        },
        "complete": report.complete,
        "truncated": report.truncated,
        "history_complete": report.history_complete,
        "counts": {
            "findings": len(reported),
            "by_severity": by_severity,
            "suppressed_by_fingerprint": report.suppressed_by_fingerprint,
            "suppressed_by_path": report.suppressed_by_path,
            "stale": report.stale,
            "issues": len(report.issues),
        },
        "stats": asdict(report.stats),
        "findings": [_finding(finding) for finding in report.findings],
        "issues": [_issue(issue) for issue in report.issues],
    }


def render_json(report: Report, host: str) -> str:
    """The report as one JSON document followed by a newline."""
    document = report_document(report, host)
    return json.dumps(document, ensure_ascii=True, indent=2, allow_nan=False) + "\n"
