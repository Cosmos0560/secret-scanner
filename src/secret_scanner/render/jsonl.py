"""The JSONL report for mini-siem, schema `secret-event/1` (PLAN.md D11, docs/siem-mapping.md).

One line per finding, then one final summary line, each a single JSON object, ASCII only
(`ensure_ascii`), compact, with a fixed key order. The shape follows what mini-siem's generic JSON
parser maps without any change to mini-siem: the top-level keys are `timestamp`, `host`, `message`
and `event_type` (the parser's own aliases), everything else sits in the object `secret`, which the
parser flattens into `secret.<name>` attributes. There is never a top-level `path`, `url`, `user`,
`ip`, `status`, `method` or any other key the parser would reinterpret.

No field holds a secret: the redacted form, the length, the 8-hex display hash and the fingerprint
are all there is (PLAN.md D7, D8), and there is no source line.
"""

from __future__ import annotations

import hashlib
import json

from secret_scanner.core.models import Finding, Report, Severity, Target
from secret_scanner.core.sanitize import clip_display, require_display_safe

SCHEMA = "secret-event/1"
EVENT_FINDING = "secret.finding"
EVENT_SUMMARY = "secret.scan_summary"

# Limits recorded in docs/siem-mapping.md (mini-siem: attribute values are cut at 1 024 characters,
# at most 64 attributes of 64-character keys, a collector line at 65 536 bytes).
MAX_VALUE_CHARS = 1_024
MAX_FILE_CHARS = 1_000
MESSAGE_FILE_CHARS = 200
COMMIT_CHARS = 12

# The finding's keys inside `secret`, in order. docs/siem-mapping.md lists the same names.
FINDING_FIELDS = (
    "rule_id",
    "detector",
    "severity",
    "confidence",
    "file",
    "file_sha256",
    "file_truncated",
    "line",
    "column",
    "commit",
    "commit_time",
    "redacted",
    "secret_length",
    "secret_hash8",
    "fingerprint",
    "target",
    "tool_version",
    "schema",
    "suppressed_by",
)

SUMMARY_FIELDS = (
    "target",
    "target_path",
    "target_path_truncated",
    "findings",
    "findings_critical",
    "findings_high",
    "findings_medium",
    "findings_low",
    "findings_info",
    "suppressed_by_fingerprint",
    "suppressed_by_path",
    "stale",
    "issues",
    "complete",
    "truncated",
    "history_complete",
    "files_seen",
    "files_scanned",
    "commits",
    "rules_sha256",
    "tool_version",
    "schema",
)

TOP_LEVEL_FIELDS = ("timestamp", "host", "message", "event_type", "secret")


def _text(value: str, what: str) -> str:
    return require_display_safe(value, what)


def _line(document: dict[str, object]) -> str:
    return json.dumps(document, ensure_ascii=True, separators=(",", ":"), allow_nan=False)


def _message_for(finding: Finding, shown_file: str) -> str:
    location = finding.location
    excerpt, cut = clip_display(shown_file, MESSAGE_FILE_CHARS)
    text = (
        f"{_text(finding.rule_id, 'rule id')}: {_text(finding.redacted.text, 'redacted value')} "
        f"at {excerpt}{'...' if cut else ''}:{location.line}:{location.column}"
    )
    if location.commit is not None:
        text += " in commit " + _text(location.commit, "commit")[:COMMIT_CHARS]
    if finding.suppressed_by is not None:
        text += f" (suppressed by {finding.suppressed_by.value})"
    return text


def _finding_event(finding: Finding, report: Report, host: str) -> dict[str, object]:
    location = finding.location
    path = _text(location.path, "location path")
    shown_file, file_truncated = clip_display(path, MAX_FILE_CHARS)
    redacted = finding.redacted
    secret: dict[str, object] = {
        "rule_id": _text(finding.rule_id, "rule id"),
        "detector": finding.detector.value,
        "severity": finding.severity.value,
        "confidence": finding.confidence.value,
        "file": shown_file,
        "file_sha256": hashlib.sha256(path.encode("utf-8")).hexdigest(),
        "file_truncated": file_truncated,
        "line": location.line,
        "column": location.column,
        "commit": None if location.commit is None else _text(location.commit, "commit"),
        "commit_time": location.commit_time,
        "redacted": _text(redacted.text, "redacted value"),
        "secret_length": redacted.length,
        "secret_hash8": redacted.hash8,
        "fingerprint": _text(finding.fingerprint, "fingerprint"),
        "target": report.target.value,
        "tool_version": _text(report.tool_version, "tool version"),
        "schema": SCHEMA,
        "suppressed_by": None if finding.suppressed_by is None else finding.suppressed_by.value,
    }
    return {
        "timestamp": _text(report.generated_at, "timestamp"),
        "host": _text(host, "host label"),
        "message": _message_for(finding, shown_file),
        "event_type": EVENT_FINDING,
        "secret": secret,
    }


def _summary_event(report: Report, host: str) -> dict[str, object]:
    reported = [f for f in report.findings if f.suppressed_by is None]
    by_severity = dict.fromkeys(Severity, 0)
    for finding in reported:
        by_severity[finding.severity] += 1
    target_path, target_truncated = clip_display(
        _text(report.target_display, "target"), MAX_FILE_CHARS
    )
    kind = "history" if report.target is Target.GIT else "directory"
    state = "complete" if report.complete else "INCOMPLETE"
    stats = report.stats
    secret: dict[str, object] = {
        "target": report.target.value,
        "target_path": target_path,
        "target_path_truncated": target_truncated,
        "findings": len(reported),
        "findings_critical": by_severity[Severity.CRITICAL],
        "findings_high": by_severity[Severity.HIGH],
        "findings_medium": by_severity[Severity.MEDIUM],
        "findings_low": by_severity[Severity.LOW],
        "findings_info": by_severity[Severity.INFO],
        "suppressed_by_fingerprint": report.suppressed_by_fingerprint,
        "suppressed_by_path": report.suppressed_by_path,
        "stale": report.stale,
        "issues": len(report.issues),
        "complete": report.complete,
        "truncated": report.truncated,
        "history_complete": report.history_complete,
        "files_seen": stats.files_seen,
        "files_scanned": stats.files_scanned,
        "commits": stats.commits,
        "rules_sha256": _text(report.rules_sha256, "rules hash"),
        "tool_version": _text(report.tool_version, "tool version"),
        "schema": SCHEMA,
    }
    return {
        "timestamp": _text(report.generated_at, "timestamp"),
        "host": _text(host, "host label"),
        "message": (
            f"secret-scanner {kind} scan {state}: {len(reported)} finding(s), "
            f"{len(report.issues)} issue(s)"
        ),
        "event_type": EVENT_SUMMARY,
        "secret": secret,
    }


def jsonl_events(report: Report, host: str) -> list[dict[str, object]]:
    """The events in output order: one per finding (report order), then the summary."""
    events = [_finding_event(finding, report, host) for finding in report.findings]
    events.append(_summary_event(report, host))
    return events


def render_jsonl(report: Report, host: str) -> str:
    """The report as JSON lines, each ending with a newline."""
    return "".join(_line(event) + "\n" for event in jsonl_events(report, host))
