"""The human-readable report (PLAN.md D11). Pure: returns text, prints nothing.

Every string reaching this module was escaped by the sanitiser when its model was built (paths,
issue text, target) or is built from fixed vocabularies and hex digits (rule ids, redacted forms,
commit ids). It is checked again here with `require_display_safe`, so a value that skipped the
sanitiser fails loudly. Rows therefore cannot be broken or forged by a hostile name: a newline,
an ANSI sequence or a bidirectional control in a path is already an inert escape sequence.
"""

from __future__ import annotations

from secret_scanner.core.models import Finding, Report, ScanIssue, Target
from secret_scanner.core.sanitize import require_display_safe

MAX_LISTED_ISSUES = 50
COMMIT_CHARS = 12
_HEADERS = ("SEVERITY", "CONFIDENCE", "RULE", "LOCATION", "REDACTED")
_SKIP_LABELS = (
    ("skipped_binary", "binary"),
    ("skipped_symlink", "symlink"),
    ("skipped_offline", "offline"),
    ("skipped_special", "special"),
    ("skipped_excluded", "excluded"),
    ("skipped_gitignored", "gitignored"),
    ("skipped_submodule", "submodule"),
)


def _location(finding: Finding) -> str:
    location = finding.location
    text = (
        f"{require_display_safe(location.path, 'location path')}:{location.line}:{location.column}"
    )
    if location.commit is not None:
        text += "@" + require_display_safe(location.commit, "commit")[:COMMIT_CHARS]
    return text


def _row(finding: Finding) -> tuple[str, str, str, str, str]:
    redacted = require_display_safe(finding.redacted.text, "redacted value")
    if finding.suppressed_by is not None:
        redacted += f" [suppressed: {finding.suppressed_by.value}]"
    return (
        finding.severity.value,
        finding.confidence.value,
        require_display_safe(finding.rule_id, "rule id"),
        _location(finding),
        redacted,
    )


def _layout(rows: list[tuple[str, str, str, str, str]]) -> list[str]:
    widths = [max(len(_HEADERS[i]), *(len(row[i]) for row in rows)) for i in range(4)]
    lines = []
    for cells in [_HEADERS, *rows]:
        padded = [cells[i].ljust(widths[i]) for i in range(4)]
        lines.append("  ".join([*padded, cells[4]]).rstrip())
    return lines


def _issue_line(issue: ScanIssue) -> str:
    where = "" if issue.path is None else f"{require_display_safe(issue.path, 'issue path')}: "
    return f"  {issue.kind.value}  {where}{require_display_safe(issue.detail, 'issue detail')}"


def _skipped(report: Report) -> str:
    parts = [
        f"{label} {getattr(report.stats, field)}"
        for field, label in _SKIP_LABELS
        if getattr(report.stats, field)
    ]
    return ", ".join(parts) if parts else "none"


def render_table(report: Report) -> str:
    """The report as plain text: findings, then a summary that always states whether the run was
    complete. An incomplete run is announced above the findings, never only below them."""
    stats = report.stats
    reported = [f for f in report.findings if f.suppressed_by is None]
    shown_suppressed = [f for f in report.findings if f.suppressed_by is not None]
    kind = "history of" if report.target is Target.GIT else "scan of"
    target = require_display_safe(report.target_display, "target")
    lines = [
        f"secret-scanner {require_display_safe(report.tool_version, 'tool version')} - "
        f"{kind} {target}",
        f"generated {require_display_safe(report.generated_at, 'timestamp')}",
        "",
    ]
    if not report.complete:
        lines += [
            "RESULT: INCOMPLETE - part of the input was not scanned; not a clean result.",
            "",
        ]
    if report.truncated:
        lines += ["The report limit was reached: findings beyond it are not listed.", ""]
    if report.findings:
        lines += _layout([_row(finding) for finding in report.findings])
    else:
        lines.append("No findings.")
    lines += ["", "Summary"]
    lines.append(
        f"  files:     {stats.files_scanned} scanned of {stats.files_seen} seen "
        f"({stats.bytes_scanned} bytes)"
    )
    lines.append(f"  skipped:   {_skipped(report)}")
    if report.target is Target.GIT:
        lines.append(
            f"  history:   {stats.commits} commits, {stats.blobs_scanned} blobs scanned, "
            f"{stats.blobs_from_cache} from cache"
        )
        complete_history = (
            "unknown"
            if report.history_complete is None
            else ("yes" if report.history_complete else "no")
        )
        lines.append(f"  history complete: {complete_history}")
    suppressed = report.suppressed_by_fingerprint + report.suppressed_by_path
    lines.append(
        f"  findings:  {len(reported)} reported, {suppressed} suppressed "
        f"({report.suppressed_by_fingerprint} by fingerprint, {report.suppressed_by_path} by path)"
    )
    if shown_suppressed:
        lines.append(f"             {len(shown_suppressed)} suppressed finding(s) listed above")
    stale = "not judged (the run was incomplete)" if report.stale is None else str(report.stale)
    lines.append(f"  stale:     {stale}")
    lines.append(f"  issues:    {len(report.issues)}")
    lines.append(f"  complete:  {'yes' if report.complete else 'NO'}")
    if report.issues:
        lines += ["", f"Issues ({len(report.issues)})"]
        lines += [_issue_line(issue) for issue in report.issues[:MAX_LISTED_ISSUES]]
        hidden = len(report.issues) - MAX_LISTED_ISSUES
        if hidden > 0:
            lines.append(f"  ... and {hidden} more (see --format json)")
    return "\n".join(lines) + "\n"
