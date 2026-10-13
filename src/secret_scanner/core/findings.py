"""`Match` + location -> `Finding` (PLAN.md section 2, D7, D8).

This is where a secret stops existing as a value: it becomes a `Redacted` form and a fingerprint,
and the `Match` is dropped. A `Finding` has no field that could hold the secret.
"""

from __future__ import annotations

from secret_scanner.core.detect.match import Match
from secret_scanner.core.fingerprint import fingerprint
from secret_scanner.core.models import Detector, Finding, Location, Redacted
from secret_scanner.core.redact import redact_private_key, redact_secret


def finding_sort_key(finding: Finding) -> tuple[str, int, int, str]:
    """Report order: path, line, column, rule. Stable across runs, so reports can be diffed."""
    location = finding.location
    return (location.path_key, location.line, location.column, finding.rule_id)


def redact_match(match: Match) -> Redacted:
    """The only form of a matched secret that may be shown."""
    if match.detector is Detector.PRIVATE_KEY:
        return redact_private_key(match.secret, match.kind_label)
    return redact_secret(match.secret, match.shown_chars)


def to_finding(
    match: Match,
    *,
    path_key: str,
    path: str,
    commit: str | None = None,
    commit_time: int | None = None,
) -> Finding:
    """Build the finding for `match` found at `path_key` (exact, for the fingerprint) shown as
    `path` (already escaped for display)."""
    return Finding(
        rule_id=match.rule_id,
        detector=match.detector,
        severity=match.severity,
        confidence=match.confidence,
        location=Location(
            path_key=path_key,
            path=path,
            line=match.line,
            column=match.col_start,
            end_column=match.col_end,
            commit=commit,
            commit_time=commit_time,
        ),
        redacted=redact_match(match),
        fingerprint=fingerprint(match.rule_id, path_key, match.secret),
    )
