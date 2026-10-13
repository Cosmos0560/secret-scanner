"""Small shared helpers for tests."""

from __future__ import annotations

from datetime import UTC, datetime, timedelta
from pathlib import Path

from secret_scanner.core.models import (
    Confidence,
    Detector,
    Finding,
    Location,
    Redacted,
    Report,
    ScanIssue,
    ScanStats,
    Severity,
    SuppressedBy,
    Target,
)

PROJECT_ROOT = Path(__file__).resolve().parent.parent

HASH8 = "0123abcd"
FINGERPRINT = "0123456789abcdef0123456789abcdef"


class FakeClock:
    """A deterministic `Clock`: time moves only when the test says so."""

    def __init__(self, start: datetime | None = None) -> None:
        self._now = start or datetime(2026, 1, 1, tzinfo=UTC)
        self._monotonic = 1000.0

    def now_utc(self) -> datetime:
        return self._now

    def monotonic(self) -> float:
        return self._monotonic

    def advance(self, seconds: float) -> None:
        self._now += timedelta(seconds=seconds)
        self._monotonic += seconds


# -- model builders for renderer and application tests ---------------------------------------


def make_finding(
    *,
    rule_id: str = "npm-token",
    path: str = "src/app.py",
    line: int = 3,
    column: int = 9,
    severity: Severity = Severity.HIGH,
    confidence: Confidence = Confidence.HIGH,
    commit: str | None = None,
    suppressed_by: SuppressedBy | None = None,
    fingerprint: str = FINGERPRINT,
    path_key: str | None = None,
) -> Finding:
    """A finding with a redacted value, for tests that never need a real detection."""
    return Finding(
        rule_id=rule_id,
        detector=Detector.RULE,
        severity=severity,
        confidence=confidence,
        location=Location(
            path_key=path_key or path,
            path=path,
            line=line,
            column=column,
            end_column=column + 40,
            commit=commit,
            commit_time=None if commit is None else 1_700_000_000,
        ),
        redacted=Redacted(
            shown="npm_", length=40, hash8=HASH8, text=f"npm_... [40 chars, sha256:{HASH8}]"
        ),
        fingerprint=fingerprint,
        suppressed_by=suppressed_by,
    )


def make_report(
    findings: tuple[Finding, ...] = (),
    *,
    target: Target = Target.FS,
    target_display: str = "project",
    issues: tuple[ScanIssue, ...] = (),
    stats: ScanStats | None = None,
    complete: bool | None = None,
    truncated: bool = False,
    stale: int | None = 0,
    by_fingerprint: int = 0,
    by_path: int = 0,
    history_complete: bool | None = None,
) -> Report:
    return Report(
        target=target,
        target_display=target_display,
        findings=findings,
        suppressed_by_fingerprint=by_fingerprint,
        suppressed_by_path=by_path,
        stale=stale,
        issues=issues,
        stats=stats or ScanStats(files_seen=4, files_scanned=3, bytes_scanned=1234),
        complete=(not issues) if complete is None else complete,
        truncated=truncated,
        rules_sha256="ab" * 32,
        generated_at="2026-01-01T00:00:00Z",
        tool_version="0.1.0",
        history_complete=history_complete,
    )
