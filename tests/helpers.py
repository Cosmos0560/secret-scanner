"""Small shared helpers for tests."""

from __future__ import annotations

import getpass
import itertools
import os
import re
import sys
import tempfile
from datetime import UTC, datetime, timedelta
from pathlib import Path

from secret_scanner.core.models import (
    Confidence,
    Detector,
    Finding,
    Location,
    Redacted,
    Report,
    Rule,
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


def public_prefix_length(rule: Rule) -> int:
    """How many leading characters of a rule's fake are the format's fixed text, which is public
    and may appear in a description or a keyword: the literal segments before the first generated
    one (at least the rule's `shown_chars`)."""
    length = 0
    for segment in rule.fake:
        if segment.charset:
            break
        length += sum(len(part) for part in segment.parts)
    return max(length, rule.shown_chars)


# -- text that must not say where it was produced ----------------------------------------------

# An absolute path of any kind: `C:\dir` or `C:/dir`, a UNC or device path, and a POSIX path (a
# `/` that starts a name and follows nothing a relative path or a URL would have before it).
ABSOLUTE_PATH_PATTERNS = (
    ("a Windows drive path", re.compile(r"(?<![A-Za-z0-9])[A-Za-z]:[\\/]")),
    ("a UNC or device path", re.compile(r"(?<![\\/])\\\\[A-Za-z0-9?.]")),
    ("a POSIX absolute path", re.compile(r"(?<![\w.>/:\\~-])/[A-Za-z0-9._~-]")),
)


def login_name() -> str | None:
    """The account name of the person running the suite, or `None` when it cannot be read."""
    try:
        return getpass.getuser() or None
    except (KeyError, OSError):
        return None


def path_spellings(directory: str | Path) -> set[str]:
    """The ways one directory can be written: as given and resolved, with either separator."""
    spellings = set()
    for form in (str(directory), os.path.realpath(directory)):
        spellings.update({form, form.replace("\\", "/"), form.replace("/", "\\")})
    return {spelling for spelling in spellings if len(spelling) > 3}


def local_traces(
    text: str, *directories: str | Path, absolute_paths: bool = True, names: tuple[str, ...] = ()
) -> list[str]:
    """What in `text` tells a reader where, or under which account, it was produced: an absolute
    path, one of `directories` (the system temporary directory is always one), one of `names`,
    or the account name as a part of a path. Returns one description per trace; empty is clean.
    The descriptions never repeat the text itself."""
    found = []
    if absolute_paths:
        found += [what for what, pattern in ABSOLUTE_PATH_PATTERNS if pattern.search(text)]
    folded = text.casefold()
    for number, directory in enumerate((tempfile.gettempdir(), *directories)):
        if any(spelling.casefold() in folded for spelling in path_spellings(directory)):
            found.append("the system temporary directory" if number == 0 else f"directory {number}")
    found += [f"name {number}" for number, name in enumerate(names, 1) if name.casefold() in folded]
    for name in sorted(account_names()):
        # only below a profile parent: `gitio/runner.py` is not the account `runner`
        if re.search(r"(?:users|home)[\\/]+" + re.escape(name.casefold()) + r"(?![\w.-])", folded):
            found.append("the account name as a part of a path")
            break
    return found


def account_names() -> set[str]:
    """The names of the account that runs the suite: the login name, and the name of the profile
    directory wherever a known location shows one (`Users/<name>`, `home/<name>`). The home
    variables themselves point at a temporary directory during the session, so they are not
    asked."""
    names = {login_name() or ""}
    for location in (tempfile.gettempdir(), sys.base_prefix, sys.executable, str(PROJECT_ROOT)):
        parts = Path(os.path.realpath(location)).parts
        for parent, child in itertools.pairwise(parts):
            if parent.casefold() in {"users", "home"}:
                names.add(child)
    return {name for name in names if len(name) >= 2}


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
