"""Enums and frozen dataclasses (PLAN.md section 2).

`Finding` and everything reachable from `Report` has no field that can hold a secret: the secret
value exists only in the detection layer's internal `Match` type and is turned into a `Redacted`
value and a fingerprint before it leaves that layer. A test walks the annotations of these types
and fails on any `bytes` field or any field named like a secret.
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import StrEnum

_HEX = frozenset("0123456789abcdef")


class Severity(StrEnum):
    """How bad a leak of this kind is (from the rule)."""

    INFO = "info"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"

    @property
    def rank(self) -> int:
        return list(type(self)).index(self)

    def at_least(self, other: Severity) -> bool:
        return self.rank >= other.rank


class Confidence(StrEnum):
    """How sure the detection is (rule, adjusted by checksum, context or completeness)."""

    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"

    @property
    def rank(self) -> int:
        return list(type(self)).index(self)

    def at_least(self, other: Confidence) -> bool:
        return self.rank >= other.rank


class Detector(StrEnum):
    RULE = "rule"
    ENTROPY = "entropy"
    PRIVATE_KEY = "private_key"


class Target(StrEnum):
    FS = "fs"
    GIT = "git"


class SuppressedBy(StrEnum):
    FINGERPRINT = "fingerprint"
    PATH = "path"


class IssueKind(StrEnum):
    """Why part of the input was not fully scanned. Every kind makes the run incomplete."""

    UNREADABLE = "unreadable"
    VANISHED = "vanished"
    UNSTABLE = "unstable"
    TOO_LARGE = "too_large"
    LINE_TOO_LONG = "line_too_long"
    UNDECODABLE = "undecodable"
    LIMIT_REACHED = "limit_reached"
    TIME_BUDGET = "time_budget"
    MISSING_OBJECT = "missing_object"
    SHALLOW_HISTORY = "shallow_history"
    FINDINGS_CAP = "findings_cap"


@dataclass(frozen=True, slots=True)
class Redacted:
    """What may be shown of a secret (PLAN.md D7): a public prefix, a length and a short hash."""

    shown: str
    length: int
    hash8: str
    text: str

    def __post_init__(self) -> None:
        if self.length < 0:
            raise ValueError("length must not be negative")
        if len(self.hash8) != 8 or not set(self.hash8) <= _HEX:
            raise ValueError("hash8 must be 8 lower-case hex digits")


@dataclass(frozen=True, slots=True)
class Location:
    """Where a finding is. `path_key` is exact (for fingerprints); `path` is escaped for display."""

    path_key: str
    path: str
    line: int
    column: int
    end_column: int
    commit: str | None = None
    commit_time: int | None = None

    def __post_init__(self) -> None:
        if self.line < 1 or self.column < 1 or self.end_column < self.column:
            raise ValueError("line and column are 1-based and end_column must not precede column")


@dataclass(frozen=True, slots=True)
class Finding:
    rule_id: str
    detector: Detector
    severity: Severity
    confidence: Confidence
    location: Location
    redacted: Redacted
    fingerprint: str
    suppressed_by: SuppressedBy | None = None


@dataclass(frozen=True, slots=True)
class ScanIssue:
    """A recorded problem. `path` is already escaped; `detail` never contains file content."""

    kind: IssueKind
    path: str | None
    detail: str


@dataclass(frozen=True, slots=True)
class ScanStats:
    files_seen: int = 0
    files_scanned: int = 0
    bytes_scanned: int = 0
    skipped_binary: int = 0
    skipped_symlink: int = 0
    skipped_offline: int = 0
    skipped_special: int = 0
    skipped_excluded: int = 0
    skipped_gitignored: int = 0
    skipped_submodule: int = 0
    commits: int = 0
    blobs_scanned: int = 0
    blobs_from_cache: int = 0


@dataclass(frozen=True, slots=True)
class SuppressionEntry:
    fingerprint: str
    rule: str | None
    path: str | None
    reason: str | None


@dataclass(frozen=True, slots=True)
class Suppressions:
    entries: tuple[SuppressionEntry, ...] = ()
    paths: tuple[str, ...] = ()


@dataclass(frozen=True, slots=True)
class Report:
    target: Target
    target_display: str
    findings: tuple[Finding, ...]
    suppressed_by_fingerprint: int
    suppressed_by_path: int
    stale: int | None  # None when the run was incomplete and staleness cannot be judged
    issues: tuple[ScanIssue, ...]
    stats: ScanStats
    complete: bool
    truncated: bool
    rules_sha256: str
    generated_at: str
    tool_version: str
    history_complete: bool | None = None  # git target only
