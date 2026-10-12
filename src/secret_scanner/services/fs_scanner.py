"""Directory scan: walker events + detection engine -> findings, issues and statistics.

This is where the walker's problems and the engine's flags become `ScanIssue`s, so that nothing
is dropped silently: every limit, every unreadable or changed file, every cut line, every
dropped match and the time budget makes the run incomplete (exit code 4), and the findings found
so far are still returned.

A secret exists here only inside the engine's `Match` objects, and only until `to_finding` turns
each into a `Finding` (a redacted form and a fingerprint). The `ScanResult` holds no secret.
"""

from __future__ import annotations

from dataclasses import dataclass, field, replace

from secret_scanner.core.clock import Clock
from secret_scanner.core.detect.engine import Engine
from secret_scanner.core.detect.entropy import EntropyConfig, path_excluded
from secret_scanner.core.findings import to_finding
from secret_scanner.core.globs import compile_globs
from secret_scanner.core.limits import DEFAULT_LIMITS, Limits
from secret_scanner.core.lines import TextKind
from secret_scanner.core.models import (
    Finding,
    IssueKind,
    Rule,
    ScanIssue,
    ScanStats,
)
from secret_scanner.core.sanitize import sanitize
from secret_scanner.fs import walk

_SHOWN_PATH_CHARS = 1_024


@dataclass(frozen=True, slots=True)
class ScanSettings:
    rules: tuple[Rule, ...]
    entropy: EntropyConfig = field(default_factory=EntropyConfig)
    limits: Limits = DEFAULT_LIMITS
    exclude_globs: tuple[str, ...] = ()
    default_excludes: bool = True


@dataclass(frozen=True, slots=True)
class ScanResult:
    """Everything a directory scan found. `findings` are sorted and not yet filtered by
    confidence or suppressed; `truncated` means the report limit cut them."""

    findings: tuple[Finding, ...]
    issues: tuple[ScanIssue, ...]
    stats: ScanStats
    truncated: bool

    @property
    def complete(self) -> bool:
        return not self.issues


def _sort_key(finding: Finding) -> tuple[str, int, int, str]:
    location = finding.location
    return (location.path_key, location.line, location.column, finding.rule_id)


def scan_tree(
    root: str,
    settings: ScanSettings,
    clock: Clock,
    reader: walk.Reader | None = None,
) -> ScanResult:
    """Scan the directory `root`. Raises `UsageError` for a root that is not a real directory;
    everything else is a recorded issue. `reader` is the file reader (tests inject one)."""
    walk.check_scan_root(root)
    limits = settings.limits
    engine = Engine(settings.rules, entropy=settings.entropy, limits=limits)
    options = walk.WalkOptions(
        limits=limits,
        excluded_directory_names=(
            walk.DEFAULT_EXCLUDED_DIRECTORIES if settings.default_excludes else frozenset()
        ),
        exclude_globs=compile_globs(settings.exclude_globs, limits, what="exclude"),
    )
    counters = walk.WalkCounters()
    events = (
        walk.walk_tree(root, options, counters)
        if reader is None
        else walk.walk_tree(root, options, counters, reader)
    )
    started = clock.monotonic()
    findings: list[Finding] = []
    issues: list[ScanIssue] = []
    stats = ScanStats()
    truncated = False
    for event in events:
        if clock.monotonic() - started > limits.max_run_seconds:
            issues.append(
                ScanIssue(
                    IssueKind.TIME_BUDGET,
                    None,
                    f"run budget of {limits.max_run_seconds} seconds exhausted; "
                    "the rest of the tree was not scanned",
                )
            )
            break
        if isinstance(event, walk.Problem):
            issues.append(ScanIssue(event.kind, event.path, event.detail))
            continue
        if isinstance(event, walk.Skipped):
            stats = _count_skip(stats, event.reason)
            continue
        display = sanitize(event.path_key, max_chars=_SHOWN_PATH_CHARS)
        result = engine.scan(event.data, use_entropy=not path_excluded(event.path_key))
        if result.kind is TextKind.BINARY:
            stats = replace(
                stats, files_seen=stats.files_seen + 1, skipped_binary=stats.skipped_binary + 1
            )
            continue
        if result.kind is TextKind.UNDECODABLE:
            stats = replace(stats, files_seen=stats.files_seen + 1)
            issues.append(
                ScanIssue(
                    IssueKind.UNDECODABLE,
                    display,
                    "UTF-16 or UTF-32 content with a byte-order mark could not be decoded",
                )
            )
            continue
        stats = replace(
            stats,
            files_seen=stats.files_seen + 1,
            files_scanned=stats.files_scanned + 1,
            bytes_scanned=stats.bytes_scanned + len(event.data),
        )
        if result.long_lines:
            issues.append(
                ScanIssue(
                    IssueKind.LINE_TOO_LONG,
                    display,
                    f"{len(result.long_lines)} line(s) longer than {limits.max_line_bytes} bytes "
                    f"were cut; the first is line {result.long_lines[0]}",
                )
            )
        if result.capped:
            issues.append(
                ScanIssue(
                    IssueKind.FINDINGS_CAP,
                    display,
                    f"more than {limits.max_findings_per_file} matches in one file; "
                    "the rest were dropped",
                )
            )
        for match in result.matches:
            if len(findings) >= limits.max_findings:
                truncated = True
                break
            findings.append(to_finding(match, path_key=event.path_key, path=display))
        if truncated:
            issues.append(
                ScanIssue(
                    IssueKind.FINDINGS_CAP,
                    None,
                    f"reached the report limit of {limits.max_findings} findings; "
                    "the scan was stopped",
                )
            )
            break
    findings.sort(key=_sort_key)
    return ScanResult(tuple(findings), tuple(issues), stats, truncated)


def _count_skip(stats: ScanStats, reason: walk.SkipReason) -> ScanStats:
    if reason is walk.SkipReason.SYMLINK:
        return replace(stats, skipped_symlink=stats.skipped_symlink + 1)
    if reason is walk.SkipReason.OFFLINE:
        return replace(stats, skipped_offline=stats.skipped_offline + 1)
    if reason is walk.SkipReason.SPECIAL:
        return replace(stats, skipped_special=stats.skipped_special + 1)
    return replace(stats, skipped_excluded=stats.skipped_excluded + 1)
