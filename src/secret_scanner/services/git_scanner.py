"""History scan: git's `log --raw` stream + blob contents + detection engine -> findings.

For every commit (oldest first) the paths it adds or modifies against its first parent are read
from the stream (`core/gitparse.py`); every distinct blob is sized with `cat-file --batch-check`
and, when small enough, read with `cat-file --batch` and scanned once. A finding names the first
commit in the walk that introduced that (rule, path, secret) (PLAN.md D2, D8), so a secret kept
for 500 commits is one finding, and a secret added and removed later is still found.

Commit messages, author identities and tag messages are never read (D2): nothing from them can
reach an output. Paths are hostile and are escaped by the sanitiser before they leave this module.

A secret exists here only inside `Match` objects, and only until `to_finding` makes a `Finding`.
The blob cache keeps the matches of blobs that have any (bounded), so a blob seen again at another
path costs nothing but a new fingerprint.
"""

from __future__ import annotations

from collections.abc import Sequence
from dataclasses import dataclass, field, replace
from typing import NoReturn, cast

from secret_scanner.core.clock import Clock
from secret_scanner.core.detect.engine import Engine
from secret_scanner.core.detect.entropy import path_excluded
from secret_scanner.core.detect.match import Match
from secret_scanner.core.findings import finding_sort_key, to_finding
from secret_scanner.core.gitparse import (
    GITLINK_MODE,
    SYMLINK_MODE,
    CommitHeader,
    DiffEntry,
    GitOutputError,
    LogParser,
    ObjectInfo,
)
from secret_scanner.core.lines import TextKind
from secret_scanner.core.models import Finding, IssueKind, ScanIssue, ScanStats
from secret_scanner.core.sanitize import sanitize_path
from secret_scanner.gitio.runner import GitLimitError, GitRunner, ObjectReader
from secret_scanner.services.fs_scanner import ScanResult, ScanSettings

_SHOWN_PATH_CHARS = 1_024
FLUSH_ENTRIES = 512  # entries gathered before their blobs are sized and read, in walk order
_BLOB_MODE_PREFIX = "100"


@dataclass(frozen=True, slots=True)
class HistorySpec:
    """What to walk: `include` (commit ids to start from; none with `all_refs`) and `exclude`
    (commit ids whose history is left out, for `--range`)."""

    include: tuple[str, ...] = ()
    exclude: tuple[str, ...] = ()
    all_refs: bool = True

    def revisions(self) -> list[str]:
        return [*self.include, *(f"^{commit}" for commit in self.exclude)]


class _LimitStopError(Exception):
    """The scan ended early on one of its own limits; the issue was recorded first."""


@dataclass(slots=True)
class _State:
    stats: ScanStats = field(default_factory=ScanStats)
    issues: list[ScanIssue] = field(default_factory=list)
    findings: list[Finding] = field(default_factory=list)
    fingerprints: set[str] = field(default_factory=set)
    seen_blobs: set[str] = field(default_factory=set)  # distinct blob ids examined
    skipped_blobs: set[str] = field(default_factory=set)  # binary, oversized, missing, undecodable
    scanned: set[tuple[str, bool]] = field(default_factory=set)  # (blob id, entropy used)
    cache: dict[tuple[str, bool], tuple[Match, ...]] = field(default_factory=dict)
    truncated: bool = False


class _HistoryScan:
    def __init__(
        self,
        objects: ObjectReader,
        engine: Engine,
        settings: ScanSettings,
        clock: Clock,
    ) -> None:
        self._objects = objects
        self._engine = engine
        self._limits = settings.limits
        self._clock = clock
        self._started = clock.monotonic()
        self.state = _State()

    # -- bookkeeping ------------------------------------------------------------------------

    def add_issue(self, kind: IssueKind, detail: str, path: str | None = None) -> None:
        self.state.issues.append(ScanIssue(kind, path, detail))

    def stop(self, kind: IssueKind, detail: str, path: str | None = None) -> NoReturn:
        self.add_issue(kind, detail, path)
        raise _LimitStopError

    def check_time(self) -> None:
        if self._clock.monotonic() - self._started > self._limits.max_run_seconds:
            self.stop(
                IssueKind.TIME_BUDGET,
                f"run budget of {self._limits.max_run_seconds} seconds exhausted; "
                "the rest of the history was not scanned",
            )

    def count_commit(self) -> bool:
        """Count one commit; False (with the issue recorded) when it is over the limit."""
        stats = self.state.stats
        self.state.stats = replace(stats, commits=stats.commits + 1)
        if self.state.stats.commits > self._limits.max_git_commits:
            self.add_issue(
                IssueKind.LIMIT_REACHED,
                f"more than {self._limits.max_git_commits} commits; the rest were not scanned",
            )
            return False
        return True

    # -- entries ----------------------------------------------------------------------------

    def flush(self, pending: Sequence[tuple[CommitHeader, DiffEntry]]) -> None:
        """Size the blobs of the gathered entries in one round trip, then take the entries in walk
        order, so the first commit that introduces something is the one that is named."""
        if not pending:
            return
        wanted: dict[str, None] = {}
        for _, entry in pending:
            known = entry.new_oid in self.state.seen_blobs
            if entry.new_mode.startswith(_BLOB_MODE_PREFIX) and not known:
                wanted[entry.new_oid] = None
        sizes = {info.oid: info for info in self._objects.sizes(list(wanted))}
        for commit, entry in pending:
            self.check_time()
            self._entry(commit, entry, sizes)

    def _entry(self, commit: CommitHeader, entry: DiffEntry, sizes: dict[str, ObjectInfo]) -> None:
        state = self.state
        mode = entry.new_mode
        if mode == GITLINK_MODE:
            state.stats = replace(state.stats, skipped_submodule=state.stats.skipped_submodule + 1)
            return
        if mode == SYMLINK_MODE:
            state.stats = replace(state.stats, skipped_symlink=state.stats.skipped_symlink + 1)
            return
        if not mode.startswith(_BLOB_MODE_PREFIX):
            raise GitOutputError("unexpected git output: a file mode that is not a file or a link")
        path_key = entry.path.decode("utf-8", errors="surrogateescape")
        display = sanitize_path(path_key, windows=False, max_chars=_SHOWN_PATH_CHARS)
        if len(path_key) > self._limits.max_path_chars:
            self.add_issue(
                IssueKind.LIMIT_REACHED,
                f"path longer than {self._limits.max_path_chars} characters; skipped",
                display,
            )
            return
        oid = entry.new_oid
        use_entropy = not path_excluded(path_key)
        key = (oid, use_entropy)
        if key in state.scanned:
            state.stats = replace(state.stats, blobs_from_cache=state.stats.blobs_from_cache + 1)
            self._emit(state.cache.get(key, ()), commit, path_key, display)
            return
        if oid in state.skipped_blobs:
            return
        if oid not in state.seen_blobs:
            if len(state.seen_blobs) >= self._limits.max_git_blobs:
                self.stop(
                    IssueKind.LIMIT_REACHED,
                    f"more than {self._limits.max_git_blobs} distinct blobs; the rest were not "
                    "scanned",
                )
            state.seen_blobs.add(oid)
            state.stats = replace(state.stats, files_seen=state.stats.files_seen + 1)
        info = sizes.get(oid)
        if info is None:  # seen before, but only with the other entropy setting: read it again
            info = self._objects.sizes([oid])[0]
        self._scan_blob(commit, info, key, path_key, display)

    def _scan_blob(
        self,
        commit: CommitHeader,
        info: ObjectInfo,
        key: tuple[str, bool],
        path_key: str,
        display: str,
    ) -> None:
        state = self.state
        limits = self._limits
        oid, use_entropy = key
        if info.kind == "missing" or info.size is None:
            state.skipped_blobs.add(oid)
            self.add_issue(
                IssueKind.MISSING_OBJECT,
                "blob is not in the repository (partial clone or damaged object store)",
                display,
            )
            return
        if info.kind != "blob":
            raise GitOutputError("unexpected git output: a changed file that is not a blob")
        if info.size > limits.max_blob_bytes:
            state.skipped_blobs.add(oid)
            self.add_issue(
                IssueKind.TOO_LARGE,
                f"larger than the limit of {limits.max_blob_bytes} bytes",
                display,
            )
            return
        if state.stats.bytes_scanned + info.size > limits.max_total_bytes:
            self.stop(
                IssueKind.LIMIT_REACHED,
                f"more than {limits.max_total_bytes} bytes read; the rest were not scanned",
            )
        data = self._objects.read_blob(oid, info.size)
        result = self._engine.scan(data, use_entropy=use_entropy)
        if result.kind is TextKind.BINARY:
            state.skipped_blobs.add(oid)
            state.stats = replace(state.stats, skipped_binary=state.stats.skipped_binary + 1)
            return
        if result.kind is TextKind.UNDECODABLE:
            state.skipped_blobs.add(oid)
            self.add_issue(
                IssueKind.UNDECODABLE,
                "UTF-16 or UTF-32 content with a byte-order mark could not be decoded",
                display,
            )
            return
        stats = state.stats
        state.stats = replace(
            stats,
            files_scanned=stats.files_scanned + 1,
            blobs_scanned=stats.blobs_scanned + 1,
            bytes_scanned=stats.bytes_scanned + len(data),
        )
        if result.long_lines:
            self.add_issue(
                IssueKind.LINE_TOO_LONG,
                f"{len(result.long_lines)} line(s) longer than {limits.max_line_bytes} bytes "
                f"were cut; the first is line {result.long_lines[0]}",
                display,
            )
        if result.capped:
            self.add_issue(
                IssueKind.FINDINGS_CAP,
                f"more than {limits.max_findings_per_file} matches in one blob; the rest were "
                "dropped",
                display,
            )
        state.scanned.add(key)
        if result.matches and len(state.cache) < limits.max_findings:
            state.cache[key] = result.matches
        self._emit(result.matches, commit, path_key, display)

    def _emit(
        self, matches: Sequence[Match], commit: CommitHeader, path_key: str, display: str
    ) -> None:
        state = self.state
        for match in matches:
            finding = to_finding(
                match,
                path_key=path_key,
                path=display,
                commit=commit.oid,
                commit_time=commit.time,
            )
            if finding.fingerprint in state.fingerprints:
                continue  # the same secret at the same path: reported at its first commit
            if len(state.findings) >= self._limits.max_findings:
                state.truncated = True
                self.stop(
                    IssueKind.FINDINGS_CAP,
                    f"reached the report limit of {self._limits.max_findings} findings; "
                    "the scan was stopped",
                )
            state.fingerprints.add(finding.fingerprint)
            state.findings.append(finding)


def scan_history(
    runner: GitRunner,
    git_dir: str,
    spec: HistorySpec,
    settings: ScanSettings,
    clock: Clock,
) -> ScanResult:
    """Scan every blob added or modified anywhere in the walked history. Raises `GitError`
    subclasses when git fails or prints something unexpected (exit code 3); every limit is a
    recorded issue with the findings found so far (exit code 4)."""
    limits = settings.limits
    engine = Engine(settings.rules, entropy=settings.entropy, limits=limits)
    objects = runner.open_objects(git_dir)
    scan = _HistoryScan(objects, engine, settings, clock)
    parser = LogParser()
    stream = runner.stream_history(git_dir, spec.revisions(), all_refs=spec.all_refs)
    pending: list[tuple[CommitHeader, DiffEntry]] = []
    commit: CommitHeader | None = None
    try:
        walking = True
        for chunk in stream:
            for token in parser.feed(chunk):
                if isinstance(token, CommitHeader):
                    commit = token
                    if not scan.count_commit():
                        walking = False
                        break
                else:  # the parser only yields a change after the header of its commit
                    pending.append((cast(CommitHeader, commit), token))
                    if len(pending) >= FLUSH_ENTRIES:
                        scan.flush(pending)
                        pending.clear()
            if not walking:
                break
            scan.check_time()
        if walking:
            parser.finish()
        scan.flush(pending)  # the entries of the commits walked so far are still scanned
    except GitLimitError as error:
        kind = IssueKind.TIME_BUDGET if error.time_budget else IssueKind.LIMIT_REACHED
        scan.add_issue(kind, str(error))
    except _LimitStopError:
        pass
    finally:
        stream.close()
        objects.close()
    state = scan.state
    findings = sorted(state.findings, key=finding_sort_key)
    return ScanResult(tuple(findings), tuple(state.issues), state.stats, state.truncated)
