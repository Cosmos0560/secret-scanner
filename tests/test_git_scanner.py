"""The history scanner (`services/git_scanner.py`) against scripted git processes: every branch of
the walk, the blob cache and the limits, deterministic and without a repository."""

from __future__ import annotations

from collections.abc import Mapping
from pathlib import Path

import pytest

from secret_scanner.core.errors import GitError
from secret_scanner.core.fakes import build_fake, fake_entropy_token
from secret_scanner.core.limits import Limits
from secret_scanner.core.models import IssueKind
from secret_scanner.gitio.runner import GitRunner
from secret_scanner.services import git_scanner
from secret_scanner.services.fs_scanner import ScanResult, ScanSettings
from secret_scanner.services.git_scanner import HistorySpec, scan_history
from secret_scanner.services.loader import load_builtin_rules
from tests.helpers import FakeClock
from tests.test_git_runner import LF, FakeProcess, Recorder, TickClock, make_runner, oid

RULES = {rule.id: rule for rule in load_builtin_rules().rules}
NUL = b"\x00"
ZERO = "0" * 40
MARK = b"\x01"


def secret(rule_id: str = "npm-token", seed: str = "scanner") -> str:
    return build_fake(RULES[rule_id], seed)


def commit(number: int, parents: tuple[int, ...] = (), stamp: int = 1_767_225_600) -> bytes:
    parent_ids = " ".join(oid(p) for p in parents)
    return MARK + f"{oid(number)} {parent_ids} {stamp}".encode() + NUL


def change(path: str, blob: int, *, status: str = "A", mode: str = "100644") -> bytes:
    old = ZERO if status == "A" else oid(blob + 1000)
    record = f":{'000000' if status == 'A' else mode} {mode} {old} {oid(blob)} {status}"
    return LF + record.encode() + NUL + path.encode("utf-8", "surrogateescape") + NUL


class Repo:
    """A scripted repository: a history stream and the blobs `cat-file` knows."""

    def __init__(self, stream: bytes, blobs: Mapping[int, bytes]) -> None:
        self.stream = stream
        self.blobs = blobs  # a blob number that is not here is missing from the repository

    def processes(self) -> list[FakeProcess]:
        by_id = {oid(number): content for number, content in self.blobs.items()}

        def check(process: FakeProcess, data: bytes) -> None:
            for name in data.decode("ascii").split():
                if name in by_id:
                    process.stdout.feed(f"{name} blob {len(by_id[name])}".encode() + LF)
                else:
                    process.stdout.feed(f"{name} missing".encode() + LF)

        def batch(process: FakeProcess, data: bytes) -> None:
            name = data.decode("ascii").strip()
            content = by_id[name]
            process.stdout.feed(f"{name} blob {len(content)}".encode() + LF + content + LF)

        return [
            FakeProcess([self.stream]),
            FakeProcess(hang=True, on_stdin=check),
            FakeProcess(hang=True, on_stdin=batch),
        ]


def run(
    tmp_path: Path,
    repo: Repo,
    *,
    limits: Limits | None = None,
    scan_clock: FakeClock | None = None,
    spec: HistorySpec | None = None,
) -> ScanResult:
    recorder = Recorder(*repo.processes())
    active = limits or Limits()
    runner: GitRunner = make_runner(tmp_path, recorder, limits=active, deadline=1_000_000.0)
    settings = ScanSettings(rules=tuple(RULES.values()), limits=active)
    return scan_history(
        runner, "/g/.git", spec or HistorySpec(), settings, scan_clock or FakeClock()
    )


def text(content: str) -> bytes:
    return content.encode("utf-8")


# -- attribution ---------------------------------------------------------------------------------


def test_a_secret_is_attributed_to_the_commit_that_introduced_it(tmp_path: Path) -> None:
    stream = commit(1) + change("README", 11) + commit(2, (1,)) + change("conf.env", 12)
    repo = Repo(stream, {11: b"hello" + LF, 12: text(f"TOKEN={secret()}" + chr(10))})
    result = run(tmp_path, repo)
    assert len(result.findings) == 1
    finding = result.findings[0]
    assert finding.rule_id == "npm-token"
    assert finding.location.commit == oid(2)
    assert finding.location.path == "conf.env"
    assert finding.location.commit_time == 1_767_225_600
    assert result.complete
    assert (result.stats.commits, result.stats.blobs_scanned, result.stats.files_seen) == (2, 2, 2)


def test_a_secret_kept_through_many_commits_is_one_finding_at_the_first(tmp_path: Path) -> None:
    body = f"TOKEN={secret()}" + chr(10)
    stream = (
        commit(1)
        + change("a.env", 11)
        + commit(2, (1,))
        + change("a.env", 12, status="M")
        + commit(3, (2,))
        + change("a.env", 13, status="M")
    )
    repo = Repo(
        stream,
        {11: text(body), 12: text("# edit" + chr(10) + body), 13: text(body + "#" + chr(10))},
    )
    result = run(tmp_path, repo)
    assert [f.location.commit for f in result.findings] == [oid(1)]
    assert result.stats.blobs_scanned == 3


def test_the_same_blob_at_two_paths_is_scanned_once_and_reported_twice(tmp_path: Path) -> None:
    body = text(f"TOKEN={secret()}" + chr(10))
    stream = commit(1) + change("one.env", 11) + change("two/two.env", 11)
    result = run(tmp_path, Repo(stream, {11: body}))
    assert sorted(f.location.path for f in result.findings) == ["one.env", "two/two.env"]
    assert len({f.fingerprint for f in result.findings}) == 2
    assert result.stats.blobs_scanned == 1
    assert result.stats.blobs_from_cache == 1
    assert result.stats.files_seen == 1


def test_a_changed_secret_at_the_same_path_is_a_second_finding(tmp_path: Path) -> None:
    stream = commit(1) + change("a.env", 11) + commit(2, (1,)) + change("a.env", 12, status="M")
    repo = Repo(
        stream,
        {
            11: text(f"TOKEN={secret(seed='first')}" + chr(10)),
            12: text(f"TOKEN={secret(seed='second')}" + chr(10)),
        },
    )
    result = run(tmp_path, repo)
    assert sorted(f.location.commit for f in result.findings if f.location.commit) == [
        oid(1),
        oid(2),
    ]


def test_entries_are_taken_in_walk_order_across_a_flush_boundary(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(git_scanner, "FLUSH_ENTRIES", 2)
    body = text(f"TOKEN={secret()}" + chr(10))
    stream = b"".join(
        commit(number, (number - 1,) if number > 1 else ()) + change(f"f{number}.env", 11)
        for number in range(1, 6)
    )
    result = run(tmp_path, Repo(stream, {11: body}))
    first = {f.location.path: f.location.commit for f in result.findings}
    assert first == {f"f{n}.env": oid(n) for n in range(1, 6)}


def test_the_entropy_setting_of_the_path_is_part_of_the_cache_key(tmp_path: Path) -> None:
    token = fake_entropy_token("scanner")
    body = text(f"api_token = {token}" + chr(10))
    # `.lock` files are excluded from the entropy detector by default, `app.cfg` is not
    stream = commit(1) + change("poetry.lock", 11) + change("app.cfg", 11)
    result = run(tmp_path, Repo(stream, {11: body}))
    assert [f.location.path for f in result.findings] == ["app.cfg"]
    assert result.stats.blobs_scanned == 2  # once with entropy, once without


# -- what is skipped, and counted ----------------------------------------------------------------


def test_binary_blobs_are_counted_not_scanned(tmp_path: Path) -> None:
    stream = commit(1) + change("image.bin", 11) + change("again.bin", 11)
    result = run(tmp_path, Repo(stream, {11: b"\x00\x01" + secret().encode()}))
    assert result.findings == ()
    assert result.stats.skipped_binary == 1
    assert result.complete


def test_gitlinks_and_symlinks_are_counted_and_never_read(tmp_path: Path) -> None:
    stream = (
        commit(1)
        + change("sub", 11, mode="160000")
        + change("link", 12, mode="120000")
        + change("real.txt", 13)
    )
    result = run(tmp_path, Repo(stream, {13: b"nothing here" + LF}))
    assert (result.stats.skipped_submodule, result.stats.skipped_symlink) == (1, 1)
    assert result.stats.files_seen == 1
    assert result.complete


def test_an_unexpected_file_mode_fails_closed(tmp_path: Path) -> None:
    stream = commit(1) + change("dir", 11, mode="040000")
    with pytest.raises(GitError, match="file mode"):
        run(tmp_path, Repo(stream, {11: b""}))


def test_an_oversized_blob_is_skipped_and_the_run_is_incomplete(tmp_path: Path) -> None:
    stream = commit(1) + change("big.txt", 11) + change("ok.env", 12)
    repo = Repo(stream, {11: b"x" * 5000, 12: text(f"TOKEN={secret()}" + chr(10))})
    result = run(tmp_path, repo, limits=Limits(max_file_bytes=1000))
    assert [issue.kind for issue in result.issues] == [IssueKind.TOO_LARGE]
    assert result.issues[0].path == "big.txt"
    assert [f.location.path for f in result.findings] == ["ok.env"]
    assert not result.complete


def test_an_oversized_blob_is_reported_once_however_often_it_appears(tmp_path: Path) -> None:
    stream = commit(1) + change("a.txt", 11) + change("b.txt", 11)
    result = run(tmp_path, Repo(stream, {11: b"x" * 5000}), limits=Limits(max_file_bytes=1000))
    assert len(result.issues) == 1


def test_a_missing_blob_is_an_issue_not_a_crash(tmp_path: Path) -> None:
    stream = commit(1) + change("a.txt", 99) + change("b.txt", 12)
    repo = Repo(stream, {12: b"fine" + LF})  # blob 99 is not in the repository
    result = run(tmp_path, repo)
    assert [issue.kind for issue in result.issues] == [IssueKind.MISSING_OBJECT]
    assert result.issues[0].path == "a.txt"
    assert not result.complete
    assert result.stats.blobs_scanned == 1


def test_an_undecodable_wide_text_blob_is_an_issue(tmp_path: Path) -> None:
    broken = b"\xff\xfe" + b"\x00\xd8"  # UTF-16 LE byte-order mark, then a lone surrogate
    result = run(tmp_path, Repo(commit(1) + change("w.txt", 11), {11: broken}))
    assert [issue.kind for issue in result.issues] == [IssueKind.UNDECODABLE]


def test_a_path_over_the_limit_is_an_issue_and_is_never_read(tmp_path: Path) -> None:
    long_name = "d/" * 20 + "f.txt"
    stream = commit(1) + change(long_name, 11)
    result = run(tmp_path, Repo(stream, {11: b"x"}), limits=Limits(max_path_chars=10))
    assert [issue.kind for issue in result.issues] == [IssueKind.LIMIT_REACHED]
    assert result.stats.files_seen == 0


def test_long_lines_and_per_blob_caps_become_issues(tmp_path: Path) -> None:
    long_line = b"a" * 5000 + LF
    many = b"".join(f"TOKEN={secret(seed=str(n))}".encode() + LF for n in range(6))
    stream = commit(1) + change("long.txt", 11) + change("many.env", 12)
    limits = Limits(max_line_bytes=1000, max_findings_per_file=3)
    result = run(tmp_path, Repo(stream, {11: long_line, 12: many}), limits=limits)
    kinds = sorted(issue.kind.value for issue in result.issues)
    assert kinds == ["findings_cap", "line_too_long"]
    assert len(result.findings) == 3


# -- limits --------------------------------------------------------------------------------------


def test_the_commit_limit_stops_the_walk_and_keeps_what_was_found(tmp_path: Path) -> None:
    body = text(f"TOKEN={secret()}" + chr(10))
    stream = (
        commit(1) + change("a.env", 11) + commit(2, (1,)) + commit(3, (2,)) + change("late", 12)
    )
    result = run(tmp_path, Repo(stream, {11: body, 12: body}), limits=Limits(max_git_commits=2))
    assert [f.location.path for f in result.findings] == ["a.env"]
    assert [issue.kind for issue in result.issues] == [IssueKind.LIMIT_REACHED]
    assert not result.complete


def test_the_blob_limit_stops_the_scan(tmp_path: Path) -> None:
    stream = commit(1) + change("a", 11) + change("b", 12) + change("c", 13)
    repo = Repo(stream, {11: b"a", 12: b"b", 13: b"c"})
    result = run(tmp_path, repo, limits=Limits(max_git_blobs=2))
    assert result.stats.files_seen == 2
    assert [issue.kind for issue in result.issues] == [IssueKind.LIMIT_REACHED]


def test_the_total_bytes_limit_stops_the_scan(tmp_path: Path) -> None:
    stream = commit(1) + change("a", 11) + change("b", 12)
    repo = Repo(stream, {11: b"a" * 600, 12: b"b" * 600})
    result = run(tmp_path, repo, limits=Limits(max_total_bytes=1000))
    assert result.stats.blobs_scanned == 1
    assert [issue.kind for issue in result.issues] == [IssueKind.LIMIT_REACHED]


def test_the_findings_cap_marks_the_report_truncated(tmp_path: Path) -> None:
    files = {n: text(f"TOKEN={secret(seed=str(n))}" + chr(10)) for n in range(11, 16)}
    stream = commit(1) + b"".join(change(f"f{n}.env", n) for n in files)
    result = run(tmp_path, Repo(stream, files), limits=Limits(max_findings=2))
    assert result.truncated
    assert len(result.findings) == 2
    assert [issue.kind for issue in result.issues] == [IssueKind.FINDINGS_CAP]


class JumpingClock(FakeClock):
    """Ten seconds pass at every reading."""

    def monotonic(self) -> float:
        self.advance(10.0)
        return super().monotonic()


def test_the_run_budget_ends_the_walk_with_a_time_issue(tmp_path: Path) -> None:
    stream = commit(1) + change("a", 11)
    result = run(
        tmp_path,
        Repo(stream, {11: b"a"}),
        limits=Limits(max_run_seconds=5),
        scan_clock=JumpingClock(),
    )
    assert [issue.kind for issue in result.issues] == [IssueKind.TIME_BUDGET]
    assert not result.complete


def test_a_git_deadline_during_the_walk_is_an_incomplete_run_not_a_failure(tmp_path: Path) -> None:
    hang = Recorder(FakeProcess(hang=True))
    runner = make_runner(tmp_path, hang, clock=TickClock(step=100.0), deadline=1250.0)
    settings = ScanSettings(rules=tuple(RULES.values()))
    outcome = scan_history(runner, "/g/.git", HistorySpec(), settings, FakeClock())
    assert [issue.kind for issue in outcome.issues] == [IssueKind.TIME_BUDGET]
    assert outcome.findings == ()


def test_an_exhausted_output_cap_is_a_limit_issue(tmp_path: Path) -> None:
    recorder = Recorder(FakeProcess([b"x" * 4000], hang=True))
    runner = make_runner(tmp_path, recorder, limits=Limits(max_git_output_bytes=1000))
    settings = ScanSettings(rules=tuple(RULES.values()), limits=Limits(max_git_output_bytes=1000))
    result = scan_history(runner, "/g/.git", HistorySpec(), settings, FakeClock())
    assert [issue.kind for issue in result.issues] == [IssueKind.LIMIT_REACHED]


# -- failures of git ---------------------------------------------------------------------------


def test_a_truncated_stream_fails_closed(tmp_path: Path) -> None:
    stream = commit(1) + change("a", 11)
    with pytest.raises(GitError, match="ended inside a record"):
        run(tmp_path, Repo(stream[:-1], {11: b"a"}))


def test_garbage_in_the_stream_fails_closed(tmp_path: Path) -> None:
    with pytest.raises(GitError, match="unexpected git output"):
        run(tmp_path, Repo(b"fatal: something" + NUL, {}))


def test_git_failing_after_output_is_a_git_error(tmp_path: Path) -> None:
    processes = [FakeProcess([commit(1)], [b"fatal: bad tree" + LF], returncode=128)]
    runner = make_runner(tmp_path, Recorder(*processes))
    settings = ScanSettings(rules=tuple(RULES.values()))
    with pytest.raises(GitError, match="bad tree"):
        scan_history(runner, "/g/.git", HistorySpec(), settings, FakeClock())


def test_the_history_spec_lists_includes_then_excludes() -> None:
    spec = HistorySpec(include=(oid(2),), exclude=(oid(1),), all_refs=False)
    assert spec.revisions() == [oid(2), f"^{oid(1)}"]
    assert HistorySpec().revisions() == []
