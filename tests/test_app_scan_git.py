"""The `scan-git` and `scan --gitignore` use cases with scripted git processes: the order of the
refusals, the version and ownership checks, shallow handling and the exit codes, without a real
repository or a real git."""

from __future__ import annotations

import os
from collections.abc import Callable
from dataclasses import replace
from pathlib import Path
from typing import Any, cast

import pytest

from secret_scanner.app.common import ScanOutcome
from secret_scanner.app.scan import ScanRequest, run_scan
from secret_scanner.app.scan_git import GitScanRequest, run_scan_git
from secret_scanner.cli import main as cli_main
from secret_scanner.core.errors import ExitCode, GitError, IncompleteRunError, UsageError
from secret_scanner.core.fakes import build_fake
from secret_scanner.core.models import IssueKind, Target
from secret_scanner.gitio.runner import Spawn
from secret_scanner.services.loader import load_builtin_rules
from tests.helpers import FakeClock
from tests.test_git_fs import standard_repository
from tests.test_git_runner import LF, FakeProcess, Recorder, TickClock, oid

RULES = {rule.id: rule for rule in load_builtin_rules().rules}
NUL = b"\x00"
MARK = b"\x01"
ZERO = "0" * 40
OLD_GIT = b"git version 2.20.1" + LF
GOOD_GIT = b"git version 2.54.0.windows.1" + LF


def program(tmp_path: Path) -> str:
    """A regular executable file standing in for git (it is never run: processes are scripted)."""
    path = tmp_path / "fakebin" / ("git.exe" if os.name == "nt" else "git")
    path.parent.mkdir(exist_ok=True)
    path.write_bytes(b"not git")
    path.chmod(0o755)
    return str(path)


def repository(tmp_path: Path) -> tuple[Path, str]:
    root = tmp_path / "repo"
    git_dir = standard_repository(root)
    return root, str(git_dir)


def history(secret: str) -> bytes:
    header = MARK + f"{oid(1)}  1767225600".encode() + NUL
    record = f":000000 100644 {ZERO} {oid(11)} A".encode()
    return header + LF + record + NUL + b"conf.env" + NUL


def cat_file_processes(content: bytes) -> list[FakeProcess]:
    def check(process: FakeProcess, data: bytes) -> None:
        process.stdout.feed(f"{oid(11)} blob {len(content)}".encode() + LF)

    def batch(process: FakeProcess, data: bytes) -> None:
        process.stdout.feed(f"{oid(11)} blob {len(content)}".encode() + LF + content + LF)

    return [FakeProcess(hang=True, on_stdin=check), FakeProcess(hang=True, on_stdin=batch)]


def scripted(
    git_dir: str,
    *,
    version: bytes = GOOD_GIT,
    shallow: bool = False,
    log: bytes = b"",
    blob: bytes = b"",
    extra: tuple[FakeProcess, ...] = (),
) -> Recorder:
    processes = [
        FakeProcess([version]),
        FakeProcess([git_dir.encode() + LF]),
        FakeProcess([b"true" + LF if shallow else b"false" + LF]),
        *extra,
        FakeProcess([log]),
        *cat_file_processes(blob),
    ]
    return Recorder(*processes)


def request(tmp_path: Path, root: Path, **options: Any) -> GitScanRequest:
    return replace(GitScanRequest(path=str(root), git=program(tmp_path)), **options)


def run(tmp_path: Path, root: Path, recorder: Recorder, **options: Any) -> ScanOutcome:
    return run_scan_git(
        request(tmp_path, root, **options), FakeClock(), spawn=cast(Spawn, recorder)
    )


def test_a_complete_history_scan(tmp_path: Path) -> None:
    root, git_dir = repository(tmp_path)
    secret = build_fake(RULES["npm-token"], "app")
    content = f"TOKEN={secret}".encode() + LF
    recorder = scripted(git_dir, log=history(secret), blob=content)
    outcome = run(tmp_path, root, recorder)
    assert outcome.exit_code == ExitCode.FINDINGS
    report = outcome.report
    assert report.target is Target.GIT
    assert report.history_complete is True
    assert [f.location.commit for f in report.findings] == [oid(1)]
    # the calls, in order: version, discovery, shallow check, history walk, sizes, contents
    assert len(recorder.calls) == 6
    assert recorder.calls[0][0][-1] == "version"
    assert "--absolute-git-dir" in recorder.calls[1][0]
    assert recorder.calls[1][2] == str(root)
    assert recorder.calls[1][1]["GIT_CEILING_DIRECTORIES"] == str(root.parent)
    assert "--is-shallow-repository" in recorder.calls[2][0]
    assert "log" in recorder.calls[3][0]
    assert "--all" in recorder.calls[3][0]


def test_discovery_runs_before_any_object_is_read(tmp_path: Path) -> None:
    root, git_dir = repository(tmp_path)
    recorder = scripted(git_dir, log=b"")
    run(tmp_path, root, recorder)
    commands = [
        next(a for a in argv if a in {"version", "rev-parse", "log", "cat-file"})
        for argv, _, _ in recorder.calls
    ]
    assert commands[:3] == ["version", "rev-parse", "rev-parse"]
    assert commands[3] == "log"


def test_a_git_older_than_the_minimum_is_exit_code_three(tmp_path: Path) -> None:
    root, git_dir = repository(tmp_path)
    recorder = scripted(git_dir, version=OLD_GIT)
    with pytest.raises(GitError, match=r"2\.20\.1.*2\.32\.0") as caught:
        run(tmp_path, root, recorder)
    assert caught.value.exit_code == ExitCode.GIT
    assert len(recorder.calls) == 1  # nothing else was run


def test_a_git_directory_that_is_not_the_repositorys_own_is_refused(tmp_path: Path) -> None:
    root, _ = repository(tmp_path)
    elsewhere = tmp_path / "elsewhere" / ".git"
    elsewhere.mkdir(parents=True)
    recorder = scripted(str(elsewhere))
    with pytest.raises(GitError, match=r"not the \.git inside"):
        run(tmp_path, root, recorder)
    assert len(recorder.calls) == 2  # version and discovery only


def test_a_shallow_repository_is_incomplete_unless_allowed(tmp_path: Path) -> None:
    root, git_dir = repository(tmp_path)
    outcome = run(tmp_path, root, scripted(git_dir, shallow=True, log=b""))
    assert outcome.exit_code == ExitCode.INCOMPLETE
    issues = outcome.report.issues
    assert [issue.kind for issue in issues] == [IssueKind.SHALLOW_HISTORY]
    assert outcome.report.history_complete is False
    allowed = run(tmp_path, root, scripted(git_dir, shallow=True, log=b""), allow_shallow=True)
    assert allowed.exit_code == ExitCode.OK
    assert allowed.report.history_complete is False
    assert any("shallow" in notice for notice in allowed.notices)


def test_a_range_resolves_both_sides_and_excludes_the_older(tmp_path: Path) -> None:
    root, git_dir = repository(tmp_path)
    resolved = (FakeProcess([oid(7).encode() + LF]), FakeProcess([oid(8).encode() + LF]))
    recorder = scripted(git_dir, extra=resolved, log=b"")
    run(tmp_path, root, recorder, revision_range="v1..main")
    assert recorder.calls[3][0][-3:] == ["--verify", "--end-of-options", "main^{commit}"]
    assert recorder.calls[4][0][-3:] == ["--verify", "--end-of-options", "v1^{commit}"]
    log = recorder.calls[5][0]
    assert "--all" not in log
    assert log[log.index("--end-of-options") + 1 :] == [oid(7), f"^{oid(8)}", "--"]


def test_a_single_revision_walks_only_that_history(tmp_path: Path) -> None:
    root, git_dir = repository(tmp_path)
    recorder = scripted(git_dir, extra=(FakeProcess([oid(7).encode() + LF]),), log=b"")
    run(tmp_path, root, recorder, revision="feature/x")
    log = recorder.calls[4][0]
    assert "--all" not in log
    assert log[log.index("--end-of-options") + 1 :] == [oid(7), "--"]


def test_bad_revisions_are_refused_before_anything_is_looked_at(tmp_path: Path) -> None:
    root, _ = repository(tmp_path)
    recorder = Recorder()
    for options in (
        {"revision": "--output=x"},
        {"revision_range": "a:b..c"},
        {"revision_range": "justone"},
        {"revision": "a", "revision_range": "a..b"},
    ):
        with pytest.raises(UsageError):
            run(tmp_path, root, recorder, **options)
    assert recorder.calls == []


def test_a_git_deadline_before_anything_was_scanned_is_exit_code_four(tmp_path: Path) -> None:
    root, _ = repository(tmp_path)
    recorder = Recorder(FakeProcess(hang=True))
    with pytest.raises(IncompleteRunError) as caught:
        run_scan_git(
            request(tmp_path, root),
            TickClock(step=500.0),
            spawn=cast(Spawn, recorder),
        )
    assert caught.value.exit_code == ExitCode.INCOMPLETE


def test_git_not_on_path_is_exit_code_three(tmp_path: Path) -> None:
    root, _ = repository(tmp_path)
    with pytest.raises(GitError, match="not found"):
        run_scan_git(
            GitScanRequest(path=str(root)), FakeClock(), environment={"PATH": str(tmp_path)}
        )


def test_the_repository_layout_is_checked_before_git_is_found(tmp_path: Path) -> None:
    plain = tmp_path / "plain"
    plain.mkdir()
    # no git on the path at all: the refusal is about the directory, not about git
    with pytest.raises(GitError, match="not a git repository"):
        run_scan_git(GitScanRequest(path=str(plain)), FakeClock(), environment={"PATH": ""})


# -- the command line -------------------------------------------------------------------------


Cli = Callable[..., tuple[int, str, str]]


@pytest.fixture
def cli(capsys: pytest.CaptureFixture[str]) -> Cli:
    def invoke(*argv: str) -> tuple[int, str, str]:
        code = cli_main.main(list(argv))
        captured = capsys.readouterr()
        return code, captured.out, captured.err

    return invoke


def test_rev_and_range_cannot_be_combined(tmp_path: Path, cli: Cli) -> None:
    code, out, err = cli("scan-git", str(tmp_path), "--rev", "a", "--range", "a..b")
    assert (code, out) == (ExitCode.USAGE, "")
    assert "not allowed with" in err


def test_a_directory_that_is_not_a_repository_is_exit_code_three(tmp_path: Path, cli: Cli) -> None:
    code, out, err = cli("scan-git", str(tmp_path))
    assert (code, out) == (ExitCode.GIT, "")
    assert "not a git repository" in err


def test_a_missing_directory_is_a_usage_error(tmp_path: Path, cli: Cli) -> None:
    code, _, err = cli("scan-git", str(tmp_path / "nowhere"))
    assert code == ExitCode.USAGE
    assert "does not exist" in err


def test_bad_revision_text_is_exit_code_two_and_is_escaped(tmp_path: Path, cli: Cli) -> None:
    code, _, err = cli("scan-git", str(tmp_path), "--rev", "x" + chr(0x1B) + "[31m")
    assert code == ExitCode.USAGE
    assert chr(0x1B) not in err
    assert "revision refused" in err


def test_the_help_lists_the_history_options(capsys: pytest.CaptureFixture[str]) -> None:
    assert cli_main.main(["scan-git", "--help"]) == 0
    text = capsys.readouterr().out
    for option in ("--rev", "--range", "--allow-shallow", "--allow-other-owner", "--git"):
        assert option in text


# -- scan --gitignore ---------------------------------------------------------------------------


def test_gitignore_lists_through_the_runner_and_filters_the_walker(tmp_path: Path) -> None:
    root = tmp_path / "tree"
    root.mkdir()
    secret = build_fake(RULES["npm-token"], "g")
    (root / "kept.env").write_text(f"TOKEN={secret}" + chr(10), encoding="utf-8")
    (root / "ignored.env").write_text(f"TOKEN={secret}" + chr(10), encoding="utf-8")
    recorder = Recorder(FakeProcess([GOOD_GIT]), FakeProcess([b"kept.env" + NUL]))
    outcome = run_scan(
        ScanRequest(path=str(root), gitignore=True, git=program(tmp_path)),
        FakeClock(),
        spawn=cast(Spawn, recorder),
    )
    assert [f.location.path for f in outcome.report.findings] == ["kept.env"]
    assert outcome.report.stats.skipped_gitignored == 1
    argv, environment, cwd = recorder.calls[1]
    assert argv[-5:] == ["ls-files", "-z", "--cached", "--others", "--exclude-standard"]
    assert cwd == str(root)
    assert "GIT_CEILING_DIRECTORIES" not in environment


def test_gitignore_with_an_old_git_is_exit_code_three(tmp_path: Path) -> None:
    root = tmp_path / "tree"
    root.mkdir()
    recorder = Recorder(FakeProcess([OLD_GIT]))
    with pytest.raises(GitError, match="older than"):
        run_scan(
            ScanRequest(path=str(root), gitignore=True, git=program(tmp_path)),
            FakeClock(),
            spawn=cast(Spawn, recorder),
        )


def test_plain_scan_never_starts_git(tmp_path: Path) -> None:
    root = tmp_path / "tree"
    root.mkdir()
    recorder = Recorder()
    outcome = run_scan(ScanRequest(path=str(root)), FakeClock(), spawn=cast(Spawn, recorder))
    assert outcome.exit_code == ExitCode.OK
    assert recorder.calls == []
