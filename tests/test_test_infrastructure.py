"""The test infrastructure itself: leak checking, the socket blocker, environment isolation,
named skip markers, and the throw-away git repositories of PLAN.md D17."""

from __future__ import annotations

import os
import socket
import subprocess
from collections.abc import Callable
from pathlib import Path

import pytest

from tests import conftest
from tests.conftest import NetworkBlockedError
from tests.gitrepo import GitRepo, git_environment, identity_email, run_git

# -- assert_not_leaked ----------------------------------------------------------------------

FAKE = "Zq8rT1vXw9LmN3bYc5HdKe7PfUa2GsJo"  # neutral, not shaped like any real token


def test_clean_output_passes(assert_not_leaked: Callable[..., None]) -> None:
    assert_not_leaked("nothing to see: [20 chars, sha256:1a2b3c4d]", FAKE)


def test_full_secret_is_detected() -> None:
    assert conftest.leak_check("value=" + FAKE + "!", FAKE) is not None


def test_a_long_run_of_the_secret_is_detected_beyond_the_allowance() -> None:
    assert conftest.leak_check(FAKE[:4] + "...", FAKE, allowed_shown=4) is None
    assert conftest.leak_check(FAKE[:12] + "...", FAKE, allowed_shown=4) is not None
    assert conftest.leak_check(FAKE[:12] + "...", FAKE, allowed_shown=11) is not None


def test_short_coincidental_runs_are_not_reported() -> None:
    assert conftest.leak_check("Zq8 appears here", FAKE) is None


def test_bytes_and_text_are_both_checked() -> None:
    assert conftest.leak_check(FAKE.encode(), FAKE) is not None
    assert conftest.leak_check(FAKE, FAKE.encode()) is not None
    assert conftest.leak_check("", b"") is None


def test_failure_message_never_contains_the_secret() -> None:
    message = conftest.leak_check("x" + FAKE, FAKE)
    assert message is not None
    assert FAKE not in message
    assert FAKE[:8] not in message
    assert "sha256:" in message


def test_fixture_fails_with_the_redacted_form_only(
    assert_not_leaked: Callable[..., None],
) -> None:
    with pytest.raises(pytest.fail.Exception) as raised:
        assert_not_leaked("log: " + FAKE, FAKE)
    assert FAKE not in str(raised.value)


# -- socket blocker and environment isolation -----------------------------------------------


def test_socket_calls_fail_during_tests() -> None:
    with pytest.raises(NetworkBlockedError):
        socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    with pytest.raises(NetworkBlockedError):
        socket.create_connection(("127.0.0.1", 9))
    with pytest.raises(NetworkBlockedError):
        socket.getaddrinfo("localhost", 80)
    with pytest.raises(NetworkBlockedError):
        socket.gethostbyname("localhost")
    with pytest.raises(NetworkBlockedError):
        socket.socketpair()


def test_per_user_locations_point_into_the_temporary_directory(
    tmp_path_factory: pytest.TempPathFactory, isolated_home: Path
) -> None:
    base = tmp_path_factory.getbasetemp()
    assert isolated_home.is_relative_to(base)
    for name in conftest.ISOLATED_ENVIRONMENT:
        assert Path(os.environ[name]) == isolated_home, name
    assert Path.home() == isolated_home
    assert os.listdir(isolated_home) == []


def test_a_changed_variable_is_restored_to_the_session_value(
    monkeypatch: pytest.MonkeyPatch, isolated_home: Path
) -> None:
    monkeypatch.setenv("HOME", "elsewhere")
    assert os.environ["HOME"] == "elsewhere"
    monkeypatch.undo()
    assert Path(os.environ["HOME"]) == isolated_home


def test_the_isolated_home_check_fails_a_test_that_writes_there_and_cleans_up(
    tmp_path: Path,
) -> None:
    conftest.check_isolated_home_is_empty(tmp_path)  # empty: fine
    (tmp_path / "stray.txt").write_text("x", encoding="utf-8")
    (tmp_path / "stray-dir").mkdir()
    (tmp_path / "stray-dir" / "inner").write_text("y", encoding="utf-8")
    with pytest.raises(pytest.fail.Exception, match="wrote 2 entries into the isolated home"):
        conftest.check_isolated_home_is_empty(tmp_path)
    assert os.listdir(tmp_path) == []
    (tmp_path / "one").write_text("x", encoding="utf-8")
    with pytest.raises(pytest.fail.Exception, match="wrote 1 entry into"):
        conftest.check_isolated_home_is_empty(tmp_path)


# -- named skip markers ---------------------------------------------------------------------


def _symlinks_yes() -> bool:
    return True


def _symlinks_no() -> bool:
    return False


def test_skip_reason_table() -> None:
    reason = conftest.skip_reason
    assert reason({"posix_only"}, platform="win32", have_symlinks=_symlinks_yes) is not None
    assert reason({"posix_only"}, platform="linux", have_symlinks=_symlinks_yes) is None
    assert reason({"windows_only"}, platform="linux", have_symlinks=_symlinks_yes) is not None
    assert reason({"windows_only"}, platform="win32", have_symlinks=_symlinks_yes) is None
    assert reason({"requires_symlinks"}, platform="linux", have_symlinks=_symlinks_no) is not None
    assert reason({"requires_symlinks"}, platform="linux", have_symlinks=_symlinks_yes) is None
    assert reason(set(), platform="linux", have_symlinks=_symlinks_no) is None
    assert reason({"slow"}, platform="win32", have_symlinks=_symlinks_no) is None


def test_every_skip_reason_names_its_marker() -> None:
    cases = [
        ({"posix_only"}, "win32", _symlinks_yes, "posix_only"),
        ({"windows_only"}, "linux", _symlinks_yes, "windows_only"),
        ({"requires_symlinks"}, "linux", _symlinks_no, "requires_symlinks"),
    ]
    for markers, platform, probe, name in cases:
        text = conftest.skip_reason(markers, platform=platform, have_symlinks=probe)
        assert text is not None
        assert text.startswith(name)


def test_missing_tool_fails_in_ci_and_skips_elsewhere() -> None:
    assert conftest.missing_tool_outcome(in_ci=True) == "fail"
    assert conftest.missing_tool_outcome(in_ci=False) == "skip"
    assert conftest.REQUIRED_TOOLS == {"requires_git": "git", "requires_sh": "sh"}


def test_symlink_probe_returns_a_bool() -> None:
    assert isinstance(conftest.symlinks_work(), bool)


def test_registered_markers_match_the_documented_names() -> None:
    text = (Path(__file__).resolve().parent.parent / "pyproject.toml").read_text(encoding="utf-8")
    names = (
        "slow",
        "requires_symlinks",
        "requires_git",
        "requires_sh",
        "requires_git_sha256",
        "posix_only",
        "windows_only",
        "reads_repository",
    )
    for name in names:
        assert f'"{name}:' in text


# -- the temporary-path guard (CLAUDE.md section 7) ---------------------------------------


def test_the_guard_refuses_a_path_outside_the_temporary_base() -> None:
    from secret_scanner.fs import safe_files, walk

    outside = str(Path(__file__).resolve().parent)  # this repository's tests directory
    with pytest.raises(pytest.fail.Exception, match="outside the test temporary directory"):
        walk.check_scan_root(outside)
    with pytest.raises(pytest.fail.Exception, match="outside the test temporary directory"):
        safe_files.read_own_file(str(Path(__file__).resolve()), 100, "file")
    with pytest.raises(pytest.fail.Exception, match="outside the test temporary directory"):
        safe_files.write_new_file(str(Path(__file__).resolve().parent / "x.out"), b"x")
    with pytest.raises(pytest.fail.Exception, match="outside the test temporary directory"):
        safe_files.is_inside(str(Path(__file__).resolve().parent), str(tmp_inside()))
    with pytest.raises(pytest.fail.Exception, match="outside"):
        list(walk.walk_tree(root=outside, options=walk.WalkOptions(), counters=walk.WalkCounters()))
    assert not (Path(outside) / "x.out").exists()


def tmp_inside() -> Path:
    return Path(os.environ["HOME"]) / "inside"  # isolated-home lives under the temporary base


def test_the_guard_allows_paths_inside_the_temporary_base(tmp_path: Path) -> None:
    from secret_scanner.fs import safe_files, walk

    walk.check_scan_root(str(tmp_path))
    assert not safe_files.is_inside(str(tmp_path), str(tmp_path.parent / "elsewhere"))
    safe_files.write_new_file(str(tmp_path / "ok.txt"), b"x")


@pytest.mark.reads_repository
def test_the_marker_exempts_a_test_that_reads_the_repository() -> None:
    from secret_scanner.fs import walk

    walk.check_scan_root(str(Path(__file__).resolve().parent))


def test_the_guard_does_not_change_what_the_functions_do(tmp_path: Path) -> None:
    from secret_scanner.fs import walk

    assert hasattr(walk.walk_tree, "__wrapped__")
    assert walk.walk_tree.__name__ == "walk_tree"
    (tmp_path / "a.txt").write_text("x", encoding="utf-8")
    events = list(walk.walk_tree(str(tmp_path), walk.WalkOptions(), walk.WalkCounters()))
    assert [type(event).__name__ for event in events if type(event).__name__ == "FileContent"] == [
        "FileContent"
    ]


# -- throw-away repositories (D17) ----------------------------------------------------------


@pytest.mark.requires_git
def test_throw_away_repository_round_trip(tmp_path: Path) -> None:
    repo = GitRepo.create(tmp_path / "repo", tmp_path)
    repo.write("a.txt", "one\n")
    repo.add("a.txt")
    first = repo.commit("first")
    repo.write("b.txt", "two\n")
    repo.add("b.txt")
    second = repo.commit("second")
    assert first != second
    log = repo.git("log", "--format=%s").stdout.split()
    assert log == ["second", "first"]


@pytest.mark.requires_git
def test_repository_has_no_hooks_no_identity_and_pinned_dates(tmp_path: Path) -> None:
    repo = GitRepo.create(tmp_path / "repo", tmp_path)
    repo.write("a.txt", "x\n")
    repo.add("a.txt")
    repo.commit("first")
    hooks = repo.path / ".git" / "hooks"
    assert not hooks.exists() or list(hooks.iterdir()) == []
    config = (repo.path / ".git" / "config").read_text(encoding="utf-8")
    assert "[user]" not in config
    assert identity_email() not in config
    stamp = repo.git("log", "-1", "--format=%at").stdout.strip()
    assert stamp == "1767225660"  # fixed date, one minute after the first-commit epoch


@pytest.mark.requires_git
def test_git_environment_is_built_from_scratch(tmp_path: Path) -> None:
    environment = git_environment(tmp_path)
    assert environment["GIT_CONFIG_NOSYSTEM"] == "1"
    assert environment["GIT_CONFIG_GLOBAL"] == os.devnull
    assert environment["GIT_TERMINAL_PROMPT"] == "0"
    assert environment["GIT_AUTHOR_EMAIL"] == identity_email()
    assert "GIT_DIR" not in environment
    assert set(environment) <= {
        "PATH",
        "HOME",
        "SYSTEMROOT",
        "TEMP",
        "TMP",
        "GIT_CONFIG_NOSYSTEM",
        "GIT_CONFIG_GLOBAL",
        "GIT_TERMINAL_PROMPT",
        "GIT_PAGER",
        "PAGER",
        "LC_ALL",
        "GIT_AUTHOR_NAME",
        "GIT_AUTHOR_EMAIL",
        "GIT_AUTHOR_DATE",
        "GIT_COMMITTER_NAME",
        "GIT_COMMITTER_EMAIL",
        "GIT_COMMITTER_DATE",
    }


@pytest.mark.requires_git
def test_failing_git_command_raises_unless_checked_off(tmp_path: Path) -> None:
    with pytest.raises(subprocess.CalledProcessError):
        run_git(tmp_path, tmp_path, "rev-parse", "--verify", "no-such-ref")
    result = run_git(tmp_path, tmp_path, "rev-parse", "--verify", "no-such-ref", check=False)
    assert result.returncode != 0


def test_identity_email_is_built_at_runtime_from_fragments() -> None:
    value = identity_email()
    assert value.count("@") == 1
    assert value.endswith(".invalid")
