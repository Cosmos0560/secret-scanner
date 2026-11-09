"""The demo's repository builder: the commit identity lives only in the subprocess environment, the
environment is built from scratch, hooks are off, and failures are reported without content
(PLAN.md D17)."""

from __future__ import annotations

import os
import re
import stat
import sys
from pathlib import Path

import pytest

from secret_scanner.core.errors import GitError
from secret_scanner.gitio import demo_git
from secret_scanner.gitio.demo_git import (
    FIRST_COMMIT_EPOCH,
    PINNED_CONFIG,
    DemoRepo,
    environment_for,
    identity_email,
)
from tests.gitrepo import git_binary

ADDRESS = re.compile(r"[\w.+-]+@[\w-]+\.[\w.-]+")


def build_repo(tmp_path: Path, name: str = "repo") -> tuple[DemoRepo, Path, Path]:
    repo = tmp_path / name
    home = tmp_path / (name + "-home")
    repo.mkdir()
    home.mkdir()
    return DemoRepo(git_binary(), str(repo), str(home)), repo, home


# -- the environment ------------------------------------------------------------------------------


def test_the_environment_is_built_from_scratch(tmp_path: Path) -> None:
    git = str(tmp_path / "bin" / "git")
    environment = environment_for(git, str(tmp_path / "home"), 0)
    expected = {
        "PATH",
        "HOME",
        "GIT_CONFIG_NOSYSTEM",
        "GIT_CONFIG_GLOBAL",
        "GIT_TERMINAL_PROMPT",
        "GIT_PAGER",
        "PAGER",
        "LC_ALL",
        "GIT_AUTHOR_NAME",
        "GIT_AUTHOR_EMAIL",
        "GIT_COMMITTER_NAME",
        "GIT_COMMITTER_EMAIL",
        "GIT_AUTHOR_DATE",
        "GIT_COMMITTER_DATE",
    }
    if sys.platform == "win32":
        expected |= {"SYSTEMROOT", "TEMP", "TMP"}
    assert set(environment) == expected
    assert environment["PATH"] == str(tmp_path / "bin")
    assert environment["HOME"] == str(tmp_path / "home")
    assert environment["GIT_CONFIG_GLOBAL"] == os.devnull
    assert environment["GIT_CONFIG_NOSYSTEM"] == "1"
    assert environment["GIT_TERMINAL_PROMPT"] == "0"


def test_the_identity_is_in_the_environment_and_has_no_literal_address() -> None:
    environment = environment_for("/x/git", "/home", 0)
    assert environment["GIT_AUTHOR_EMAIL"] == environment["GIT_COMMITTER_EMAIL"] == identity_email()
    assert environment["GIT_AUTHOR_NAME"] == environment["GIT_COMMITTER_NAME"]
    local, at, domain = identity_email().partition("@")
    assert (local, at, domain.rsplit(".", 1)[-1]) == ("demo", "@", "invalid")
    source = Path(demo_git.__file__).read_text(encoding="utf-8")
    assert ADDRESS.search(source) is None, "no file may hold an email address"


def test_commit_dates_are_fixed_and_one_hour_apart() -> None:
    first = environment_for("/x/git", "/home", 0)
    second = environment_for("/x/git", "/home", 1)
    assert first["GIT_AUTHOR_DATE"] == f"{FIRST_COMMIT_EPOCH} +0000"
    assert first["GIT_AUTHOR_DATE"] == first["GIT_COMMITTER_DATE"]
    assert second["GIT_AUTHOR_DATE"] == f"{FIRST_COMMIT_EPOCH + 3600} +0000"


def test_the_pinned_configuration_turns_off_hooks_signing_transport_and_gc() -> None:
    config = dict(PINNED_CONFIG)
    assert config["core.hooksPath"] == os.devnull
    assert config["commit.gpgsign"] == "false"
    assert config["tag.gpgsign"] == "false"
    assert config["protocol.allow"] == "never"
    assert config["gc.auto"] == "0"
    assert config["core.fsmonitor"] == "false"
    assert not any(key.startswith("user.") for key in config), "identity is never configuration"


def test_a_relative_git_program_is_refused(tmp_path: Path) -> None:
    with pytest.raises(GitError, match="absolute path"):
        DemoRepo("git", str(tmp_path), str(tmp_path))


# -- real repositories ----------------------------------------------------------------------------


@pytest.mark.requires_git
def test_a_repository_gets_commits_with_full_ids(tmp_path: Path) -> None:
    builder, repo, _ = build_repo(tmp_path)
    builder.init()
    (repo / "a.txt").write_text("one\n", encoding="utf-8", newline="\n")
    builder.add("a.txt")
    first = builder.commit("first")
    (repo / "a.txt").write_text("two\n", encoding="utf-8", newline="\n")
    builder.add("a.txt")
    second = builder.commit("second")
    assert re.fullmatch(r"[0-9a-f]{40}|[0-9a-f]{64}", first)
    assert re.fullmatch(r"[0-9a-f]{40}|[0-9a-f]{64}", second)
    assert first != second
    assert (repo / ".git").is_dir()


@pytest.mark.requires_git
def test_removing_a_file_is_a_commit(tmp_path: Path) -> None:
    builder, repo, _ = build_repo(tmp_path)
    builder.init()
    (repo / "gone.txt").write_text("x\n", encoding="utf-8", newline="\n")
    builder.add("gone.txt")
    builder.commit("add")
    builder.remove("gone.txt")
    builder.commit("remove")
    assert not (repo / "gone.txt").exists()


@pytest.mark.requires_git
def test_the_same_content_gives_the_same_commit_ids(tmp_path: Path) -> None:
    ids = []
    for name in ("one", "two"):
        builder, repo, _ = build_repo(tmp_path, name)
        builder.init()
        (repo / "a.txt").write_text("same\n", encoding="utf-8", newline="\n")
        builder.add("a.txt")
        ids.append(builder.commit("same message"))
    assert ids[0] == ids[1]


@pytest.mark.requires_git
def test_no_identity_is_written_to_any_configuration_file(tmp_path: Path) -> None:
    builder, repo, home = build_repo(tmp_path)
    builder.init()
    (repo / "a.txt").write_text("x\n", encoding="utf-8", newline="\n")
    builder.add("a.txt")
    builder.commit("one")
    config = (repo / ".git" / "config").read_text(encoding="utf-8")
    assert "[user]" not in config
    assert "email" not in config.lower()
    assert list(home.iterdir()) == [], "nothing is written to the home directory"
    assert ADDRESS.search(config) is None


@pytest.mark.requires_git
def test_a_hook_in_the_repository_never_runs(tmp_path: Path) -> None:
    builder, repo, _ = build_repo(tmp_path)
    builder.init()
    marker = tmp_path / "hook-ran"
    hook = repo / ".git" / "hooks" / "post-commit"
    hook.parent.mkdir(parents=True, exist_ok=True)
    hook.write_text(f"#!/bin/sh\necho ran > '{marker.as_posix()}'\n", encoding="utf-8")
    hook.chmod(hook.stat().st_mode | stat.S_IXUSR)
    (repo / "a.txt").write_text("x\n", encoding="utf-8", newline="\n")
    builder.add("a.txt")
    builder.commit("one")
    assert not marker.exists()


@pytest.mark.requires_git
def test_a_failing_command_is_a_git_error_with_the_exit_code_and_no_output(
    tmp_path: Path,
) -> None:
    builder, _, _ = build_repo(tmp_path)
    builder.init()
    with pytest.raises(GitError, match=r"git commit failed in the demo repository \(exit 1\)"):
        builder.commit("nothing is staged")


@pytest.mark.requires_git
def test_a_missing_program_is_a_git_error(tmp_path: Path) -> None:
    missing = str(tmp_path / "nowhere" / ("git.exe" if sys.platform == "win32" else "git"))
    repo = tmp_path / "repo"
    repo.mkdir()
    with pytest.raises(GitError, match="could not be started"):
        DemoRepo(missing, str(repo), str(tmp_path)).init()


@pytest.mark.requires_git
def test_a_command_that_does_not_finish_is_a_git_error(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(demo_git, "TIMEOUT_SECONDS", 0.001)
    builder, _, _ = build_repo(tmp_path)
    with pytest.raises(GitError, match="did not finish"):
        builder.init()
