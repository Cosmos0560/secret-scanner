"""The demo's sandbox: the only module that creates and deletes files for the demo, and the checks
that keep it inside its own directory (PLAN.md Phase 5, CLAUDE.md section 5)."""

from __future__ import annotations

import errno
import os
import shutil
import stat
import subprocess
import sys
from pathlib import Path

import pytest

from secret_scanner.core.errors import DemoError
from secret_scanner.fs import sandbox
from secret_scanner.fs.sandbox import (
    PREFIX,
    create_sandbox,
    make_directory,
    member,
    remove_sandbox,
    write_text,
)

BACKSLASH = chr(92)


def make_junction(link: str | Path, target: str | Path) -> None:
    """A Windows junction (the reparse point `os.symlink` does not make) through `mklink /J`."""
    subprocess.run(
        ["cmd", "/c", "mklink", "/J", str(link), str(target)],
        check=True,
        capture_output=True,
        timeout=60,
    )


@pytest.fixture
def box(tmp_path: Path) -> str:
    return create_sandbox(str(tmp_path))


# -- creating -------------------------------------------------------------------------------------


def test_the_sandbox_is_a_new_prefixed_directory_under_the_parent(tmp_path: Path) -> None:
    first = create_sandbox(str(tmp_path))
    second = create_sandbox(str(tmp_path))
    assert first != second
    for path in (first, second):
        assert os.path.isdir(path)
        assert os.path.basename(path).startswith(PREFIX)
        assert os.path.dirname(path) == os.path.realpath(tmp_path)
        assert os.listdir(path) == []


def test_a_missing_parent_is_a_demo_error_without_a_path(tmp_path: Path) -> None:
    missing = tmp_path / "no" / "such" / "parent"
    with pytest.raises(DemoError, match="cannot create") as caught:
        create_sandbox(str(missing))
    assert str(missing) not in str(caught.value)


# -- names ----------------------------------------------------------------------------------------


@pytest.mark.parametrize(
    "relative",
    [
        "",
        ".",
        "..",
        "a/../b",
        "a/./b",
        "a//b",
        "/abs",
        "a/",
        "a" + BACKSLASH + "b",
        "c:x",
        "a:stream",
        "nul" + chr(0) + "x",
        "ctl" + chr(0x1B),
        "line" + chr(10) + "feed",
        "dot.",
        "space ",
        "dir/space ",
        "question?",
        "star*",
        "pipe|",
        "less<",
        "more>",
        'quote"',
    ],
    ids=repr,
)
def test_a_name_that_is_not_a_plain_relative_name_is_refused(relative: str, box: str) -> None:
    with pytest.raises(DemoError, match="plain relative name"):
        member(box, relative)
    with pytest.raises(DemoError, match="plain relative name"):
        write_text(box, relative, "x")
    with pytest.raises(DemoError, match="plain relative name"):
        make_directory(box, relative)
    assert os.listdir(box) == []


def test_plain_names_join_under_the_root(box: str) -> None:
    assert member(box, ".env") == os.path.join(box, ".env")
    assert member(box, "a/b/c.txt") == os.path.join(box, "a", "b", "c.txt")
    assert member(box, "..hidden/x..y") == os.path.join(box, "..hidden", "x..y")


# -- writing --------------------------------------------------------------------------------------


def test_write_text_makes_parents_and_writes_utf8_with_line_feeds(box: str) -> None:
    path = write_text(box, "a/b/c.txt", "one" + chr(10) + "two" + chr(0xE9) + chr(10))
    assert path == os.path.join(box, "a", "b", "c.txt")
    with open(path, "rb") as handle:
        assert handle.read() == b"one\ntwo\xc3\xa9\n"


def test_write_text_never_overwrites_without_replace(box: str) -> None:
    write_text(box, "f.txt", "first")
    with pytest.raises(DemoError, match="cannot write"):
        write_text(box, "f.txt", "second")
    with open(os.path.join(box, "f.txt"), encoding="utf-8") as handle:
        assert handle.read() == "first"


def test_replace_rewrites_an_existing_regular_file(box: str) -> None:
    write_text(box, "f.txt", "first")
    write_text(box, "f.txt", "second", replace=True)
    with open(os.path.join(box, "f.txt"), encoding="utf-8") as handle:
        assert handle.read() == "second"


def test_replace_of_a_missing_file_or_a_directory_is_refused(box: str) -> None:
    with pytest.raises(DemoError, match="cannot write"):
        write_text(box, "missing.txt", "x", replace=True)
    make_directory(box, "dir")
    with pytest.raises(DemoError, match="not a regular file"):
        write_text(box, "dir", "x", replace=True)


@pytest.mark.requires_symlinks
def test_replace_never_writes_through_a_link(box: str, tmp_path: Path) -> None:
    outside = tmp_path / "outside.txt"
    outside.write_text("untouched", encoding="utf-8")
    os.symlink(outside, os.path.join(box, "link.txt"))
    with pytest.raises(DemoError, match="not a regular file"):
        write_text(box, "link.txt", "overwritten", replace=True)
    assert outside.read_text(encoding="utf-8") == "untouched"


def test_make_directory_is_nested_and_repeatable(box: str) -> None:
    path = make_directory(box, "a/b")
    assert os.path.isdir(path)
    assert make_directory(box, "a/b") == path


def test_os_errors_become_demo_errors_that_name_no_path(
    box: str, monkeypatch: pytest.MonkeyPatch
) -> None:
    secret_place = os.path.join(box, "private-place")

    def refuse(*args: object, **kwargs: object) -> None:
        raise PermissionError(errno.EACCES, "denied", secret_place)

    monkeypatch.setattr(os, "makedirs", refuse)
    with pytest.raises(DemoError) as made:
        make_directory(box, "d")
    with pytest.raises(DemoError) as written:
        write_text(box, "d/f.txt", "x")
    for caught in (made, written):
        assert secret_place not in str(caught.value)
        assert "EACCES" in str(caught.value)


# -- removing -------------------------------------------------------------------------------------


def test_remove_deletes_the_tree_including_read_only_files(box: str) -> None:
    write_text(box, "a/b/plain.txt", "x")
    locked = write_text(box, "objects/ab/locked", "x")
    os.chmod(locked, stat.S_IREAD)  # a git object file is read-only
    remove_sandbox(box)
    assert not os.path.exists(box)


@pytest.mark.posix_only
def test_remove_deletes_a_fifo_without_opening_it(box: str) -> None:
    if sys.platform != "win32":  # mypy: os.mkfifo does not exist on Windows
        os.mkfifo(os.path.join(box, "pipe"))  # opening it for reading would block forever
    remove_sandbox(box)
    assert not os.path.exists(box)


def test_remove_of_a_sandbox_that_is_gone_is_fine(box: str) -> None:
    remove_sandbox(box)
    remove_sandbox(box)


def test_remove_refuses_a_directory_that_is_not_a_demo_directory(tmp_path: Path) -> None:
    other = tmp_path / "precious"
    other.mkdir()
    (other / "file.txt").write_text("keep me", encoding="utf-8")
    with pytest.raises(DemoError, match="not a demo directory"):
        remove_sandbox(str(other))
    assert (other / "file.txt").read_text(encoding="utf-8") == "keep me"


def test_remove_refuses_a_file_in_place_of_the_directory(tmp_path: Path) -> None:
    impostor = tmp_path / (PREFIX + "file")
    impostor.write_text("not a directory", encoding="utf-8")
    with pytest.raises(DemoError, match="not a plain directory"):
        remove_sandbox(str(impostor))
    assert impostor.exists()


@pytest.mark.requires_symlinks
def test_remove_refuses_a_link_in_place_of_the_directory(tmp_path: Path) -> None:
    target = tmp_path / "target"
    target.mkdir()
    (target / "keep.txt").write_text("keep me", encoding="utf-8")
    link = tmp_path / (PREFIX + "link")
    os.symlink(target, link, target_is_directory=True)
    with pytest.raises(DemoError, match="not a plain directory"):
        remove_sandbox(str(link))
    assert (target / "keep.txt").read_text(encoding="utf-8") == "keep me"


@pytest.mark.requires_symlinks
def test_remove_unlinks_a_link_inside_without_following_it(box: str, tmp_path: Path) -> None:
    target = tmp_path / "target-dir"
    target.mkdir()
    (target / "keep.txt").write_text("keep me", encoding="utf-8")
    outside_file = tmp_path / "outside.txt"
    outside_file.write_text("keep me too", encoding="utf-8")
    os.symlink(target, os.path.join(box, "dir-link"), target_is_directory=True)
    os.symlink(outside_file, os.path.join(box, "file-link"))
    remove_sandbox(box)
    assert not os.path.exists(box)
    assert (target / "keep.txt").read_text(encoding="utf-8") == "keep me"
    assert outside_file.read_text(encoding="utf-8") == "keep me too"


@pytest.mark.windows_only
def test_remove_does_not_follow_a_junction_inside(box: str, tmp_path: Path) -> None:
    target = tmp_path / "junction-target"
    target.mkdir()
    (target / "keep.txt").write_text("keep me", encoding="utf-8")
    make_junction(os.path.join(box, "junction"), target)
    remove_sandbox(box)
    assert not os.path.exists(box)
    assert (target / "keep.txt").read_text(encoding="utf-8") == "keep me"


@pytest.mark.windows_only
def test_remove_refuses_a_junction_in_place_of_the_directory(tmp_path: Path) -> None:
    target = tmp_path / "junction-target"
    target.mkdir()
    (target / "keep.txt").write_text("keep me", encoding="utf-8")
    link = tmp_path / (PREFIX + "junction")
    make_junction(link, target)
    with pytest.raises(DemoError, match="not a plain directory"):
        remove_sandbox(str(link))
    assert (target / "keep.txt").read_text(encoding="utf-8") == "keep me"


def test_a_failed_removal_says_so_and_names_no_path(
    box: str, monkeypatch: pytest.MonkeyPatch
) -> None:
    def fail(*args: object, **kwargs: object) -> None:
        raise PermissionError(errno.EACCES, "denied", box)

    monkeypatch.setattr(shutil, "rmtree", fail)
    with pytest.raises(DemoError, match="delete it by hand") as caught:
        remove_sandbox(box)
    assert box not in str(caught.value)
    assert os.path.isdir(box)


def test_an_unreadable_root_is_a_demo_error(box: str, monkeypatch: pytest.MonkeyPatch) -> None:
    class UnreadableOs:
        """The `os` module as the sandbox sees it, with a `lstat` that fails (the test guard and
        pytest keep the real one)."""

        @staticmethod
        def lstat(path: object) -> os.stat_result:
            raise PermissionError(errno.EACCES, "denied")

        def __getattr__(self, name: str) -> object:
            return getattr(os, name)

    monkeypatch.setattr(sandbox, "os", UnreadableOs())
    with pytest.raises(DemoError, match="cannot examine"):
        remove_sandbox(box)
