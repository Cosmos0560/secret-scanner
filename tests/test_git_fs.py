"""The file-system side of the git scan: finding the git program, examining a repository directory
before git is allowed to read it, and the `--gitignore` filter of the walker."""

from __future__ import annotations

import os
import stat
from pathlib import Path

import pytest

from secret_scanner.core.errors import ScanIOError
from secret_scanner.fs import safe_files, walk
from secret_scanner.fs.walk import (
    GitDirKind,
    SkipReason,
    WalkCounters,
    WalkOptions,
    directories_of,
    inspect_repository,
    same_directory,
)

# -- finding the git program ---------------------------------------------------------------------


def make_program(directory: Path, name: str = "git", *, executable: bool = True) -> Path:
    directory.mkdir(parents=True, exist_ok=True)
    program = directory / name
    program.write_bytes(b"not really git")
    mode = program.stat().st_mode
    program.chmod(mode | stat.S_IXUSR if executable else mode & ~stat.S_IXUSR & ~stat.S_IXGRP)
    return program


def search_path(*entries: object) -> str:
    return os.pathsep.join(str(entry) for entry in entries)


def test_the_first_absolute_entry_with_the_program_wins(tmp_path: Path) -> None:
    first = make_program(tmp_path / "one")
    make_program(tmp_path / "two")
    found = safe_files.find_program(
        "git", search_path(tmp_path / "none", tmp_path / "one", tmp_path / "two"), windows=False
    )
    assert found == str(first)


def test_relative_and_empty_entries_are_never_searched(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    planted = make_program(tmp_path / "work", "git")
    monkeypatch.chdir(planted.parent)
    for entry in ("", ".", "..", "work", "./", os.curdir + os.sep):
        assert safe_files.find_program("git", entry, windows=False) is None
    assert safe_files.find_program(
        "git", search_path("", ".", planted.parent), windows=False
    ) == str(planted)


def test_the_current_directory_is_not_searched_when_path_has_no_entry_for_it(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    make_program(tmp_path / "cwd", "git.exe")
    monkeypatch.chdir(tmp_path / "cwd")
    assert safe_files.find_program("git", "", windows=True) is None
    assert safe_files.find_program("git", str(tmp_path / "elsewhere"), windows=True) is None


def test_a_program_inside_the_scanned_tree_is_never_trusted(tmp_path: Path) -> None:
    tree = tmp_path / "repo"
    make_program(tree / "tools")
    good = make_program(tmp_path / "system")
    found = safe_files.find_program(
        "git", search_path(tree / "tools", tmp_path / "system"), windows=False, avoid=[str(tree)]
    )
    assert found == str(good)
    assert (
        safe_files.find_program(
            "git", search_path(tree / "tools"), windows=False, avoid=[str(tree)]
        )
        is None
    )


def test_windows_looks_for_an_exe_and_ignores_other_names(tmp_path: Path) -> None:
    make_program(tmp_path / "bin", "git")
    make_program(tmp_path / "bin", "git.cmd")
    make_program(tmp_path / "bin", "git.bat")
    assert safe_files.find_program("git", str(tmp_path / "bin"), windows=True) is None
    exe = make_program(tmp_path / "bin", "git.exe")
    assert safe_files.find_program("git", str(tmp_path / "bin"), windows=True) == str(exe)


def test_a_directory_named_like_the_program_is_not_a_program(tmp_path: Path) -> None:
    (tmp_path / "bin" / "git").mkdir(parents=True)
    assert safe_files.find_program("git", str(tmp_path / "bin"), windows=False) is None


@pytest.mark.posix_only
def test_a_file_without_the_execute_bit_is_skipped_on_posix(tmp_path: Path) -> None:
    make_program(tmp_path / "bin", executable=False)
    good = make_program(tmp_path / "other")
    assert safe_files.find_program(
        "git", search_path(tmp_path / "bin", tmp_path / "other"), windows=False
    ) == str(good)


@pytest.mark.requires_symlinks
def test_a_link_to_a_regular_file_is_followed_but_a_link_to_a_directory_is_not(
    tmp_path: Path,
) -> None:
    target = make_program(tmp_path / "real", "git-real")
    (tmp_path / "bin").mkdir()
    (tmp_path / "bin" / "git").symlink_to(target)
    assert safe_files.find_program("git", str(tmp_path / "bin"), windows=False) == str(
        tmp_path / "bin" / "git"
    )
    (tmp_path / "dirs").mkdir()
    (tmp_path / "dirs" / "git").symlink_to(tmp_path / "real", target_is_directory=True)
    assert safe_files.find_program("git", str(tmp_path / "dirs"), windows=False) is None


def test_a_user_given_program_is_validated(tmp_path: Path) -> None:
    good = make_program(tmp_path / "x", "git")
    assert safe_files.check_program(str(good), windows=False) == str(good)
    with pytest.raises(ScanIOError, match="absolute"):
        safe_files.check_program("git", windows=False)
    with pytest.raises(ScanIOError, match="inside the scanned tree"):
        safe_files.check_program(str(good), windows=False, avoid=[str(tmp_path)])
    with pytest.raises(ScanIOError, match="cannot be examined"):
        safe_files.check_program(str(tmp_path / "missing"), windows=False)
    with pytest.raises(ScanIOError, match="not a regular file"):
        safe_files.check_program(str(tmp_path), windows=False)


@pytest.mark.posix_only
def test_a_user_given_program_must_be_executable_on_posix(tmp_path: Path) -> None:
    plain = make_program(tmp_path / "x", "git", executable=False)
    with pytest.raises(ScanIOError, match="not executable"):
        safe_files.check_program(str(plain), windows=False)


# -- the layout of a repository directory --------------------------------------------------------


def standard_repository(root: Path) -> Path:
    git_dir = root / ".git"
    (git_dir / "objects" / "info").mkdir(parents=True)
    (git_dir / "refs").mkdir()
    (git_dir / "info").mkdir()
    (git_dir / "HEAD").write_bytes(b"ref: refs/heads/main" + chr(10).encode())
    return git_dir


def test_a_standard_repository(tmp_path: Path) -> None:
    git_dir = standard_repository(tmp_path / "r")
    layout = inspect_repository(str(tmp_path / "r"))
    assert layout.kind is GitDirKind.STANDARD
    assert layout.git_dir is not None
    assert same_directory(layout.git_dir, str(git_dir))
    assert (layout.alternates, layout.grafts) == (False, False)


def test_a_bare_repository(tmp_path: Path) -> None:
    root = tmp_path / "bare.git"
    (root / "objects").mkdir(parents=True)
    (root / "refs").mkdir()
    (root / "HEAD").write_bytes(b"ref: refs/heads/main")
    layout = inspect_repository(str(root))
    assert layout.kind is GitDirKind.BARE
    assert layout.git_dir is not None
    assert same_directory(layout.git_dir, str(root))


def test_a_directory_that_is_not_a_repository(tmp_path: Path) -> None:
    (tmp_path / "plain").mkdir()
    layout = inspect_repository(str(tmp_path / "plain"))
    assert layout.kind is GitDirKind.MISSING
    assert layout.git_dir is None
    # parts of a bare layout are not enough
    (tmp_path / "half" / "objects").mkdir(parents=True)
    assert inspect_repository(str(tmp_path / "half")).kind is GitDirKind.MISSING


def test_a_dot_git_file_is_a_gitdir_link_and_is_not_read(tmp_path: Path) -> None:
    root = tmp_path / "wt"
    root.mkdir()
    (root / ".git").write_bytes(b"gitdir: " + str(tmp_path / "elsewhere").encode())
    layout = inspect_repository(str(root))
    assert layout.kind is GitDirKind.LINK_FILE
    assert layout.git_dir is None


@pytest.mark.requires_symlinks
def test_a_dot_git_symlink_is_refused_not_followed(tmp_path: Path) -> None:
    real = standard_repository(tmp_path / "real")
    root = tmp_path / "link"
    root.mkdir()
    (root / ".git").symlink_to(real, target_is_directory=True)
    layout = inspect_repository(str(root))
    assert layout.kind is GitDirKind.LINK
    assert layout.git_dir is None


@pytest.mark.parametrize(
    ("content", "expected"),
    [
        (b"/somewhere/else/objects" + chr(10).encode(), True),
        (b"../../shared/objects", True),
        (b"# only a comment" + chr(10).encode(), False),
        (b"   " + chr(10).encode() + chr(10).encode(), False),
        (b"", False),
        (b"# note" + chr(10).encode() + b"/real/objects" + chr(10).encode(), True),
    ],
)
@pytest.mark.parametrize("name", ["alternates", "http-alternates"])
def test_alternate_object_stores_are_detected(
    tmp_path: Path, name: str, content: bytes, expected: bool
) -> None:
    git_dir = standard_repository(tmp_path / "r")
    (git_dir / "objects" / "info" / name).write_bytes(content)
    assert inspect_repository(str(tmp_path / "r")).alternates is expected


def test_an_alternates_entry_that_is_not_a_regular_file_counts_as_present(tmp_path: Path) -> None:
    git_dir = standard_repository(tmp_path / "r")
    (git_dir / "objects" / "info" / "alternates").mkdir()
    assert inspect_repository(str(tmp_path / "r")).alternates is True


def test_a_large_alternates_file_counts_as_present_without_being_parsed(tmp_path: Path) -> None:
    git_dir = standard_repository(tmp_path / "r")
    (git_dir / "objects" / "info" / "alternates").write_bytes(b"#" * 200_000)
    assert inspect_repository(str(tmp_path / "r")).alternates is True


def test_grafts_are_detected(tmp_path: Path) -> None:
    git_dir = standard_repository(tmp_path / "r")
    assert inspect_repository(str(tmp_path / "r")).grafts is False
    (git_dir / "info" / "grafts").write_bytes(b"# nothing" + chr(10).encode())
    assert inspect_repository(str(tmp_path / "r")).grafts is False
    (git_dir / "info" / "grafts").write_bytes(
        ("a" * 40 + " " + "b" * 40).encode() + chr(10).encode()
    )
    assert inspect_repository(str(tmp_path / "r")).grafts is True


def test_same_directory_ignores_case_style_and_form(tmp_path: Path) -> None:
    (tmp_path / "d").mkdir()
    assert same_directory(str(tmp_path / "d"), str(tmp_path / "d" / ".." / "d"))
    assert not same_directory(str(tmp_path / "d"), str(tmp_path))


# -- the --gitignore filter of the walker ------------------------------------------------------


def test_directories_of() -> None:
    assert directories_of(frozenset({"a.txt"})) == frozenset()
    assert directories_of(frozenset({"a/b/c.txt", "a/d.txt", "e/f.txt"})) == frozenset(
        {"a", "a/b", "e"}
    )


def populate(root: Path) -> None:
    for relative in ("keep.txt", "skip.txt", "pkg/inner.txt", "pkg/sub/deep.txt", "ign/a.txt"):
        target = root / relative
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_bytes(b"data")


def test_only_listed_files_are_read_and_unlisted_directories_are_not_entered(
    tmp_path: Path,
) -> None:
    populate(tmp_path)
    options = WalkOptions(only_paths=frozenset({"keep.txt", "pkg/sub/deep.txt"}))
    read: list[str] = []
    skipped: list[tuple[str, SkipReason]] = []
    for event in walk.walk_tree(str(tmp_path), options, WalkCounters()):
        if isinstance(event, walk.FileContent):
            read.append(event.path_key)
        elif isinstance(event, walk.Skipped):
            skipped.append((event.path_key, event.reason))
    assert read == ["keep.txt", "pkg/sub/deep.txt"]
    assert ("skip.txt", SkipReason.GITIGNORED) in skipped
    assert ("pkg/inner.txt", SkipReason.GITIGNORED) in skipped
    assert ("ign", SkipReason.GITIGNORED) in skipped  # a whole directory, entered never
    assert not any(path.startswith("ign/") for path, _ in skipped)


def test_without_a_list_everything_is_read(tmp_path: Path) -> None:
    populate(tmp_path)
    paths = [
        event.path_key
        for event in walk.walk_tree(str(tmp_path), WalkOptions(), WalkCounters())
        if isinstance(event, walk.FileContent)
    ]
    assert sorted(paths) == [
        "ign/a.txt",
        "keep.txt",
        "pkg/inner.txt",
        "pkg/sub/deep.txt",
        "skip.txt",
    ]
