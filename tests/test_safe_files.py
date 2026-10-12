"""Reading and writing the tool's own files (PLAN.md section 1.4, CLAUDE.md section 5 invariants 9
and 10): atomic, no-clobber, never through a link, never leaving a temporary file behind."""

from __future__ import annotations

import errno
import os
from pathlib import Path

import pytest

from secret_scanner.core.errors import ExitCode, ScanIOError
from secret_scanner.fs import safe_files
from secret_scanner.fs.safe_files import is_inside, read_own_file, write_new_file


def listing(directory: Path) -> list[str]:
    return sorted(entry.name for entry in directory.iterdir())


# -- reading ----------------------------------------------------------------------------------


def test_a_regular_file_is_read_exactly(tmp_path: Path) -> None:
    (tmp_path / "c.yaml").write_bytes(b"version: 1\n")
    assert read_own_file(str(tmp_path / "c.yaml"), 100, "configuration file") == b"version: 1\n"
    (tmp_path / "empty").write_bytes(b"")
    assert read_own_file(str(tmp_path / "empty"), 100, "configuration file") == b""


def test_the_size_limit_is_exact(tmp_path: Path) -> None:
    (tmp_path / "a").write_bytes(b"x" * 10)
    (tmp_path / "b").write_bytes(b"x" * 11)
    assert read_own_file(str(tmp_path / "a"), 10, "baseline") == b"x" * 10
    with pytest.raises(ScanIOError, match="larger than the limit of 10 bytes"):
        read_own_file(str(tmp_path / "b"), 10, "baseline")


def test_a_missing_file_a_directory_are_refused(tmp_path: Path) -> None:
    with pytest.raises(ScanIOError, match="does not exist"):
        read_own_file(str(tmp_path / "missing"), 10, "baseline")
    with pytest.raises(ScanIOError, match="not a regular file"):
        read_own_file(str(tmp_path), 10, "baseline")


@pytest.mark.requires_symlinks
def test_a_link_is_refused_not_followed(tmp_path: Path) -> None:
    (tmp_path / "real").write_bytes(b"x")
    os.symlink(tmp_path / "real", tmp_path / "link")
    with pytest.raises(ScanIOError, match="link or reparse point"):
        read_own_file(str(tmp_path / "link"), 10, "baseline")


def test_read_errors_name_the_errno_and_never_the_content(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    path = tmp_path / "f"
    path.write_bytes(b"CONTENT-THAT-MUST-NOT-APPEAR")

    def refuse(target: str, flags: int) -> int:
        raise PermissionError(errno.EACCES, "denied: CONTENT-THAT-MUST-NOT-APPEAR")

    monkeypatch.setattr(os, "open", refuse)
    with pytest.raises(ScanIOError, match=r"cannot be opened \(EACCES\)") as caught:
        read_own_file(str(path), 100, "baseline")
    assert "CONTENT" not in str(caught.value)


def test_an_lstat_error_and_a_read_error_are_reported(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    path = tmp_path / "f"
    path.write_bytes(b"data")
    real_read = os.read

    def failing_read(descriptor: int, count: int) -> bytes:
        raise OSError(errno.EIO, "io")

    monkeypatch.setattr(os, "read", failing_read)
    with pytest.raises(ScanIOError, match=r"cannot be read \(EIO\)"):
        read_own_file(str(path), 100, "baseline")
    monkeypatch.setattr(os, "read", real_read)

    def failing_lstat(target: str) -> os.stat_result:
        raise OSError(errno.EIO, "io")

    monkeypatch.setattr(os, "lstat", failing_lstat)
    with pytest.raises(ScanIOError, match=r"cannot be examined \(EIO\)"):
        read_own_file(str(path), 100, "baseline")


def test_a_file_swapped_between_examination_and_open_is_refused(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    path = tmp_path / "f"
    path.write_bytes(b"original")
    (tmp_path / "other").write_bytes(b"other")
    real_open = os.open

    def swapping(target: str, flags: int) -> int:
        os.unlink(target)
        os.replace(tmp_path / "other", target)
        return real_open(target, flags)

    monkeypatch.setattr(os, "open", swapping)
    with pytest.raises(ScanIOError, match="changed while it was being opened"):
        read_own_file(str(path), 100, "baseline")


def test_a_file_that_grows_past_the_limit_during_the_read_is_refused(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    path = tmp_path / "f"
    path.write_bytes(b"x" * 40)
    real_lstat = os.lstat

    def understated(target: str) -> os.stat_result:
        fields = list(real_lstat(target))[:10]
        fields[6] = 5  # the examination saw 5 bytes; 40 are there when it is read
        return os.stat_result(fields)

    monkeypatch.setattr(os, "lstat", understated)
    with pytest.raises(ScanIOError, match="larger than the limit of 10 bytes"):
        read_own_file(str(path), 10, "baseline")


# -- writing ----------------------------------------------------------------------------------


def test_a_new_file_is_created_with_exactly_the_data_and_no_temporary_is_left(
    tmp_path: Path,
) -> None:
    write_new_file(str(tmp_path / "out.json"), b'{"a": 1}\n')
    assert (tmp_path / "out.json").read_bytes() == b'{"a": 1}\n'
    assert listing(tmp_path) == ["isolated-home", "out.json"]


def test_empty_data_is_written(tmp_path: Path) -> None:
    write_new_file(str(tmp_path / "empty"), b"")
    assert (tmp_path / "empty").read_bytes() == b""


@pytest.mark.posix_only
def test_the_new_file_is_private(tmp_path: Path) -> None:
    write_new_file(str(tmp_path / "out"), b"x")
    assert (tmp_path / "out").stat().st_mode & 0o777 == 0o600


def test_an_existing_file_is_never_overwritten_without_force(tmp_path: Path) -> None:
    target = tmp_path / "out"
    target.write_bytes(b"precious")
    with pytest.raises(ScanIOError, match="already exists") as caught:
        write_new_file(str(target), b"new")
    assert caught.value.exit_code is ExitCode.USAGE
    assert target.read_bytes() == b"precious"
    assert listing(tmp_path) == ["isolated-home", "out"]


def test_force_replaces_a_regular_file(tmp_path: Path) -> None:
    target = tmp_path / "out"
    target.write_bytes(b"old")
    write_new_file(str(target), b"new", force=True)
    assert target.read_bytes() == b"new"
    assert listing(tmp_path) == ["isolated-home", "out"]


def test_force_creates_a_missing_file_too(tmp_path: Path) -> None:
    write_new_file(str(tmp_path / "out"), b"x", force=True)
    assert (tmp_path / "out").read_bytes() == b"x"


def test_a_missing_directory_and_a_directory_target_are_refused(tmp_path: Path) -> None:
    with pytest.raises(ScanIOError, match="directory does not exist"):
        write_new_file(str(tmp_path / "nope" / "out"), b"x")
    (tmp_path / "adir").mkdir()
    for force in (False, True):
        with pytest.raises(ScanIOError, match="not a regular file"):
            write_new_file(str(tmp_path / "adir"), b"x", force=force)


@pytest.mark.requires_symlinks
def test_a_link_target_is_refused_even_with_force_and_the_link_target_is_untouched(
    tmp_path: Path,
) -> None:
    victim = tmp_path / "victim"
    victim.write_bytes(b"victim data")
    os.symlink(victim, tmp_path / "out")
    for force in (False, True):
        with pytest.raises(ScanIOError, match="link or reparse point"):
            write_new_file(str(tmp_path / "out"), b"attack", force=force)
    assert victim.read_bytes() == b"victim data"
    assert listing(tmp_path) == ["isolated-home", "out", "victim"]


@pytest.mark.requires_symlinks
def test_a_link_planted_after_the_check_is_replaced_not_followed(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    victim = tmp_path / "victim"
    victim.write_bytes(b"victim data")
    target = tmp_path / "out"

    def plant(path: str, *, force: bool) -> None:
        os.symlink(victim, path)  # the race: the link appears right after the check passed

    monkeypatch.setattr(safe_files, "check_output_target", plant)
    write_new_file(str(target), b"report", force=True)
    assert victim.read_bytes() == b"victim data"  # never written through
    assert target.read_bytes() == b"report"
    assert not target.is_symlink()


def test_a_target_created_after_the_check_is_not_clobbered_without_force(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    target = tmp_path / "out"

    def create(path: str, *, force: bool) -> None:
        Path(path).write_bytes(b"won the race")

    monkeypatch.setattr(safe_files, "check_output_target", create)
    with pytest.raises(ScanIOError, match="already exists"):
        write_new_file(str(target), b"loser")
    assert target.read_bytes() == b"won the race"
    assert listing(tmp_path) == ["isolated-home", "out"]


def test_a_failed_write_leaves_neither_temporary_nor_a_changed_target(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    target = tmp_path / "out"
    target.write_bytes(b"old")

    def failing_fsync(descriptor: int) -> None:
        raise OSError(errno.ENOSPC, "disk full")

    monkeypatch.setattr(os, "fsync", failing_fsync)
    with pytest.raises(ScanIOError, match=r"cannot be written \(ENOSPC\)"):
        write_new_file(str(target), b"new", force=True)
    assert target.read_bytes() == b"old"
    assert listing(tmp_path) == ["isolated-home", "out"]


def test_a_failure_to_publish_is_reported_and_cleaned_up(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    def refuse(source: str, destination: str) -> None:
        raise PermissionError(errno.EACCES, "denied")

    monkeypatch.setattr(os, "replace", refuse)
    with pytest.raises(ScanIOError, match=r"cannot be written \(EACCES\)"):
        write_new_file(str(tmp_path / "out"), b"x", force=True)
    assert listing(tmp_path) == ["isolated-home"]


def test_a_failure_to_create_the_temporary_is_reported(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    def refuse(path: str, flags: int, mode: int = 0o777) -> int:
        raise PermissionError(errno.EACCES, "denied")

    monkeypatch.setattr(os, "open", refuse)
    with pytest.raises(ScanIOError, match=r"cannot be created \(EACCES\)"):
        write_new_file(str(tmp_path / "out"), b"x")


def test_a_lstat_error_on_the_target_is_reported(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    def failing(path: str) -> os.stat_result:
        raise OSError(errno.EIO, "io")

    monkeypatch.setattr(os, "lstat", failing)
    with pytest.raises(ScanIOError, match=r"cannot be examined \(EIO\)"):
        write_new_file(str(tmp_path / "out"), b"x")


def test_the_error_message_is_sanitised(tmp_path: Path) -> None:
    with pytest.raises(ScanIOError) as caught:
        write_new_file(str(tmp_path / ("nope" + chr(0x1B) + "[31m") / "out"), b"x")
    assert chr(0x1B) not in str(caught.value)


def test_a_large_write_is_complete(tmp_path: Path) -> None:
    data = bytes(range(256)) * 20_000
    write_new_file(str(tmp_path / "big"), data)
    assert (tmp_path / "big").read_bytes() == data


def test_the_directory_flush_is_best_effort(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    real_open = os.open

    def selective(path: str, flags: int, mode: int = 0o777) -> int:
        if path == str(tmp_path):  # the directory flush, on POSIX
            raise OSError(errno.EACCES, "no")
        return real_open(path, flags, mode)

    monkeypatch.setattr(os, "open", selective)
    write_new_file(str(tmp_path / "out"), b"x")
    assert (tmp_path / "out").read_bytes() == b"x"


@pytest.mark.posix_only
def test_a_failing_directory_fsync_is_ignored(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    real_fsync = os.fsync
    calls: list[int] = []

    def flaky(descriptor: int) -> None:
        calls.append(descriptor)
        if len(calls) == 2:  # the first call is the file, the second the directory
            raise OSError(errno.EINVAL, "not supported")
        real_fsync(descriptor)

    monkeypatch.setattr(os, "fsync", flaky)
    write_new_file(str(tmp_path / "out"), b"x")
    assert len(calls) == 2


# -- is_inside --------------------------------------------------------------------------------


def test_is_inside(tmp_path: Path) -> None:
    root = tmp_path / "tree"
    (root / "sub").mkdir(parents=True)
    (tmp_path / "tree-sibling").mkdir()
    assert is_inside(str(root), str(root / "sub" / "out.json"))
    assert is_inside(str(root), str(root / "not-created-yet" / "out.json"))
    assert is_inside(str(root), str(root))
    assert not is_inside(str(root), str(tmp_path / "out.json"))
    assert not is_inside(str(root), str(tmp_path / "tree-sibling" / "out.json"))  # not a prefix


def test_is_inside_resolves_dot_dot_segments(tmp_path: Path) -> None:
    root = tmp_path / "tree"
    (root / "sub").mkdir(parents=True)
    assert is_inside(str(root), str(root / "sub" / ".." / "out.json"))
    assert not is_inside(str(root), str(root / ".." / "out.json"))


@pytest.mark.requires_symlinks
def test_is_inside_resolves_links(tmp_path: Path) -> None:
    root = tmp_path / "tree"
    root.mkdir()
    outside = tmp_path / "outside"
    outside.mkdir()
    os.symlink(root, outside / "into-tree", target_is_directory=True)
    assert is_inside(str(root), str(outside / "into-tree" / "out.json"))


def test_is_inside_with_paths_on_different_drives_is_false(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    def raising(paths: object) -> str:
        raise ValueError("Paths don't have the same drive")

    monkeypatch.setattr(os.path, "commonpath", raising)
    assert not is_inside(str(tmp_path), str(tmp_path / "x"))
