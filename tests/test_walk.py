"""The walker (PLAN.md section 1.3, CLAUDE.md section 5 invariants 3, 6, 8): regular files only,
no link is followed, every limit is a recorded problem, and a file that changes mid-read is never
trusted. Temporary trees only."""

from __future__ import annotations

import errno
import os
import subprocess
import sys
import types
from collections.abc import Iterable
from pathlib import Path

import pytest

from secret_scanner.core.entries import FILE_ATTRIBUTE_RECALL_ON_DATA_ACCESS, EntryKind
from secret_scanner.core.errors import UsageError
from secret_scanner.core.globs import compile_globs
from secret_scanner.core.limits import DEFAULT_LIMITS, Limits
from secret_scanner.core.models import IssueKind
from secret_scanner.fs import walk
from secret_scanner.fs.walk import (
    DEFAULT_EXCLUDED_DIRECTORIES,
    FileContent,
    Problem,
    ReadFailure,
    Skipped,
    SkipReason,
    WalkCounters,
    WalkEvent,
    WalkOptions,
    check_scan_root,
    read_regular_file,
    walk_tree,
)

Tree = dict[str, str | bytes]


@pytest.fixture
def root(tmp_path: Path) -> Path:
    """An empty tree to walk. (`tmp_path` itself also holds the isolated home directory.)"""
    directory = tmp_path / "tree"
    directory.mkdir()
    return directory


def make_tree(root: Path, tree: Tree) -> Path:
    for relative, content in tree.items():
        path = root / relative
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(content if isinstance(content, bytes) else content.encode("utf-8"))
    return root


def run(
    root: Path,
    *,
    limits: Limits = DEFAULT_LIMITS,
    excluded: frozenset[str] = DEFAULT_EXCLUDED_DIRECTORIES,
    globs: Iterable[str] = (),
    reader: walk.Reader = read_regular_file,
) -> tuple[list[WalkEvent], WalkCounters]:
    counters = WalkCounters()
    options = WalkOptions(
        limits=limits, excluded_directory_names=excluded, exclude_globs=compile_globs(globs)
    )
    return list(walk_tree(str(root), options, counters, reader)), counters


def contents(events: Iterable[WalkEvent]) -> dict[str, bytes]:
    return {e.path_key: e.data for e in events if isinstance(e, FileContent)}


def skipped(events: Iterable[WalkEvent]) -> dict[str, SkipReason]:
    return {e.path_key: e.reason for e in events if isinstance(e, Skipped)}


def problems(events: Iterable[WalkEvent]) -> list[Problem]:
    return [e for e in events if isinstance(e, Problem)]


# -- ordinary trees ---------------------------------------------------------------------------


def test_regular_empty_hidden_and_nested_files_are_read_in_sorted_order(root: Path) -> None:
    make_tree(
        root,
        {".env": "k=v", "a.txt": "a", "empty": "", "d/e/f.txt": "deep", "z/inner.txt": "z"},
    )
    events, counters = run(root)
    assert [e.path_key for e in events if isinstance(e, FileContent)] == [
        ".env",
        "a.txt",
        "d/e/f.txt",
        "empty",
        "z/inner.txt",
    ]
    assert contents(events)["empty"] == b""
    assert contents(events)["d/e/f.txt"] == b"deep"
    assert problems(events) == []
    assert counters.entries == 8  # 5 files and the directories d, d/e and z
    assert counters.bytes_read == 3 + 1 + 0 + 4 + 1


def test_an_empty_directory_yields_nothing(root: Path) -> None:
    events, counters = run(root)
    assert events == []
    assert counters.entries == 0


def test_default_excluded_directories_are_recorded_and_not_entered(root: Path) -> None:
    tree: Tree = {f"{name}/inside.txt": "x" for name in sorted(DEFAULT_EXCLUDED_DIRECTORIES)}
    tree["kept.txt"] = "k"
    make_tree(root, tree)
    seen: list[str] = []

    def counting_reader(path: str, info: os.stat_result, maximum: int) -> bytes | ReadFailure:
        seen.append(Path(path).name)
        return read_regular_file(path, info, maximum)

    events, _ = run(root, reader=counting_reader)
    assert set(skipped(events)) == set(DEFAULT_EXCLUDED_DIRECTORIES)
    assert set(skipped(events).values()) == {SkipReason.EXCLUDED}
    assert list(contents(events)) == ["kept.txt"]
    assert seen == ["kept.txt"]  # nothing inside an excluded directory was opened


def test_default_excludes_apply_at_any_depth_but_only_to_directories(root: Path) -> None:
    make_tree(root, {"a/b/node_modules/x.js": "x", "node_modules": "a file with that name"})
    events, _ = run(root)
    assert list(contents(events)) == ["node_modules"]
    assert skipped(events) == {"a/b/node_modules": SkipReason.EXCLUDED}


def test_default_excludes_can_be_turned_off(root: Path) -> None:
    make_tree(root, {".git/config": "c", "node_modules/m.js": "m"})
    events, _ = run(root, excluded=frozenset())
    assert set(contents(events)) == {".git/config", "node_modules/m.js"}


def test_config_globs_exclude_directories_and_files(root: Path) -> None:
    make_tree(
        root,
        {
            "build/out.txt": "o",
            "src/app.py": "a",
            "src/debug.log": "l",
            "root.log": "r",
            "docs/x.md": "m",
        },
    )
    events, _ = run(root, globs=["build/**", "**/*.log"])
    assert set(contents(events)) == {"src/app.py", "docs/x.md"}
    assert skipped(events) == {
        "build": SkipReason.EXCLUDED,
        "src/debug.log": SkipReason.EXCLUDED,
        "root.log": SkipReason.EXCLUDED,
    }


# -- links, junctions and special files -------------------------------------------------------


@pytest.mark.requires_symlinks
def test_symlinks_are_recorded_and_never_followed(tmp_path: Path) -> None:
    outside = make_tree(tmp_path / "outside", {"secret.txt": "outside", "d/inner.txt": "inner"})
    root = make_tree(tmp_path / "root", {"real.txt": "real"})
    os.symlink(outside / "secret.txt", root / "file-link")
    os.symlink(outside / "d", root / "dir-link", target_is_directory=True)
    os.symlink(root / "does-not-exist", root / "dangling")
    os.symlink(root, root / "loop", target_is_directory=True)
    events, _ = run(root)
    assert list(contents(events)) == ["real.txt"]
    assert skipped(events) == {
        "dangling": SkipReason.SYMLINK,
        "dir-link": SkipReason.SYMLINK,
        "file-link": SkipReason.SYMLINK,
        "loop": SkipReason.SYMLINK,
    }
    assert problems(events) == []


@pytest.mark.windows_only
def test_a_junction_is_not_traversed(tmp_path: Path) -> None:
    outside = make_tree(tmp_path / "outside", {"secret.txt": "outside"})
    root = make_tree(tmp_path / "root", {"real.txt": "real"})
    link = root / "junction"
    result = subprocess.run(
        ["cmd", "/c", "mklink", "/J", str(link), str(outside)],
        capture_output=True,
        text=True,
        check=False,
    )
    assert result.returncode == 0, "mklink /J failed"
    events, _ = run(root)
    assert list(contents(events)) == ["real.txt"]
    assert skipped(events) == {"junction": SkipReason.SYMLINK}


@pytest.mark.posix_only
def test_fifos_are_recorded_and_never_opened(tmp_path: Path) -> None:
    make_tree(tmp_path, {"a.txt": "a"})
    os.mkfifo(tmp_path / "pipe")  # type: ignore[attr-defined, unused-ignore]  # reason: POSIX only
    events, _ = run(tmp_path)  # opening the FIFO for reading would block forever
    assert list(contents(events)) == ["a.txt"]
    assert skipped(events) == {"pipe": SkipReason.SPECIAL}


def test_an_offline_placeholder_is_skipped_not_read(
    root: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    make_tree(root, {"cloud.txt": "c", "local.txt": "l"})
    original_lstat = os.lstat

    class Placeholder:
        """An lstat result as Windows reports a cloud placeholder: a regular file with the
        recall-on-data-access attribute."""

        def __init__(self, info: os.stat_result) -> None:
            self.st_mode = info.st_mode
            self.st_file_attributes = FILE_ATTRIBUTE_RECALL_ON_DATA_ACCESS

    def fake_lstat(path: str) -> object:
        info = original_lstat(path)
        return Placeholder(info) if str(path).endswith("cloud.txt") else info

    monkeypatch.setattr(os, "lstat", fake_lstat)
    # Interpret the attribute bits as the Windows build of the walker does.
    monkeypatch.setattr(walk, "sys", types.SimpleNamespace(platform="win32"))
    events, _ = run(root)
    assert skipped(events) == {"cloud.txt": SkipReason.OFFLINE}
    assert list(contents(events)) == ["local.txt"]


# -- unreadable, vanished, swapped ------------------------------------------------------------


@pytest.mark.posix_only
def test_an_unreadable_file_is_a_problem_unless_we_are_root(tmp_path: Path) -> None:
    make_tree(tmp_path, {"locked.txt": "x", "ok.txt": "y"})
    (tmp_path / "locked.txt").chmod(0)
    try:
        events, _ = run(tmp_path)
    finally:
        (tmp_path / "locked.txt").chmod(0o600)
    # root reads it: the same tree, the opposite (and also asserted) result
    if os.geteuid() == 0:  # type: ignore[attr-defined, unused-ignore]  # reason: POSIX only
        assert set(contents(events)) == {"locked.txt", "ok.txt"}
    else:
        assert list(contents(events)) == ["ok.txt"]
        [problem] = problems(events)
        assert (problem.path, problem.kind) == ("locked.txt", IssueKind.UNREADABLE)
        assert problem.detail == "open: permission denied"


def test_a_file_that_vanishes_before_it_is_opened_is_a_problem(root: Path) -> None:
    make_tree(root, {"gone.txt": "x", "kept.txt": "y"})

    def vanishing(path: str, info: os.stat_result, maximum: int) -> bytes | ReadFailure:
        if path.endswith("gone.txt"):
            os.unlink(path)
        return read_regular_file(path, info, maximum)

    events, _ = run(root, reader=vanishing)
    assert list(contents(events)) == ["kept.txt"]
    [problem] = problems(events)
    assert (problem.path, problem.kind) == ("gone.txt", IssueKind.VANISHED)


def test_a_file_replaced_by_another_file_before_it_is_opened_is_unstable(tmp_path: Path) -> None:
    make_tree(tmp_path, {"swap.txt": "original", "spare/other.txt": "other"})

    def swapping(path: str, info: os.stat_result, maximum: int) -> bytes | ReadFailure:
        if path.endswith("swap.txt"):
            os.unlink(path)
            os.replace(tmp_path / "spare" / "other.txt", path)
        return read_regular_file(path, info, maximum)

    events, _ = run(tmp_path, reader=swapping)
    assert "swap.txt" not in contents(events)
    assert [(p.path, p.kind) for p in problems(events)] == [("swap.txt", IssueKind.UNSTABLE)]


@pytest.mark.requires_symlinks
def test_a_file_replaced_by_a_link_before_it_is_opened_is_never_followed(tmp_path: Path) -> None:
    outside = make_tree(tmp_path / "outside", {"secret.txt": "outside secret"})
    root = make_tree(tmp_path / "root", {"swap.txt": "original"})

    def swapping(path: str, info: os.stat_result, maximum: int) -> bytes | ReadFailure:
        os.unlink(path)
        os.symlink(outside / "secret.txt", path)
        return read_regular_file(path, info, maximum)

    events, _ = run(root, reader=swapping)
    assert contents(events) == {}  # the outside content never reaches the caller
    assert [(p.path, p.kind) for p in problems(events)] == [("swap.txt", IssueKind.UNSTABLE)]


def test_a_file_replaced_by_a_directory_before_it_is_opened_is_a_problem(root: Path) -> None:
    make_tree(root, {"swap.txt": "original"})

    def swapping(path: str, info: os.stat_result, maximum: int) -> bytes | ReadFailure:
        os.unlink(path)
        os.mkdir(path)
        return read_regular_file(path, info, maximum)

    events, _ = run(root, reader=swapping)
    assert contents(events) == {}
    [problem] = problems(events)
    # POSIX opens a directory read-only and notices the type; Windows refuses the open.
    expected = IssueKind.UNREADABLE if sys.platform == "win32" else IssueKind.UNSTABLE
    assert (problem.path, problem.kind) == ("swap.txt", expected)


def test_a_file_whose_size_changes_while_it_is_read_is_unstable(
    root: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    path = make_tree(root, {"grow.txt": "12345"}) / "grow.txt"
    expected = os.lstat(path)
    real_fstat = os.fstat

    def lying_fstat(descriptor: int) -> os.stat_result:
        info = real_fstat(descriptor)
        fields = list(info)[:10]
        fields[6] += 3  # st_size
        return os.stat_result(fields)

    monkeypatch.setattr(os, "fstat", lying_fstat)
    outcome = read_regular_file(str(path), expected, 1024)
    assert outcome == ReadFailure(IssueKind.UNSTABLE, "size changed while reading")


def test_an_os_error_while_reading_is_a_problem_with_the_errno_name_only(
    root: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    path = make_tree(root, {"io.txt": "data"}) / "io.txt"
    expected = os.lstat(path)

    def failing_read(descriptor: int, count: int) -> bytes:
        raise OSError(errno.EIO, "secret detail that must not be shown")

    monkeypatch.setattr(os, "read", failing_read)
    outcome = read_regular_file(str(path), expected, 1024)
    assert outcome == ReadFailure(IssueKind.UNREADABLE, "read: EIO")


def test_errno_mapping() -> None:
    cases = [
        (FileNotFoundError(errno.ENOENT, "x"), IssueKind.VANISHED),
        (PermissionError(errno.EACCES, "x"), IssueKind.UNREADABLE),
        (OSError(errno.ELOOP, "x"), IssueKind.UNSTABLE),
        (OSError(errno.EIO, "x"), IssueKind.UNREADABLE),
        (OSError(), IssueKind.UNREADABLE),
    ]
    for error, kind in cases:
        assert walk._failure_for(error, "act").kind is kind
    assert walk._failure_for(OSError(), "act").detail == "act: unknown"


# -- size and every limit ---------------------------------------------------------------------


def test_the_file_size_limit_is_exact_and_a_larger_file_is_never_partly_scanned(
    root: Path,
) -> None:
    limits = DEFAULT_LIMITS.with_overrides({"max_file_bytes": 10})
    make_tree(root, {"exact.txt": b"x" * 10, "over.txt": b"x" * 11, "huge.txt": b"x" * 5000})
    events, _ = run(root, limits=limits)
    assert contents(events) == {"exact.txt": b"x" * 10}
    assert [(p.path, p.kind) for p in problems(events)] == [
        ("huge.txt", IssueKind.TOO_LARGE),
        ("over.txt", IssueKind.TOO_LARGE),
    ]


def test_a_file_that_grew_past_the_limit_after_the_size_check_is_too_large(
    root: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    path = make_tree(root, {"g.txt": b"x" * 40}) / "g.txt"
    expected = os.lstat(path)
    real_fstat = os.fstat

    def understated(descriptor: int) -> os.stat_result:
        fields = list(real_fstat(descriptor))[:10]
        fields[6] = 5  # claims 5 bytes; 40 are there
        return os.stat_result(fields)

    monkeypatch.setattr(os, "fstat", understated)
    assert read_regular_file(str(path), expected, 10) == ReadFailure(
        IssueKind.TOO_LARGE, "larger than the limit of 10 bytes"
    )


def test_the_entry_limit_stops_the_walk_with_a_problem(root: Path) -> None:
    limits = DEFAULT_LIMITS.with_overrides({"max_files": 3})
    make_tree(root, {f"f{n}.txt": "x" for n in range(6)})
    events, counters = run(root, limits=limits)
    assert list(contents(events)) == ["f0.txt", "f1.txt", "f2.txt"]
    [problem] = problems(events)
    assert (problem.path, problem.kind) == (None, IssueKind.LIMIT_REACHED)
    assert events[-1] is problem
    assert counters.entries == 4


def test_directories_count_toward_the_entry_limit(root: Path) -> None:
    limits = DEFAULT_LIMITS.with_overrides({"max_files": 2})
    make_tree(root, {"d1/a.txt": "x", "d2/b.txt": "x"})
    events, _ = run(root, limits=limits)
    assert [p.kind for p in problems(events)] == [IssueKind.LIMIT_REACHED]


def test_the_depth_limit_skips_the_deeper_directory_with_a_problem(root: Path) -> None:
    limits = DEFAULT_LIMITS.with_overrides({"max_depth": 2})
    make_tree(root, {"a/b/ok.txt": "x", "a/b/c/deep.txt": "x", "top.txt": "x"})
    events, _ = run(root, limits=limits)
    assert set(contents(events)) == {"a/b/ok.txt", "top.txt"}
    [problem] = problems(events)
    assert (problem.path, problem.kind) == ("a/b/c", IssueKind.LIMIT_REACHED)
    assert "deeper than 2 levels" in problem.detail


def test_the_path_length_limit_skips_the_entry_with_a_problem(root: Path) -> None:
    limits = DEFAULT_LIMITS.with_overrides({"max_path_chars": 12})
    make_tree(root, {"short.txt": "x", "a-rather-long-name.txt": "x"})
    events, _ = run(root, limits=limits)
    assert list(contents(events)) == ["short.txt"]
    [problem] = problems(events)
    assert problem.kind is IssueKind.LIMIT_REACHED
    assert problem.path is not None
    assert "longer than 12 characters" in problem.detail


def test_the_total_byte_limit_stops_the_walk(root: Path) -> None:
    limits = DEFAULT_LIMITS.with_overrides({"max_total_bytes": 15})
    make_tree(root, {"a.txt": b"x" * 10, "b.txt": b"x" * 10, "c.txt": b"x" * 2})
    events, counters = run(root, limits=limits)
    assert list(contents(events)) == ["a.txt"]  # b.txt crossed the limit and is not delivered
    assert [(p.path, p.kind) for p in problems(events)] == [(None, IssueKind.LIMIT_REACHED)]
    assert counters.bytes_read == 20


# -- listing and stat failures ----------------------------------------------------------------


def test_a_directory_that_cannot_be_listed_is_a_problem_and_the_walk_continues(
    root: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    make_tree(root, {"locked/x.txt": "x", "ok/y.txt": "y"})
    real = os.scandir

    def scandir(path: str) -> object:
        if str(path).endswith("locked"):
            raise PermissionError(errno.EACCES, "no")
        return real(path)

    monkeypatch.setattr(os, "scandir", scandir)
    events, _ = run(root)
    assert list(contents(events)) == ["ok/y.txt"]
    assert [(p.path, p.kind) for p in problems(events)] == [("locked", IssueKind.UNREADABLE)]


def test_an_unlistable_root_is_a_tree_wide_problem(
    root: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    def scandir(path: str) -> object:
        raise FileNotFoundError(errno.ENOENT, "gone")

    monkeypatch.setattr(os, "scandir", scandir)
    events, _ = run(root)
    assert [(p.path, p.kind) for p in problems(events)] == [(None, IssueKind.VANISHED)]


def test_an_lstat_failure_on_one_entry_is_a_problem_and_the_walk_continues(
    root: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    make_tree(root, {"bad.txt": "x", "good.txt": "y"})
    real = os.lstat

    def lstat(path: str) -> os.stat_result:
        if str(path).endswith("bad.txt"):
            raise OSError(errno.EIO, "io")
        return real(path)

    monkeypatch.setattr(os, "lstat", lstat)
    events, _ = run(root)
    assert list(contents(events)) == ["good.txt"]
    [problem] = problems(events)
    assert (problem.path, problem.kind, problem.detail) == (
        "bad.txt",
        IssueKind.UNREADABLE,
        "stat: EIO",
    )


# -- hostile names ----------------------------------------------------------------------------


def test_a_bidi_and_zero_width_name_is_exact_in_the_key_and_escaped_in_problems(
    root: Path,
) -> None:
    name = "a" + chr(0x202E) + "b" + chr(0x200B) + "c.txt"
    limits = DEFAULT_LIMITS.with_overrides({"max_file_bytes": 1})
    make_tree(root, {name: "x", "big" + chr(0x202E) + ".txt": b"xx"})
    events, _ = run(root, limits=limits)
    assert name in contents(events)  # the exact name is kept for fingerprints
    [problem] = problems(events)
    assert problem.path == "big\\u202e.txt"


@pytest.mark.posix_only
def test_control_characters_and_invalid_bytes_in_names_are_escaped_in_problems(
    tmp_path: Path,
) -> None:
    limits = DEFAULT_LIMITS.with_overrides({"max_file_bytes": 1})
    hostile = ["new\nline.txt", "esc" + chr(0x1B) + "[31m.txt", os.fsdecode(b"bad\xff.txt")]
    for name in hostile:
        (tmp_path / name).write_bytes(b"xx")
    events, _ = run(tmp_path, limits=limits)
    shown = sorted(p.path or "" for p in problems(events))
    assert shown == ["bad\\udcff.txt", "esc\\x1b[31m.txt", "new\\nline.txt"]
    assert all(
        "\n" not in text and chr(0x1B) not in text and chr(0xDCFF) not in text for text in shown
    )


# -- the scan root ----------------------------------------------------------------------------


def test_a_directory_is_an_acceptable_root(tmp_path: Path) -> None:
    check_scan_root(str(tmp_path))


def test_a_missing_root_a_file_root_are_refused(tmp_path: Path) -> None:
    with pytest.raises(UsageError, match="does not exist"):
        check_scan_root(str(tmp_path / "missing"))
    make_tree(tmp_path, {"file.txt": "x"})
    with pytest.raises(UsageError, match="not a directory"):
        check_scan_root(str(tmp_path / "file.txt"))


@pytest.mark.requires_symlinks
def test_a_link_as_the_root_is_refused_rather_than_followed(tmp_path: Path) -> None:
    make_tree(tmp_path / "real", {"a.txt": "x"})
    os.symlink(tmp_path / "real", tmp_path / "link", target_is_directory=True)
    with pytest.raises(UsageError, match="link or reparse point"):
        check_scan_root(str(tmp_path / "link"))


def test_an_offline_root_and_an_unexaminable_root_are_refused(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(walk, "classify_stat", lambda *a, **k: EntryKind.OFFLINE)
    with pytest.raises(UsageError, match="offline placeholder"):
        check_scan_root(str(tmp_path))

    def failing(path: str) -> os.stat_result:
        raise OSError(errno.EIO, "io")

    monkeypatch.setattr(os, "lstat", failing)
    with pytest.raises(UsageError, match="cannot be examined"):
        check_scan_root(str(tmp_path))


def test_the_root_error_message_is_sanitised(tmp_path: Path) -> None:
    with pytest.raises(UsageError) as caught:
        check_scan_root(str(tmp_path / ("x" + chr(0x1B) + "[31m")))
    assert chr(0x1B) not in str(caught.value)


def test_default_excluded_directories_match_the_plan() -> None:
    assert (
        frozenset(
            {
                ".git",
                ".hg",
                ".svn",
                "node_modules",
                ".venv",
                "venv",
                "__pycache__",
                ".tox",
                ".nox",
                ".mypy_cache",
                ".ruff_cache",
                ".pytest_cache",
            }
        )
        == DEFAULT_EXCLUDED_DIRECTORIES
    )
