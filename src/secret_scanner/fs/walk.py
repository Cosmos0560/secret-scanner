"""The ONLY reader of scanned files (PLAN.md section 1.3, CLAUDE.md section 5 invariants 3, 6, 8).

Read-only by construction: this module contains no write or mutate API (the architecture checker
enforces it). It walks a tree iteratively with sorted entries and never follows a link:

* symbolic links, Windows junctions, mount points and other reparse points are recorded and
  skipped; cloud placeholders (offline or recall-on-access) are skipped because reading them
  would download them; FIFOs, sockets and devices are recorded and never opened;
* a regular file is opened read-only without following a final link (`O_NOFOLLOW`,
  `O_NONBLOCK`, `O_CLOEXEC` on POSIX, `O_BINARY` on Windows), its descriptor is compared with
  the `lstat` taken a moment earlier (a mismatch is `unstable`), and at most `max_file_bytes`
  bytes are read: a larger file is `too_large`, never partially scanned and called clean;
* every bound of `Limits` that applies here (entries, depth, path length, file size, total
  bytes) produces a recorded problem and stops or skips; nothing is dropped silently.

The walker yields events; it neither interprets content nor decides what is a finding.
"""

from __future__ import annotations

import errno
import os
import stat
import sys
from collections.abc import Callable, Iterator
from dataclasses import dataclass
from enum import StrEnum

from secret_scanner.core.entries import EntryKind, classify_stat
from secret_scanner.core.errors import UsageError
from secret_scanner.core.globs import Glob, any_match
from secret_scanner.core.limits import DEFAULT_LIMITS, Limits
from secret_scanner.core.models import IssueKind
from secret_scanner.core.sanitize import sanitize, sanitize_path

DEFAULT_EXCLUDED_DIRECTORIES = frozenset(
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

READ_CHUNK_BYTES = 1024 * 1024
_SHOWN_PATH_CHARS = 120
_SHOWN_ISSUE_CHARS = 1_024  # an escaped path in an issue is bounded, however long the name


class SkipReason(StrEnum):
    SYMLINK = "symlink"  # symbolic links and Windows reparse points
    OFFLINE = "offline"
    SPECIAL = "special"
    EXCLUDED = "excluded"
    GITIGNORED = "gitignored"  # not in git's own list of tracked and not-ignored files


@dataclass(frozen=True, slots=True)
class FileContent:
    """A regular file read completely. `path_key` is the exact relative path with `/`."""

    path_key: str
    data: bytes


@dataclass(frozen=True, slots=True)
class Skipped:
    path_key: str
    reason: SkipReason


@dataclass(frozen=True, slots=True)
class Problem:
    """Something that makes the run incomplete. `path` is escaped for display, or None for a
    tree-wide limit; `detail` is a fixed sentence plus at most an errno name, never content."""

    path: str | None
    kind: IssueKind
    detail: str


WalkEvent = FileContent | Skipped | Problem


@dataclass(frozen=True, slots=True)
class ReadFailure:
    """A file that could not be read completely, as the reader reports it."""

    kind: IssueKind
    detail: str


Reader = Callable[[str, os.stat_result, int], bytes | ReadFailure]


@dataclass(frozen=True, slots=True)
class WalkOptions:
    limits: Limits = DEFAULT_LIMITS
    excluded_directory_names: frozenset[str] = DEFAULT_EXCLUDED_DIRECTORIES
    exclude_globs: tuple[Glob, ...] = ()
    # With `scan --gitignore` (PLAN.md D13): the `/` paths git listed. Only these files are read;
    # a directory that holds none of them is not entered. The walker still does all the walking,
    # type checking and limiting; git's list is a filter only.
    only_paths: frozenset[str] | None = None


@dataclass(slots=True)
class WalkCounters:
    """Filled in while walking: entries examined (files and directories), bytes read."""

    entries: int = 0
    bytes_read: int = 0


def directories_of(paths: frozenset[str]) -> frozenset[str]:
    """Every directory prefix (`a`, `a/b`) of the given `/` paths."""
    found: set[str] = set()
    for path in paths:
        position = path.find("/")
        while position >= 0:
            found.add(path[:position])
            position = path.find("/", position + 1)
    return frozenset(found)


def _errno_name(error: OSError) -> str:
    return errno.errorcode.get(error.errno or 0, "unknown")


def _failure_for(error: OSError, action: str) -> ReadFailure:
    """Map an OSError to an issue kind with a fixed sentence (never the message, which can hold
    the path or other text)."""
    if isinstance(error, FileNotFoundError):
        return ReadFailure(IssueKind.VANISHED, f"{action}: no longer exists")
    if isinstance(error, PermissionError):
        return ReadFailure(IssueKind.UNREADABLE, f"{action}: permission denied")
    if error.errno == errno.ELOOP:
        return ReadFailure(IssueKind.UNSTABLE, f"{action}: became a link while scanning")
    return ReadFailure(IssueKind.UNREADABLE, f"{action}: {_errno_name(error)}")


def _open_flags() -> int:
    flags = os.O_RDONLY
    for name in ("O_BINARY", "O_NOFOLLOW", "O_NONBLOCK", "O_CLOEXEC"):
        flags |= getattr(os, name, 0)
    return flags


def _same_file(opened: os.stat_result, expected: os.stat_result) -> bool:
    if not stat.S_ISREG(opened.st_mode):
        return False
    if expected.st_ino and opened.st_ino:  # some file systems report no identity
        return (opened.st_dev, opened.st_ino) == (expected.st_dev, expected.st_ino)
    return True


def read_regular_file(path: str, expected: os.stat_result, max_bytes: int) -> bytes | ReadFailure:
    """Read one regular file completely, read-only and without following a final link.

    `expected` is the `lstat` taken earlier; the opened descriptor must be the same regular file.
    """
    flags = _open_flags()
    try:
        descriptor = os.open(path, flags | getattr(os, "O_NOATIME", 0))
    except PermissionError:
        # O_NOATIME is refused for a file the user does not own; try again without it.
        try:
            descriptor = os.open(path, flags)
        except OSError as error:
            return _failure_for(error, "open")
    except OSError as error:
        return _failure_for(error, "open")
    try:
        opened = os.fstat(descriptor)
        if not _same_file(opened, expected):
            return ReadFailure(IssueKind.UNSTABLE, "changed while scanning")
        if opened.st_size > max_bytes:
            return ReadFailure(IssueKind.TOO_LARGE, f"larger than the limit of {max_bytes} bytes")
        chunks: list[bytes] = []
        total = 0
        while total <= max_bytes:
            chunk = os.read(descriptor, min(READ_CHUNK_BYTES, max_bytes + 1 - total))
            if not chunk:
                break
            chunks.append(chunk)
            total += len(chunk)
        if total > max_bytes:
            return ReadFailure(IssueKind.TOO_LARGE, f"larger than the limit of {max_bytes} bytes")
        if total != opened.st_size:
            return ReadFailure(IssueKind.UNSTABLE, "size changed while reading")
        return b"".join(chunks)
    except OSError as error:
        return _failure_for(error, "read")
    finally:
        os.close(descriptor)


def check_scan_root(root: str) -> None:
    """Refuse a scan root that is not a real directory. A link as the last component is refused
    rather than followed, so the tree that is scanned is the one that was named."""
    shown = sanitize_path(root, windows=sys.platform == "win32", max_chars=_SHOWN_PATH_CHARS)
    try:
        info = os.lstat(root)
    except FileNotFoundError:
        raise UsageError(f"scan path does not exist: {shown}") from None
    except OSError as error:
        raise UsageError(f"scan path cannot be examined ({_errno_name(error)}): {shown}") from None
    kind = classify_stat(info, windows=sys.platform == "win32")
    if kind in {EntryKind.SYMLINK, EntryKind.REPARSE_POINT}:
        raise UsageError(f"scan path is a link or reparse point; pass the real directory: {shown}")
    if kind is EntryKind.OFFLINE:
        raise UsageError(f"scan path is an offline placeholder: {shown}")
    if kind is not EntryKind.DIRECTORY:
        raise UsageError(f"scan path is not a directory: {shown}")


def _list_directory(path: str) -> list[str] | ReadFailure:
    try:
        with os.scandir(path) as listing:
            return sorted(entry.name for entry in listing)
    except OSError as error:
        return _failure_for(error, "list directory")


def walk_tree(
    root: str,
    options: WalkOptions,
    counters: WalkCounters,
    reader: Reader = read_regular_file,
) -> Iterator[WalkEvent]:
    """Yield the files of `root` (a directory path, already checked by `check_scan_root`).

    Entries are visited in sorted order, depth first. Reaching `max_files` or `max_total_bytes`
    yields a `Problem` and ends the walk; the other limits skip the entry that hit them.
    """
    limits = options.limits
    windows = sys.platform == "win32"
    only_files = options.only_paths
    only_directories = directories_of(only_files) if only_files is not None else frozenset()
    # Each frame: (absolute directory path, key parts of the directory, remaining names)
    stack: list[tuple[str, tuple[str, ...], Iterator[str]]] = []
    listing = _list_directory(root)
    if isinstance(listing, ReadFailure):
        yield Problem(None, listing.kind, listing.detail)
        return
    stack.append((root, (), iter(listing)))
    while stack:
        directory, parts, names = stack[-1]
        name = next(names, None)
        if name is None:
            stack.pop()
            continue
        counters.entries += 1
        if counters.entries > limits.max_files:
            yield Problem(
                None, IssueKind.LIMIT_REACHED, f"more than {limits.max_files} entries; stopped"
            )
            return
        key_parts = (*parts, name)
        path_key = "/".join(key_parts)
        shown = sanitize(path_key, max_chars=_SHOWN_ISSUE_CHARS)
        if len(path_key) > limits.max_path_chars:
            yield Problem(
                shown,
                IssueKind.LIMIT_REACHED,
                f"path longer than {limits.max_path_chars} characters; skipped",
            )
            continue
        path = os.path.join(directory, name)
        try:
            info = os.lstat(path)
        except OSError as error:
            failure = _failure_for(error, "stat")
            yield Problem(shown, failure.kind, failure.detail)
            continue
        kind = classify_stat(info, windows=windows)
        if kind is EntryKind.DIRECTORY:
            if name in options.excluded_directory_names or any_match(
                options.exclude_globs, path_key
            ):
                yield Skipped(path_key, SkipReason.EXCLUDED)
                continue
            if only_files is not None and path_key not in only_directories:
                yield Skipped(path_key, SkipReason.GITIGNORED)
                continue
            if len(key_parts) > limits.max_depth:
                yield Problem(
                    shown,
                    IssueKind.LIMIT_REACHED,
                    f"deeper than {limits.max_depth} levels; not entered",
                )
                continue
            children = _list_directory(path)
            if isinstance(children, ReadFailure):
                yield Problem(shown, children.kind, children.detail)
                continue
            stack.append((path, key_parts, iter(children)))
        elif kind is EntryKind.REGULAR:
            if only_files is not None and path_key not in only_files:
                yield Skipped(path_key, SkipReason.GITIGNORED)
                continue
            if any_match(options.exclude_globs, path_key):
                yield Skipped(path_key, SkipReason.EXCLUDED)
                continue
            outcome = reader(path, info, limits.max_file_bytes)
            if isinstance(outcome, ReadFailure):
                yield Problem(shown, outcome.kind, outcome.detail)
                continue
            counters.bytes_read += len(outcome)
            if counters.bytes_read > limits.max_total_bytes:
                yield Problem(
                    None,
                    IssueKind.LIMIT_REACHED,
                    f"more than {limits.max_total_bytes} bytes read; stopped",
                )
                return
            yield FileContent(path_key, outcome)
        elif kind in {EntryKind.SYMLINK, EntryKind.REPARSE_POINT}:
            yield Skipped(path_key, SkipReason.SYMLINK)
        elif kind is EntryKind.OFFLINE:
            yield Skipped(path_key, SkipReason.OFFLINE)
        else:
            yield Skipped(path_key, SkipReason.SPECIAL)


# -- the layout of a git repository (PLAN.md D2: nothing outside the repository is followed) -----


class GitDirKind(StrEnum):
    STANDARD = "standard"  # `.git` is a directory
    BARE = "bare"  # the path itself is a git directory
    LINK_FILE = "link_file"  # `.git` is a file (`gitdir: ...`: a worktree or a submodule)
    LINK = "link"  # `.git` is a symbolic link or reparse point
    MISSING = "missing"  # neither


@dataclass(frozen=True, slots=True)
class RepositoryLayout:
    """Facts about a repository directory that git itself would act on silently: where its git
    directory is, whether it borrows objects from another place (`objects/info/alternates`) and
    whether it rewrites history with a grafts file (`info/grafts`). All read with `lstat` and
    bounded reads; nothing is followed or changed."""

    kind: GitDirKind
    git_dir: str | None  # the repository's own git directory (STANDARD, BARE)
    alternates: bool
    grafts: bool


_LAYOUT_READ_BYTES = 64 * 1024


def _has_entry_lines(path: str) -> bool:
    """True when the file at `path` holds a line that is not blank and not a comment. A link or a
    non-regular file counts as present: it is never read."""
    try:
        info = os.lstat(path)
    except OSError:
        return False
    kind = classify_stat(info, windows=sys.platform == "win32")
    if kind is not EntryKind.REGULAR:
        return True
    try:
        descriptor = os.open(path, _open_flags())
    except OSError:
        return True  # cannot be read: assume it matters
    try:
        data = os.read(descriptor, _LAYOUT_READ_BYTES + 1)
    except OSError:
        return True
    finally:
        os.close(descriptor)
    if len(data) > _LAYOUT_READ_BYTES:
        return True
    return any(line.strip() and not line.lstrip().startswith(b"#") for line in data.split(b"\n"))


def _kind_at(path: str) -> EntryKind | None:
    try:
        info = os.lstat(path)
    except OSError:
        return None
    return classify_stat(info, windows=sys.platform == "win32")


def inspect_repository(root: str) -> RepositoryLayout:
    """Examine `root`, a directory already checked by `check_scan_root`."""
    dot_git = os.path.join(root, ".git")
    kind = _kind_at(dot_git)
    git_dir: str | None
    if kind is EntryKind.DIRECTORY:
        layout, git_dir = GitDirKind.STANDARD, dot_git
    elif kind in {EntryKind.SYMLINK, EntryKind.REPARSE_POINT}:
        return RepositoryLayout(GitDirKind.LINK, None, False, False)
    elif kind is not None:
        return RepositoryLayout(GitDirKind.LINK_FILE, None, False, False)
    elif (
        _kind_at(os.path.join(root, "HEAD")) is EntryKind.REGULAR
        and _kind_at(os.path.join(root, "objects")) is EntryKind.DIRECTORY
        and _kind_at(os.path.join(root, "refs")) is EntryKind.DIRECTORY
    ):
        layout, git_dir = GitDirKind.BARE, root
    else:
        return RepositoryLayout(GitDirKind.MISSING, None, False, False)
    alternates = _has_entry_lines(os.path.join(git_dir, "objects", "info", "alternates"))
    alternates = alternates or _has_entry_lines(
        os.path.join(git_dir, "objects", "info", "http-alternates")
    )
    grafts = _has_entry_lines(os.path.join(git_dir, "info", "grafts"))
    return RepositoryLayout(layout, os.path.abspath(git_dir), alternates, grafts)


def same_directory(first: str, second: str) -> bool:
    """True when both names resolve to one directory (case and links resolved)."""
    return os.path.normcase(os.path.realpath(first)) == os.path.normcase(os.path.realpath(second))
