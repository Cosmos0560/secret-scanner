"""The ONLY reader and writer of the tool's own files (PLAN.md section 1.4, CLAUDE.md section 5
invariants 9 and 10): configuration, rules and baseline are read here, reports and baselines are
written here.

Reading: the file must be a regular file and not a link or reparse point, is size-checked before
it is read, and the opened descriptor must be the file that was examined.

Writing: the data goes into a new temporary file next to the target (created exclusively, mode
0600, flushed to disk) and is then published with a single rename. Without `force` the publish
step fails if the target exists (a hard link on POSIX, a rename on Windows, both atomic and
no-clobber); with `force` it replaces the target. A target that is a symbolic link, a reparse
point, a directory or a special file is refused whatever `force` says, and because the final step
replaces the directory entry rather than writing through it, a link planted at the last moment is
replaced, never followed.
"""

from __future__ import annotations

import contextlib
import errno
import os
import stat
import sys
import tempfile
from collections.abc import Sequence

from secret_scanner.core.entries import EntryKind, classify_stat
from secret_scanner.core.errors import ScanIOError
from secret_scanner.core.sanitize import sanitize_path

_SHOWN_PATH_CHARS = 120
_TEMP_SUFFIX = ".tmp"


def _shown(path: str) -> str:
    return sanitize_path(path, windows=sys.platform == "win32", max_chars=_SHOWN_PATH_CHARS)


def _errno_name(error: OSError) -> str:
    return errno.errorcode.get(error.errno or 0, "unknown")


def _kind_of(info: os.stat_result) -> EntryKind:
    return classify_stat(info, windows=sys.platform == "win32")


def _read_flags() -> int:
    flags = os.O_RDONLY
    for name in ("O_BINARY", "O_NOFOLLOW", "O_CLOEXEC"):
        flags |= getattr(os, name, 0)
    return flags


def read_own_file(path: str, max_bytes: int, what: str) -> bytes:
    """Read a configuration, rules or baseline file of at most `max_bytes`. `what` names the file
    in error messages ("configuration file"). Raises `ScanIOError`; never includes content."""
    shown = f"{what} {_shown(path)}"
    try:
        info = os.lstat(path)
    except FileNotFoundError:
        raise ScanIOError(f"{shown}: does not exist") from None
    except OSError as error:
        raise ScanIOError(f"{shown}: cannot be examined ({_errno_name(error)})") from None
    kind = _kind_of(info)
    if kind in {EntryKind.SYMLINK, EntryKind.REPARSE_POINT}:
        raise ScanIOError(f"{shown}: is a link or reparse point; pass the real file")
    if kind is not EntryKind.REGULAR:
        raise ScanIOError(f"{shown}: is not a regular file")
    if info.st_size > max_bytes:
        raise ScanIOError(f"{shown}: larger than the limit of {max_bytes} bytes")
    try:
        descriptor = os.open(path, _read_flags())
    except OSError as error:
        raise ScanIOError(f"{shown}: cannot be opened ({_errno_name(error)})") from None
    try:
        opened = os.fstat(descriptor)
        same = not (opened.st_ino and info.st_ino) or (opened.st_dev, opened.st_ino) == (
            info.st_dev,
            info.st_ino,
        )
        if not stat.S_ISREG(opened.st_mode) or not same:
            raise ScanIOError(f"{shown}: changed while it was being opened")
        chunks: list[bytes] = []
        total = 0
        while total <= max_bytes:
            chunk = os.read(descriptor, min(1024 * 1024, max_bytes + 1 - total))
            if not chunk:
                break
            chunks.append(chunk)
            total += len(chunk)
        if total > max_bytes:
            raise ScanIOError(f"{shown}: larger than the limit of {max_bytes} bytes")
        return b"".join(chunks)
    except OSError as error:
        raise ScanIOError(f"{shown}: cannot be read ({_errno_name(error)})") from None
    finally:
        os.close(descriptor)


def check_output_target(path: str, *, force: bool) -> None:
    """Refuse an output target that could not be written (a link, a directory, a special file,
    or an existing file without `force`). `write_new_file` repeats the check at write time; the
    application calls this first so a long scan is not wasted on an output that cannot be made."""
    shown = _shown(path)
    try:
        info = os.lstat(path)
    except FileNotFoundError:
        return
    except OSError as error:
        raise ScanIOError(f"output {shown}: cannot be examined ({_errno_name(error)})") from None
    kind = _kind_of(info)
    if kind in {EntryKind.SYMLINK, EntryKind.REPARSE_POINT}:
        raise ScanIOError(f"output {shown}: is a link or reparse point; refusing to write there")
    if kind is not EntryKind.REGULAR:
        raise ScanIOError(f"output {shown}: exists and is not a regular file")
    if not force:
        raise ScanIOError(f"output {shown}: already exists (use --force to replace it)")


def _write_all(descriptor: int, data: bytes) -> None:
    view = memoryview(data)
    while view:
        written = os.write(descriptor, view)
        view = view[written:]


def _flush_directory(directory: str) -> None:
    """Best effort: make the rename durable on POSIX. Not meaningful on Windows."""
    if sys.platform != "win32":
        try:
            descriptor = os.open(directory, os.O_RDONLY)
        except OSError:
            return
        try:
            with contextlib.suppress(OSError):
                os.fsync(descriptor)
        finally:
            os.close(descriptor)


def write_new_file(path: str, data: bytes, *, force: bool = False) -> None:
    """Atomically create the file `path` with `data`; with `force`, replace an existing regular
    file. Raises `ScanIOError` with a fixed reason; the target is never written through a link."""
    shown = _shown(path)
    check_output_target(path, force=force)
    directory = os.path.dirname(os.path.abspath(path))
    if not os.path.isdir(directory):
        raise ScanIOError(f"output {shown}: the directory does not exist")
    temp = os.path.join(directory, f".{os.path.basename(path)}.{os.urandom(8).hex()}{_TEMP_SUFFIX}")
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
    for name in ("O_BINARY", "O_NOFOLLOW", "O_CLOEXEC"):
        flags |= getattr(os, name, 0)
    try:
        descriptor = os.open(temp, flags, 0o600)
    except OSError as error:
        raise ScanIOError(f"output {shown}: cannot be created ({_errno_name(error)})") from None
    try:
        try:
            _write_all(descriptor, data)
            os.fsync(descriptor)
        finally:
            os.close(descriptor)
        try:
            if force:
                os.replace(temp, path)
            elif sys.platform == "win32":
                os.rename(temp, path)  # fails if the target exists
            else:
                os.link(temp, path)  # fails if the target exists
        except FileExistsError:
            raise ScanIOError(f"output {shown}: already exists (use --force)") from None
        except OSError as error:
            raise ScanIOError(f"output {shown}: cannot be written ({_errno_name(error)})") from None
    except OSError as error:
        raise ScanIOError(f"output {shown}: cannot be written ({_errno_name(error)})") from None
    finally:
        # After a rename the temporary name is already gone; after a link, or a failure, it is
        # still there and must not be left behind.
        with contextlib.suppress(OSError):
            os.unlink(temp)
    _flush_directory(directory)


def _resolved_inside(root: str, candidate: str) -> bool:
    resolved_root = os.path.normcase(os.path.realpath(root))
    resolved = os.path.normcase(os.path.realpath(candidate))
    try:
        return os.path.commonpath([resolved_root, resolved]) == resolved_root
    except ValueError:  # different drives
        return False


def is_inside(root: str, candidate: str) -> bool:
    """True when `candidate` (which need not exist) resolves to a place inside the directory
    `root`, after resolving links in both. Used to keep outputs out of a scanned tree."""
    return _resolved_inside(root, candidate)


def is_same_path(first: str, second: str) -> bool:
    """True when both paths (which need not exist) name the same place after resolving links and
    normalising case. Used to keep an output from overwriting a file the run reads or writes."""
    return os.path.normcase(os.path.realpath(first)) == os.path.normcase(os.path.realpath(second))


def is_absolute(path: str) -> bool:
    """True for a fully qualified path. On Windows that needs a drive or a UNC share: `\\dir` and
    `C:dir` still depend on the current directory or drive (Python before 3.13 calls the first
    one absolute), and a program found through them could be a planted one."""
    return os.path.isabs(path) and (sys.platform != "win32" or bool(os.path.splitdrive(path)[0]))


def search_hazards() -> tuple[list[str], list[str]]:
    """Places a program search must not trust: (trees, directories). The tree is the system
    temporary directory with everything below it, where another local user or a build step can
    plant files. The directory is the current one, but only that directory itself and not what is
    below it: a program installed next to the working directory is no hazard, whereas the
    working directory is exactly where Windows would look first. Run from a drive root, trees
    below the current directory would otherwise cover the whole system."""
    trees = [tempfile.gettempdir()]
    directories: list[str] = []
    with contextlib.suppress(OSError):  # a deleted current directory cannot hold a planted file
        directories.append(os.getcwd())
    return trees, directories


def find_program(
    name: str,
    search_path: str,
    *,
    windows: bool,
    avoid: Sequence[str] = (),
    avoid_directories: Sequence[str] = (),
) -> str | None:
    """The absolute, normalised path of the first regular file called `name` (`name.exe` on
    Windows, never a script type) in the entries of `search_path`, or None.

    Only fully qualified entries are considered: an empty or relative entry means the current
    directory, where a planted `git.exe` would otherwise be found first (CreateProcess searches it
    too). An entry inside any tree of `avoid` (the scanned tree) or equal to any directory of
    `avoid_directories` (the current directory) is never trusted either. A link is followed,
    because system installations use them, but the target must be a regular file.
    """
    filename = name + ".exe" if windows else name
    refused = {os.path.normcase(os.path.realpath(directory)) for directory in avoid_directories}
    for entry in search_path.split(os.pathsep):
        if not entry or not is_absolute(entry):
            continue
        if os.path.normcase(os.path.realpath(entry)) in refused:
            continue
        if any(_resolved_inside(root, entry) for root in avoid):
            continue
        candidate = os.path.normpath(os.path.join(entry, filename))
        try:
            info = os.stat(candidate)
        except OSError:
            continue
        if not stat.S_ISREG(info.st_mode):
            continue
        if not windows and not os.access(candidate, os.X_OK):
            continue
        return candidate
    return None


def check_program(path: str, *, windows: bool, avoid: Sequence[str] = ()) -> str:
    """Validate a program path given by the user (`--git PATH`): fully qualified, an existing
    regular file, on Windows named `git.exe`, not inside a directory of `avoid`. Returns the
    normalised path; raises `ScanIOError`. A path the user typed is trusted wherever it is (the
    current directory included), except inside the scanned tree."""
    shown = _shown(path)
    if not is_absolute(path):
        raise ScanIOError(f"program {shown}: must be an absolute path")
    path = os.path.normpath(path)
    if windows and os.path.basename(path).lower() != "git.exe":
        raise ScanIOError(f"program {shown}: must be named git.exe")
    if any(_resolved_inside(root, path) for root in avoid):
        raise ScanIOError(f"program {shown}: must not be inside the scanned tree")
    try:
        info = os.stat(path)
    except OSError as error:
        raise ScanIOError(f"program {shown}: cannot be examined ({_errno_name(error)})") from None
    if not stat.S_ISREG(info.st_mode):
        raise ScanIOError(f"program {shown}: is not a regular file")
    if not windows and not os.access(path, os.X_OK):
        raise ScanIOError(f"program {shown}: is not executable")
    return path
