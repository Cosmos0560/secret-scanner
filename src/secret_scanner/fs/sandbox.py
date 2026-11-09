"""The demo's temporary tree (PLAN.md section 1.1, Phase 5).

The only module that creates and deletes files for a purpose other than the tool's own output
files, and importable by `app/demo.py` only (`scripts/check_architecture.py`, rule `sandbox`).
Everything it creates is inside one directory that it made itself with `tempfile.mkdtemp`, whose
name starts with `PREFIX`; everything it removes is that directory.

* A path inside the sandbox is a list of plain names joined with `/`: no empty name, no `.` or `..`,
  no separator, drive or stream syntax, no control character, no trailing dot or space. The demo
  only ever uses constant names, so a refusal means a bug, and it is an error, not a repair.
* Files are created with exclusive creation, or replaced only when the existing entry is a regular
  file (never through a link).
* Removal refuses a directory whose name is not the sandbox's, or that is not a plain directory
  any more (a link or reparse point put there would otherwise be followed). Links and junctions
  inside are removed as links before the tree is deleted, and read-only files (git object files on
  Windows) are made writable first.
"""

from __future__ import annotations

import errno
import os
import shutil
import stat
import tempfile

from secret_scanner.core.errors import DemoError

PREFIX = "secret-scanner-demo-"
_FORBIDDEN_CHARACTERS = frozenset('<>:"\\|?*')


def _errno_name(error: OSError) -> str:
    return errno.errorcode.get(error.errno or 0, "OSError")


def _is_link(info: os.stat_result) -> bool:
    """A symbolic link, or on Windows any reparse point (a junction or mount point)."""
    reparse = getattr(info, "st_file_attributes", 0) & getattr(
        stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0
    )
    return stat.S_ISLNK(info.st_mode) or bool(reparse)


def _valid_name(name: str) -> bool:
    return (
        bool(name)
        and name not in {".", ".."}
        and not name.endswith((" ", "."))
        and not any(ord(char) < 0x20 or char in _FORBIDDEN_CHARACTERS for char in name)
    )


def member(root: str, relative: str) -> str:
    """The path of `relative` (names joined with `/`) inside the sandbox `root`."""
    names = relative.split("/")
    if not all(_valid_name(name) for name in names):
        raise DemoError("the demo built a path that is not a plain relative name")
    return os.path.join(root, *names)


def create_sandbox(parent: str | None = None) -> str:
    """Make the demo's directory (under `parent`, or the system temporary directory) and return
    its real path."""
    try:
        return os.path.realpath(tempfile.mkdtemp(prefix=PREFIX, dir=parent))
    except OSError as error:
        raise DemoError(
            f"cannot create the demo's temporary directory ({_errno_name(error)})"
        ) from None


def make_directory(root: str, relative: str) -> str:
    """Create a directory (and its parents) inside the sandbox; returns its path."""
    path = member(root, relative)
    try:
        os.makedirs(path, exist_ok=True)
    except OSError as error:
        raise DemoError(f"cannot create a demo directory ({_errno_name(error)})") from None
    return path


def write_text(root: str, relative: str, text: str, *, replace: bool = False) -> str:
    """Write a UTF-8 file with `\\n` line ends inside the sandbox and return its path. An existing
    file is an error, unless `replace` is set and it is a regular file."""
    path = member(root, relative)
    try:
        os.makedirs(os.path.dirname(path), exist_ok=True)
        if replace:
            info = os.lstat(path)
            if not stat.S_ISREG(info.st_mode) or _is_link(info):
                raise DemoError("a demo file to replace is not a regular file")
        with open(path, "w" if replace else "x", encoding="utf-8", newline="\n") as handle:
            handle.write(text)
    except OSError as error:
        raise DemoError(f"cannot write a demo file ({_errno_name(error)})") from None
    return path


def _prepare_removal(root: str) -> None:
    """Remove links (so that nothing can follow one) and make regular files writable."""
    for directory, subdirectories, files in os.walk(root, followlinks=False):
        for name in [*subdirectories]:
            path = os.path.join(directory, name)
            if _is_link(os.lstat(path)):
                subdirectories.remove(name)
                os.unlink(path)
        for name in files:
            path = os.path.join(directory, name)
            info = os.lstat(path)
            if _is_link(info):
                os.unlink(path)
            elif stat.S_ISREG(info.st_mode):
                os.chmod(path, stat.S_IREAD | stat.S_IWRITE)


def remove_sandbox(root: str) -> None:
    """Delete the sandbox and everything in it. A sandbox that is already gone is fine."""
    if not os.path.basename(root).startswith(PREFIX):
        raise DemoError("refusing to remove a directory that is not a demo directory")
    try:
        info = os.lstat(root)
    except FileNotFoundError:
        return
    except OSError as error:
        raise DemoError(f"cannot examine the demo directory ({_errno_name(error)})") from None
    if not stat.S_ISDIR(info.st_mode) or _is_link(info):
        raise DemoError("the demo directory is not a plain directory any more; left in place")
    try:
        _prepare_removal(root)
        shutil.rmtree(root)
    except OSError as error:
        raise DemoError(
            f"cannot remove the demo directory ({_errno_name(error)}); delete it by hand"
        ) from None
