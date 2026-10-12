"""Classification of a directory entry from raw `lstat` facts (PLAN.md section 1.3). Pure.

The walker (`fs/walk.py`) collects the raw numbers, `st_mode` and, on Windows, the file
attribute bits; this module decides what they mean, so the interpretation is tested on every
operating system. Nothing here follows a link or touches a file.

Order matters on Windows: a cloud placeholder is a reparse point too, and it must be reported as
offline (reading it would download it), not as an ordinary link; a junction is a directory with
the reparse bit and must never be traversed.
"""

from __future__ import annotations

import stat
from enum import StrEnum
from typing import Protocol

FILE_ATTRIBUTE_REPARSE_POINT = 0x400
FILE_ATTRIBUTE_OFFLINE = 0x1000
FILE_ATTRIBUTE_RECALL_ON_OPEN = 0x40000
FILE_ATTRIBUTE_RECALL_ON_DATA_ACCESS = 0x400000
OFFLINE_ATTRIBUTES = (
    FILE_ATTRIBUTE_OFFLINE | FILE_ATTRIBUTE_RECALL_ON_OPEN | FILE_ATTRIBUTE_RECALL_ON_DATA_ACCESS
)


class EntryKind(StrEnum):
    REGULAR = "regular"
    DIRECTORY = "directory"
    SYMLINK = "symlink"  # a symbolic link
    REPARSE_POINT = "reparse_point"  # Windows junction, mount point or other reparse point
    OFFLINE = "offline"  # cloud placeholder: reading it would download it
    SPECIAL = "special"  # FIFO, socket, device


def classify_entry(mode: int, attributes: int, *, windows: bool) -> EntryKind:
    """What an entry is, from `st_mode` and (Windows only) `st_file_attributes`."""
    if stat.S_ISLNK(mode):
        return EntryKind.SYMLINK
    if windows:
        if attributes & OFFLINE_ATTRIBUTES:
            return EntryKind.OFFLINE
        if attributes & FILE_ATTRIBUTE_REPARSE_POINT:
            return EntryKind.REPARSE_POINT
    if stat.S_ISDIR(mode):
        return EntryKind.DIRECTORY
    if stat.S_ISREG(mode):
        return EntryKind.REGULAR
    return EntryKind.SPECIAL


class StatLike(Protocol):
    """The part of an `os.stat_result` that classification needs."""

    @property
    def st_mode(self) -> int: ...


def classify_stat(info: StatLike, *, windows: bool) -> EntryKind:
    """Classify an `os.stat_result` (from `lstat`); `st_file_attributes` exists on Windows only,
    and a hand-built result may carry `None` for it."""
    attributes = getattr(info, "st_file_attributes", 0) or 0
    return classify_entry(info.st_mode, attributes, windows=windows)
