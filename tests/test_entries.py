"""Entry classification from raw lstat facts (PLAN.md section 1.3): the same table on every OS."""

from __future__ import annotations

import stat

import pytest

from secret_scanner.core.entries import (
    FILE_ATTRIBUTE_OFFLINE,
    FILE_ATTRIBUTE_RECALL_ON_DATA_ACCESS,
    FILE_ATTRIBUTE_RECALL_ON_OPEN,
    FILE_ATTRIBUTE_REPARSE_POINT,
    EntryKind,
    classify_entry,
)

REG = stat.S_IFREG | 0o644
DIR = stat.S_IFDIR | 0o755
LNK = stat.S_IFLNK | 0o777
FIFO = stat.S_IFIFO | 0o644
SOCK = stat.S_IFSOCK | 0o644
CHR = stat.S_IFCHR | 0o644
BLK = stat.S_IFBLK | 0o644

TABLE = [
    # (mode, attributes, windows, expected)
    (REG, 0, False, EntryKind.REGULAR),
    (DIR, 0, False, EntryKind.DIRECTORY),
    (LNK, 0, False, EntryKind.SYMLINK),
    (FIFO, 0, False, EntryKind.SPECIAL),
    (SOCK, 0, False, EntryKind.SPECIAL),
    (CHR, 0, False, EntryKind.SPECIAL),
    (BLK, 0, False, EntryKind.SPECIAL),
    (REG, 0, True, EntryKind.REGULAR),
    (DIR, 0, True, EntryKind.DIRECTORY),
    (LNK, 0, True, EntryKind.SYMLINK),
    # a junction: a directory carrying the reparse bit must never be traversed
    (DIR, FILE_ATTRIBUTE_REPARSE_POINT, True, EntryKind.REPARSE_POINT),
    (REG, FILE_ATTRIBUTE_REPARSE_POINT, True, EntryKind.REPARSE_POINT),
    # cloud placeholders: offline wins over reparse, because reading would download them
    (REG, FILE_ATTRIBUTE_OFFLINE, True, EntryKind.OFFLINE),
    (REG, FILE_ATTRIBUTE_RECALL_ON_OPEN, True, EntryKind.OFFLINE),
    (REG, FILE_ATTRIBUTE_RECALL_ON_DATA_ACCESS, True, EntryKind.OFFLINE),
    (
        REG,
        FILE_ATTRIBUTE_RECALL_ON_DATA_ACCESS | FILE_ATTRIBUTE_REPARSE_POINT,
        True,
        EntryKind.OFFLINE,
    ),
    (DIR, FILE_ATTRIBUTE_RECALL_ON_DATA_ACCESS, True, EntryKind.OFFLINE),
    # the attribute bits mean nothing off Windows
    (REG, FILE_ATTRIBUTE_OFFLINE, False, EntryKind.REGULAR),
    (DIR, FILE_ATTRIBUTE_REPARSE_POINT, False, EntryKind.DIRECTORY),
]


@pytest.mark.parametrize(("mode", "attributes", "windows", "expected"), TABLE)
def test_classification_table(
    mode: int, attributes: int, windows: bool, expected: EntryKind
) -> None:
    assert classify_entry(mode, attributes, windows=windows) is expected
