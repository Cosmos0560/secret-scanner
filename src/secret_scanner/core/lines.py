"""Binary check, byte-order marks, line splitting and columns (PLAN.md D14, D15). Pure.

Detection runs on bytes. Every detector looks for ASCII tokens, so scanning bytes covers UTF-8,
Latin-1, cp1252 and every other ASCII-compatible encoding without decoding and without decode
errors. The exceptions are the UTF-16 and UTF-32 files that announce themselves with a byte-order
mark: they are transcoded to UTF-8 first. UTF-16 without a mark looks binary (NUL bytes) and is
skipped, which is a documented limitation.

Lines split on `\\n`; a trailing `\\r` is removed. A line longer than the limit is scanned up to the
limit and the rest is skipped (the caller records an issue). Line numbers are 1-based. Columns are
1-based Unicode code points, counted by decoding the line prefix as UTF-8 with `errors="replace"`,
so each invalid byte counts as one.
"""

from __future__ import annotations

from collections.abc import Iterator
from dataclasses import dataclass
from enum import StrEnum
from typing import NamedTuple

BINARY_PROBE_BYTES = 8_000

UTF8_BOM = b"\xef\xbb\xbf"
UTF32_LE_BOM = b"\xff\xfe\x00\x00"
UTF32_BE_BOM = b"\x00\x00\xfe\xff"
UTF16_LE_BOM = b"\xff\xfe"
UTF16_BE_BOM = b"\xfe\xff"
# Order matters: the UTF-32 LE mark starts with the UTF-16 LE mark.
_WIDE_BOMS: tuple[tuple[bytes, str], ...] = (
    (UTF32_LE_BOM, "utf-32-le"),
    (UTF32_BE_BOM, "utf-32-be"),
    (UTF16_LE_BOM, "utf-16-le"),
    (UTF16_BE_BOM, "utf-16-be"),
)


class TextKind(StrEnum):
    TEXT = "text"
    BINARY = "binary"
    UNDECODABLE = "undecodable"


@dataclass(frozen=True, slots=True)
class Prepared:
    """File content ready for detection: BOM removed, UTF-16/32 transcoded to UTF-8. `text` is
    empty unless `kind` is TEXT."""

    kind: TextKind
    text: bytes


class Line(NamedTuple):
    number: int
    content: bytes  # no line terminator; at most the line limit
    truncated: bool  # the line was longer than the limit and its rest was skipped


def prepare(data: bytes) -> Prepared:
    """Classify `data` and return what the detectors should read."""
    for mark, codec in _WIDE_BOMS:
        if data.startswith(mark):
            try:
                text = data[len(mark) :].decode(codec).encode("utf-8")
            except (UnicodeDecodeError, UnicodeEncodeError):
                return Prepared(TextKind.UNDECODABLE, b"")
            return Prepared(TextKind.TEXT, text)
    if b"\0" in data[:BINARY_PROBE_BYTES]:
        return Prepared(TextKind.BINARY, b"")
    if data.startswith(UTF8_BOM):
        return Prepared(TextKind.TEXT, data[len(UTF8_BOM) :])
    return Prepared(TextKind.TEXT, data)


def split_lines(text: bytes, max_line_bytes: int) -> Iterator[Line]:
    """Yield the lines of `text`. A final line without a terminator is a line; a terminator at
    the very end does not start another one."""
    position = 0
    length = len(text)
    number = 0
    while position < length:
        end = text.find(b"\n", position)
        stop = length if end == -1 else end
        number += 1
        truncated = stop - position > max_line_bytes
        content = text[position : position + max_line_bytes] if truncated else text[position:stop]
        if not truncated and content.endswith(b"\r"):
            content = content[:-1]
        yield Line(number, content, truncated)
        position = stop + 1


def column_of(line: bytes, byte_offset: int) -> int:
    """1-based column, in code points, of the byte at `byte_offset` (or just past the end)."""
    return len(line[:byte_offset].decode("utf-8", errors="replace")) + 1


class ColumnCursor:
    """Columns of many offsets in one line, in linear time for offsets that only grow.

    `column_of` decodes the whole prefix each time, which is quadratic on a line with thousands
    of matches. The cursor decodes only the bytes since the previous query. Matches start at an
    ASCII byte, so a segment boundary never splits a character and the count equals what a
    decode of the whole prefix gives; an offset before the previous one starts over.
    """

    __slots__ = ("_column", "_line", "_offset")

    def __init__(self, line: bytes) -> None:
        self._line = line
        self._offset = 0
        self._column = 1

    def column(self, byte_offset: int) -> int:
        if byte_offset < self._offset:
            self._offset = 0
            self._column = 1
        if byte_offset > self._offset:
            segment = self._line[self._offset : byte_offset]
            self._column += len(segment.decode("utf-8", errors="replace"))
            self._offset = byte_offset
        return self._column
