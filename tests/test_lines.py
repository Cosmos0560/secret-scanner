"""Binary check, byte-order marks, line splitting and columns (PLAN.md D14, D15)."""

from __future__ import annotations

import pytest

from secret_scanner.core.lines import (
    BINARY_PROBE_BYTES,
    ColumnCursor,
    Line,
    TextKind,
    column_of,
    prepare,
    split_lines,
)

# -- prepare: kind, BOM, transcoding ----------------------------------------------------------


def test_plain_ascii_and_utf8_are_text_unchanged() -> None:
    assert prepare(b"hello\n") == prepare(b"hello\n")
    assert prepare(b"hello\n").kind is TextKind.TEXT
    assert prepare(b"hello\n").text == b"hello\n"
    assert prepare("café\n".encode()).text == "café\n".encode()
    assert prepare(b"").kind is TextKind.TEXT


def test_latin1_and_invalid_utf8_are_still_text_scanned_as_bytes() -> None:
    data = b"key = \xe9\xe8 \xff\xfe-not-a-bom\n"
    result = prepare(data)
    assert result.kind is TextKind.TEXT
    assert result.text == data


def test_utf8_bom_is_skipped() -> None:
    assert prepare(b"\xef\xbb\xbfabc").text == b"abc"


@pytest.mark.parametrize(
    ("bom", "codec"),
    [
        (b"\xff\xfe", "utf-16-le"),
        (b"\xfe\xff", "utf-16-be"),
        (b"\xff\xfe\x00\x00", "utf-32-le"),
        (b"\x00\x00\xfe\xff", "utf-32-be"),
    ],
)
def test_wide_encodings_with_a_bom_are_transcoded_to_utf8(bom: bytes, codec: str) -> None:
    text = "token = café\nsecond line\n"
    result = prepare(bom + text.encode(codec))
    assert result.kind is TextKind.TEXT
    assert result.text == text.encode("utf-8")


def test_utf16_with_a_bom_is_not_binary_although_it_contains_nul_bytes() -> None:
    data = b"\xff\xfe" + "abc".encode("utf-16-le")
    assert b"\x00" in data
    assert prepare(data).kind is TextKind.TEXT


@pytest.mark.parametrize(
    "data",
    [
        b"\xff\xfe" + b"a",  # odd number of bytes
        b"\xff\xfe" + b"\x00\xd8",  # a lone high surrogate
        b"\xff\xfe\x00\x00" + b"\x00\x00\x11\x00",  # code point above U+10FFFF
        b"\xfe\xff" + b"\xdc\x00",  # a lone low surrogate
    ],
)
def test_undecodable_wide_text_is_reported_not_raised(data: bytes) -> None:
    result = prepare(data)
    assert result.kind is TextKind.UNDECODABLE
    assert result.text == b""


def test_utf16_without_a_bom_looks_binary() -> None:
    assert prepare("abcdef".encode("utf-16-le")).kind is TextKind.BINARY


def test_nul_in_the_first_8000_bytes_is_binary() -> None:
    assert prepare(b"abc\x00def").kind is TextKind.BINARY
    inside = b"a" * (BINARY_PROBE_BYTES - 1) + b"\x00"
    assert prepare(inside).kind is TextKind.BINARY
    outside = b"a" * BINARY_PROBE_BYTES + b"\x00"
    assert prepare(outside).kind is TextKind.TEXT


def test_binary_result_carries_no_text() -> None:
    assert prepare(b"\x00" * 10).text == b""


# -- split_lines ------------------------------------------------------------------------------


def _lines(text: bytes, limit: int = 1000) -> list[Line]:
    return list(split_lines(text, limit))


def test_lines_are_numbered_from_one_and_terminators_removed() -> None:
    assert [(line.number, line.content) for line in _lines(b"a\nbb\nccc")] == [
        (1, b"a"),
        (2, b"bb"),
        (3, b"ccc"),
    ]


def test_trailing_newline_does_not_start_another_line() -> None:
    assert [line.content for line in _lines(b"a\nb\n")] == [b"a", b"b"]
    assert _lines(b"") == []
    assert [line.content for line in _lines(b"\n")] == [b""]
    assert [line.content for line in _lines(b"\n\n")] == [b"", b""]


def test_one_trailing_carriage_return_is_removed() -> None:
    assert [line.content for line in _lines(b"a\r\nb\r\r\nc\r")] == [b"a", b"b\r", b"c"]


def test_lone_carriage_returns_do_not_split() -> None:
    assert [line.content for line in _lines(b"a\rb\n")] == [b"a\rb"]


def test_a_line_longer_than_the_limit_is_cut_and_marked() -> None:
    lines = _lines(b"ok\n" + b"x" * 30 + b"\nafter\n", limit=10)
    assert [(line.number, line.content, line.truncated) for line in lines] == [
        (1, b"ok", False),
        (2, b"x" * 10, True),
        (3, b"after", False),
    ]


def test_a_line_exactly_at_the_limit_is_not_truncated() -> None:
    (line,) = _lines(b"y" * 10 + b"\n", limit=10)
    assert (line.content, line.truncated) == (b"y" * 10, False)
    (over,) = _lines(b"y" * 11 + b"\n", limit=10)
    assert over.truncated


def test_line_numbers_continue_after_a_cut_line() -> None:
    lines = _lines(b"a" * 50 + b"\n" + b"b\n", limit=5)
    assert [line.number for line in lines] == [1, 2]


# -- columns ----------------------------------------------------------------------------------


def test_columns_are_one_based_code_points() -> None:
    line = b"abc=secret"
    assert column_of(line, 0) == 1
    assert column_of(line, 4) == 5
    assert column_of(line, len(line)) == len(line) + 1


def test_multibyte_prefix_counts_code_points_not_bytes() -> None:
    line = "café 日本 = token".encode()
    offset = line.index(b"token")
    assert column_of(line, offset) == len("café 日本 = ") + 1


def test_each_invalid_byte_counts_as_one_column() -> None:
    line = b"\xff\xfe\xfdtoken"
    assert column_of(line, 3) == 4
    emoji = "\U0001f600x".encode()
    assert column_of(emoji, len(emoji) - 1) == 2


# -- the column cursor ------------------------------------------------------------------------


def test_cursor_agrees_with_column_of_for_every_offset_in_any_order() -> None:
    import random

    line = "café 日本 \U0001f600 key=".encode() + b"\xff\xfe broken \xe6\x97 end \xf0\x9f"
    line += b" tail=value"
    rng = random.Random(7)
    boundaries = [i for i, byte in enumerate(line) if byte < 0x80] + [len(line)]
    ordered = sorted(boundaries)
    cursor = ColumnCursor(line)
    assert [cursor.column(offset) for offset in ordered] == [column_of(line, o) for o in ordered]
    shuffled = boundaries[:]
    rng.shuffle(shuffled)
    cursor = ColumnCursor(line)
    assert [cursor.column(offset) for offset in shuffled] == [column_of(line, o) for o in shuffled]


def test_cursor_handles_repeated_and_zero_offsets() -> None:
    cursor = ColumnCursor(b"abc")
    assert (cursor.column(0), cursor.column(0), cursor.column(2), cursor.column(2)) == (1, 1, 3, 3)
    assert cursor.column(1) == 2  # going back starts over
    assert cursor.column(3) == 4


def test_cursor_is_linear_not_quadratic() -> None:
    line = b"abcdefghij" * 20_000  # 200 KB
    cursor = ColumnCursor(line)
    assert [cursor.column(offset) for offset in range(0, len(line), 10)][-1] == len(line) - 9
