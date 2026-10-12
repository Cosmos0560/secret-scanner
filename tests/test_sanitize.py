"""The single display sanitiser: escape table, truncation, round trip, exhaustive sweep."""

from __future__ import annotations

import re
import unicodedata

import pytest

from secret_scanner.core.sanitize import ELLIPSIS, sanitize, sanitize_bytes

BACKSLASH = chr(92)
_ESCAPE = re.compile(r"\\(x[0-9a-f]{2}|u[0-9a-f]{4}|U[0-9a-f]{8}|[tnr\\])")


def unescape(text: str) -> str:
    """The inverse of the sanitiser's escaping (test helper)."""

    def replace(match: re.Match[str]) -> str:
        token = match.group(1)
        named = {"t": "\t", "n": "\n", "r": "\r", BACKSLASH: BACKSLASH}
        if token in named:
            return named[token]
        return chr(int(token[1:], 16))

    return _ESCAPE.sub(replace, text)


def esc(text: str) -> str:
    """Build the expected escape text without writing a unicode escape in this source file."""
    return BACKSLASH + text


ESCAPE_TABLE = [
    ("plain ascii", "hello world 123 ~", "hello world 123 ~"),
    ("tab", "a\tb", "a" + esc("t") + "b"),
    ("newline", "a\nb", "a" + esc("n") + "b"),
    ("carriage return", "a\rb", "a" + esc("r") + "b"),
    ("backslash", "a" + BACKSLASH + "b", "a" + BACKSLASH * 2 + "b"),
    ("nul", chr(0), esc("x00")),
    ("escape (ANSI)", chr(0x1B) + "[31mred", esc("x1b") + "[31mred"),
    ("bell", chr(7), esc("x07")),
    ("DEL", chr(0x7F), esc("x7f")),
    ("C1 control", chr(0x85), esc("x85")),
    ("C1 CSI", chr(0x9B), esc("x9b")),
    ("right-to-left override", chr(0x202E), esc("u202e")),
    ("left-to-right isolate", chr(0x2066), esc("u2066")),
    ("left-to-right mark", chr(0x200E), esc("u200e")),
    ("arabic letter mark", chr(0x61C), esc("u061c")),
    ("zero-width space", chr(0x200B), esc("u200b")),
    ("zero-width joiner", chr(0x200D), esc("u200d")),
    ("word joiner", chr(0x2060), esc("u2060")),
    ("byte-order mark", chr(0xFEFF), esc("ufeff")),
    ("soft hyphen", chr(0xAD), esc("xad")),
    ("no-break space", chr(0xA0), esc("xa0")),
    ("ideographic space", chr(0x3000), esc("u3000")),
    ("line separator", chr(0x2028), esc("u2028")),
    ("paragraph separator", chr(0x2029), esc("u2029")),
    ("lone surrogate (from surrogateescape)", chr(0xDC80), esc("udc80")),
    ("variation selector", chr(0xFE0F), esc("ufe0f")),
    ("private use", chr(0xE000), esc("ue000")),
    ("tag character", chr(0xE0041), esc("U000e0041")),
    ("variation selector supplement", chr(0xE0100), esc("U000e0100")),
    ("braille blank", chr(0x2800), esc("u2800")),
    ("hangul filler", chr(0x3164), esc("u3164")),
    ("noncharacter U+FFFF", chr(0xFFFF), esc("uffff")),
]


@pytest.mark.parametrize(
    ("label", "raw", "expected"), ESCAPE_TABLE, ids=[row[0] for row in ESCAPE_TABLE]
)
def test_escape_table(label: str, raw: str, expected: str) -> None:
    assert sanitize(raw) == expected, label


def test_printable_non_ascii_is_kept_unless_ascii_only() -> None:
    text = "caf" + chr(0xE9) + " " + chr(0x4E2D) + chr(0x6587) + " " + chr(0x1F600)
    assert sanitize(text) == text
    assert sanitize(text, ascii_only=True) == (
        "caf" + esc("xe9") + " " + esc("u4e2d") + esc("u6587") + " " + esc("U0001f600")
    )


def test_ascii_only_output_is_printable_ascii() -> None:
    hostile = "".join(chr(code) for code in (0, 9, 10, 0x1B, 0x7F, 0xE9, 0x202E, 0xDC80, 0x1F600))
    result = sanitize(hostile, ascii_only=True)
    assert all(0x20 <= ord(char) < 0x7F for char in result)


def test_ansi_sequence_cannot_survive() -> None:
    result = sanitize(chr(0x1B) + "[2J" + chr(0x1B) + "]0;title" + chr(7))
    assert chr(0x1B) not in result
    assert chr(7) not in result


def test_newline_cannot_forge_a_second_log_line() -> None:
    result = sanitize("file.txt\n2026-01-01 FAKE LOG LINE")
    assert "\n" not in result


def test_truncation_marks_the_cut_and_respects_the_bound() -> None:
    assert sanitize("a" * 100, max_chars=10) == "a" * 7 + ELLIPSIS
    assert sanitize("a" * 10, max_chars=10) == "a" * 10
    assert sanitize("a" * 11, max_chars=10) == "a" * 7 + ELLIPSIS
    assert sanitize("", max_chars=3) == ""


def test_truncation_never_cuts_an_escape_in_half() -> None:
    result = sanitize(chr(0x1B) * 10, max_chars=10)
    assert result == esc("x1b") + ELLIPSIS
    assert len(result) <= 10
    assert unescape(result.removesuffix(ELLIPSIS)) == chr(0x1B)


def test_truncation_counts_escaped_length() -> None:
    result = sanitize(chr(0x202E) * 5, max_chars=12)
    assert len(result) <= 12
    assert result.endswith(ELLIPSIS)


def test_truncation_when_the_next_escape_is_what_does_not_fit() -> None:
    result = sanitize("a" * 5 + chr(0x1F600), max_chars=10, ascii_only=True)
    assert result == "aaaaa" + ELLIPSIS


def test_max_chars_below_the_marker_is_refused() -> None:
    with pytest.raises(ValueError, match="max_chars"):
        sanitize("abc", max_chars=2)


def test_sanitize_bytes_escapes_invalid_utf8() -> None:
    assert sanitize_bytes(b"a\xffb") == "a" + esc("udcff") + "b"
    assert sanitize_bytes(b"caf" + b"\xc3\xa9") == "caf" + chr(0xE9)
    assert sanitize_bytes(b"\x1b[0m", ascii_only=True) == esc("x1b") + "[0m"
    assert sanitize_bytes(b"x" * 50, max_chars=10) == "x" * 7 + ELLIPSIS


@pytest.mark.parametrize(
    "text",
    [
        "",
        "plain",
        "back" + BACKSLASH + "slash" + BACKSLASH + "n",
        "mixed" + chr(0x1B) + "[0m" + chr(0x202E) + "x" + chr(0xDC80) + chr(0x1F600) + "\t\n\r",
        BACKSLASH * 3,
        BACKSLASH + "x1b literal text that only looks like an escape",
    ],
)
def test_round_trip(text: str) -> None:
    assert unescape(sanitize(text)) == text
    assert unescape(sanitize(text, ascii_only=True)) == text


def test_literal_escape_looking_text_is_distinguishable() -> None:
    # The backslash is escaped, so an attacker cannot make a name look like a sanitiser escape.
    typed = BACKSLASH + "u202e"
    assert sanitize(typed) == BACKSLASH * 2 + "u202e"
    assert sanitize(typed) != sanitize(chr(0x202E))


@pytest.mark.slow
def test_exhaustive_sweep_over_every_code_point() -> None:
    for code_point in range(0x110000):
        char = chr(code_point)
        for ascii_only in (False, True):
            result = sanitize(char, ascii_only=ascii_only)
            assert unescape(result) == char, hex(code_point)
            if ascii_only:
                assert all(0x20 <= ord(c) < 0x7F for c in result), hex(code_point)
            else:
                for c in result:
                    category = unicodedata.category(c)
                    assert category[0] != "C", hex(code_point)
                    assert category not in {"Zl", "Zp"}, hex(code_point)
                    assert c == " " or category != "Zs", hex(code_point)
