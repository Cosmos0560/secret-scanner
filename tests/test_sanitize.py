"""The single display sanitiser: escape table, truncation, round trip, exhaustive sweep."""

from __future__ import annotations

import re
import unicodedata

import pytest

from secret_scanner.core.sanitize import (
    ELLIPSIS,
    clip_display,
    sanitize,
    sanitize_bytes,
    sanitize_path,
)

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


def _violations(char: str, ascii_only: bool) -> list[str]:
    """What is wrong with the sanitised form of one character (empty list: nothing)."""
    result = sanitize(char, ascii_only=ascii_only)
    problems: list[str] = []
    if unescape(result) != char:
        problems.append("does not round-trip")
    if ascii_only:
        if not all(0x20 <= ord(c) < 0x7F for c in result):
            problems.append("not printable ASCII")
    else:
        for c in result:
            category = unicodedata.category(c)
            if category[0] == "C" or category in {"Zl", "Zp"} or (c != " " and category == "Zs"):
                problems.append("a control, format or separator character survived")
    return problems


@pytest.mark.slow
def test_exhaustive_sweep_over_every_code_point() -> None:
    """Every code point, checked in chunks (the escaping is context-free); on a failure the
    offending chunk is re-checked character by character so the report names the code point."""
    chunk_size = 4096
    for start in range(0, 0x110000, chunk_size):
        chunk = "".join(chr(code) for code in range(start, min(start + chunk_size, 0x110000)))
        for ascii_only in (False, True):
            result = sanitize(chunk, ascii_only=ascii_only)
            ok = unescape(result) == chunk
            if ascii_only:
                ok = ok and all(0x20 <= ord(c) < 0x7F for c in result)
            else:
                ok = ok and not any(
                    unicodedata.category(c)[0] == "C"
                    or unicodedata.category(c) in {"Zl", "Zp"}
                    or (c != " " and unicodedata.category(c) == "Zs")
                    for c in result
                )
            if not ok:
                bad = {
                    hex(ord(c)): _violations(c, ascii_only)
                    for c in chunk
                    if _violations(c, ascii_only)
                }
                pytest.fail(f"sanitiser invariant broken for: {bad}")


def test_is_display_safe_accepts_sanitised_output_and_refuses_raw_text() -> None:
    from secret_scanner.core.sanitize import is_display_safe

    hostile = "a" + chr(0x1B) + "[31m" + chr(0x202E) + "b\n" + chr(0xDCFF) + BACKSLASH + "c"
    assert not is_display_safe(hostile)
    assert is_display_safe(sanitize(hostile))
    assert is_display_safe(sanitize(hostile, ascii_only=True))
    assert is_display_safe("plain/path.txt")
    assert is_display_safe("caf" + chr(0xE9) + "/" + chr(0x65E5))  # printable non-ASCII is fine
    assert not is_display_safe(chr(0))
    assert not is_display_safe("x" + chr(0x200B) + "y")


def test_require_display_safe_returns_safe_text_and_refuses_raw_text_without_echoing_it() -> None:
    from secret_scanner.core.sanitize import require_display_safe

    assert require_display_safe("src/app.py", "path") == "src/app.py"
    with pytest.raises(ValueError, match="host label is not escaped") as caught:
        require_display_safe("a" + chr(0x1B) + "[31mINJECTED", "host label")
    assert "INJECTED" not in str(caught.value)


# -- paths: separators and escaping per component (PLAN.md v0.9) -------------------------------


def test_a_windows_path_is_shown_with_forward_slashes_and_no_doubled_backslash() -> None:
    shown = sanitize_path(BACKSLASH.join(["C:", "Users", "dev", "repo", "config.py"]), windows=True)
    assert shown == "C:/Users/dev/repo/config.py"
    assert BACKSLASH * 2 not in shown
    assert BACKSLASH not in shown


def test_a_windows_relative_path_with_mixed_separators_is_shown_with_slashes() -> None:
    shown = sanitize_path("src" + BACKSLASH + "app" + "/" + "config.py", windows=True)
    assert shown == "src/app/config.py"


def test_components_are_escaped_one_by_one_and_the_separator_is_not() -> None:
    hostile = BACKSLASH.join(["a" + chr(0x1B) + "b", "c" + chr(0x202E), "d"])
    shown = sanitize_path(hostile, windows=True)
    assert shown == "a" + esc("x1b") + "b/c" + esc("u202e") + "/d"
    assert chr(0x1B) not in shown


def test_on_posix_a_backslash_is_a_name_character_and_stays_escaped() -> None:
    assert sanitize_path("a" + BACKSLASH + "b/c", windows=False) == "a" + BACKSLASH * 2 + "b/c"


def test_windows_path_display_honours_the_bound_and_ascii_only() -> None:
    long_path = BACKSLASH.join(["dir"] * 40)
    shown = sanitize_path(long_path, windows=True, max_chars=20)
    assert len(shown) <= 20
    assert shown.endswith(ELLIPSIS)
    assert BACKSLASH not in shown
    assert sanitize_path("caf" + chr(0xE9), windows=True, ascii_only=True) == "caf" + esc("xe9")


# -- clip_display: cutting escaped text without splitting an escape -----------------------------


def test_clip_display_leaves_text_that_fits_alone() -> None:
    assert clip_display("abc", 3) == ("abc", False)
    assert clip_display("", 0) == ("", False)


def test_clip_display_cuts_plain_text_at_the_bound() -> None:
    assert clip_display("abcdef", 4) == ("abcd", True)
    assert clip_display("abcdef", 0) == ("", True)


@pytest.mark.parametrize(
    ("escape", "length"),
    [
        (esc("t"), 2),
        (esc("n"), 2),
        (esc("r"), 2),
        (BACKSLASH * 2, 2),
        (esc("x1b"), 4),
        (esc("u202e"), 6),
        (esc("U0001f600"), 10),
    ],
)
def test_clip_display_never_splits_an_escape_sequence(escape: str, length: int) -> None:
    text = "ab" + escape + "cd"
    assert len(escape) == length
    for bound in range(len(text)):
        cut, was_cut = clip_display(text, bound)
        assert was_cut
        assert len(cut) <= bound
        assert text.startswith(cut)
        assert cut in {text[:i] for i in (0, 1, 2, 2 + length, 3 + length)}
    assert clip_display(text, len(text)) == (text, False)


def test_clip_display_of_a_sanitised_hostile_string_round_trips() -> None:
    original = "x" + chr(0x1B) + chr(0x202E) + chr(0x1F600) + BACKSLASH + chr(0xDCFF) + "end"
    shown = sanitize(original)
    for bound in range(len(shown) + 1):
        cut, _ = clip_display(shown, bound)
        assert unescape(cut) == original[: len(unescape(cut))]


def test_clip_display_treats_a_lone_trailing_backslash_as_one_character() -> None:
    # not produced by the sanitiser, but the function must still be total
    assert clip_display("ab" + BACKSLASH, 2) == ("ab", True)
    assert clip_display("ab" + BACKSLASH, 3) == ("ab" + BACKSLASH, False)


def test_clip_display_refuses_a_negative_bound() -> None:
    with pytest.raises(ValueError, match="negative"):
        clip_display("abc", -1)
