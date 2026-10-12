"""The single display sanitiser for hostile text.

File names, paths, commit data and file content are hostile (CLAUDE.md section 5, invariant 5).
Everything that is shown to a person or written to a report passes through `sanitize` first.

What is escaped: ASCII control characters (so ANSI escape sequences are inert), DEL, C1 controls,
every Unicode format character (bidirectional controls, zero-width characters, byte-order marks,
tag characters), lone surrogates (from `surrogateescape`), private-use and unassigned code points,
line and paragraph separators, every space character other than U+0020, variation selectors and a
few other invisible characters. The backslash is escaped as well, so the output is unambiguous:
an escape sequence in the output always came from the sanitiser.

Escape forms (the same ones Python's `repr` uses): `\\t`, `\\n`, `\\r`, `\\\\`, `\\xNN`,
`\\uNNNN`, `\\UNNNNNNNN`. A lone surrogate is `\\udcNN`, which cannot collide with the `\\xNN`
form of a C1 control.
"""

from __future__ import annotations

import unicodedata

ELLIPSIS = "..."

_NAMED_ESCAPES: dict[int, str] = {
    0x09: "\\t",
    0x0A: "\\n",
    0x0D: "\\r",
    0x5C: "\\\\",
}

_ESCAPED_CATEGORIES = frozenset({"Cc", "Cf", "Cs", "Co", "Cn", "Zl", "Zp", "Zs"})

# Invisible or blank characters that Unicode does not class as format characters.
_EXTRA_INVISIBLE = frozenset(
    {
        0x034F,  # combining grapheme joiner
        0x115F,  # hangul choseong filler
        0x1160,  # hangul jungseong filler
        0x17B4,  # khmer vowel inherent aq
        0x17B5,  # khmer vowel inherent aa
        0x2800,  # braille pattern blank
        0x3164,  # hangul filler
        0xFFA0,  # halfwidth hangul filler
    }
)


def _needs_escape(code_point: int) -> bool:
    if code_point < 0x80:
        return code_point < 0x20 or code_point == 0x7F or code_point == 0x5C
    if code_point in _EXTRA_INVISIBLE:
        return True
    if 0x180B <= code_point <= 0x180D or 0xFE00 <= code_point <= 0xFE0F:
        return True  # mongolian and general variation selectors
    if 0xE0100 <= code_point <= 0xE01EF:
        return True  # variation selectors supplement
    return unicodedata.category(chr(code_point)) in _ESCAPED_CATEGORIES


def _escape(code_point: int) -> str:
    named = _NAMED_ESCAPES.get(code_point)
    if named is not None:
        return named
    if code_point < 0x100:
        return f"\\x{code_point:02x}"
    if code_point < 0x10000:
        return f"\\u{code_point:04x}"
    return f"\\U{code_point:08x}"


def _render(char: str, ascii_only: bool) -> str:
    code_point = ord(char)
    if _needs_escape(code_point):
        return _escape(code_point)
    if ascii_only and code_point >= 0x80:
        return _escape(code_point)
    return char


def sanitize(text: str, *, max_chars: int | None = None, ascii_only: bool = False) -> str:
    """Return `text` made safe to display.

    `max_chars` bounds the length of the result (an escape sequence is never cut in half; a cut
    result ends with `...`). `ascii_only` also escapes every printable non-ASCII character, as
    needed for strings that go into JSON-bound fields.
    """
    if max_chars is None:
        return "".join(_render(char, ascii_only) for char in text)
    if max_chars < len(ELLIPSIS):
        raise ValueError("max_chars is smaller than the truncation marker")
    # Render at most max_chars + 1 characters' worth: enough to know whether the text fits.
    pieces: list[str] = []
    used = 0
    for char in text:
        piece = _render(char, ascii_only)
        if used + len(piece) > max_chars:
            break
        pieces.append(piece)
        used += len(piece)
    else:
        return "".join(pieces)
    budget = max_chars - len(ELLIPSIS)
    kept: list[str] = []
    total = 0
    for piece in pieces:
        if total + len(piece) > budget:
            break
        kept.append(piece)
        total += len(piece)
    return "".join(kept) + ELLIPSIS


def sanitize_bytes(data: bytes, *, max_chars: int | None = None, ascii_only: bool = False) -> str:
    """Sanitise bytes as UTF-8 with `surrogateescape`, so invalid bytes show as `\\udcNN`."""
    return sanitize(
        data.decode("utf-8", errors="surrogateescape"),
        max_chars=max_chars,
        ascii_only=ascii_only,
    )
