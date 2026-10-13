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
from collections.abc import Iterable

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


def _bounded(rendered: Iterable[str], max_chars: int | None) -> str:
    """Join already escaped pieces, cut at `max_chars` without splitting a piece."""
    if max_chars is None:
        return "".join(rendered)
    if max_chars < len(ELLIPSIS):
        raise ValueError("max_chars is smaller than the truncation marker")
    # Stop at the first piece that does not fit, so a huge input costs at most max_chars of work.
    pieces: list[str] = []
    used = 0
    for piece in rendered:
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


def sanitize(text: str, *, max_chars: int | None = None, ascii_only: bool = False) -> str:
    """Return `text` made safe to display.

    `max_chars` bounds the length of the result (an escape sequence is never cut in half; a cut
    result ends with `...`). `ascii_only` also escapes every printable non-ASCII character, as
    needed for strings that go into JSON-bound fields.
    """
    return _bounded((_render(char, ascii_only) for char in text), max_chars)


def sanitize_path(
    path: str, *, windows: bool, max_chars: int | None = None, ascii_only: bool = False
) -> str:
    """Return a user-given or scanned path made safe to display, with `/` separators.

    A path is shown as a list of escaped components joined by `/` (PLAN.md v0.9). With `windows`
    set, `\\` is a separator, as it is in a Windows path, and shown as `/`, so a Windows path
    never appears with doubled backslashes. Without it (POSIX), `\\` is an ordinary character of a
    name and is escaped like any other, so the output stays unambiguous. `/` is never altered.
    """
    return _bounded(
        ("/" if windows and char == "\\" else _render(char, ascii_only) for char in path),
        max_chars,
    )


def is_display_safe(text: str) -> bool:
    """True when `text` could have come out of `sanitize`: it holds no character that `sanitize`
    would escape, apart from the backslash, which only occurs inside the escape sequences.

    Models that are rendered verbatim use this to refuse a raw hostile string at construction,
    so a renderer never has to guess whether a path was escaped already.
    """
    return all(char == "\\" or not _needs_escape(ord(char)) for char in text)


def require_display_safe(text: str, what: str) -> str:
    """Return `text` unchanged when `is_display_safe` holds, else raise `ValueError` naming `what`
    (never the text). Renderers use it on every string they were handed, so a value that skipped
    the sanitiser fails loudly instead of reaching a terminal or a report."""
    if not is_display_safe(text):
        raise ValueError(f"{what} is not escaped for display (core/sanitize.py)")
    return text


def sanitize_bytes(data: bytes, *, max_chars: int | None = None, ascii_only: bool = False) -> str:
    """Sanitise bytes as UTF-8 with `surrogateescape`, so invalid bytes show as `\\udcNN`."""
    return sanitize(
        data.decode("utf-8", errors="surrogateescape"),
        max_chars=max_chars,
        ascii_only=ascii_only,
    )
