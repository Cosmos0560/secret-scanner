"""Segment-wise glob matcher for exclude lists and baseline paths (PLAN.md D9, D13). Pure.

Patterns are matched against a relative path with `/` separators, as a whole (anchored): to match
at any depth write `**/*.pem`. There is no regular expression and no recursion over the input.

* `*` matches any run of characters inside one path segment, `?` exactly one character,
  `[abc]`, `[a-z]` and `[!abc]` (or `[^abc]`) one character from, or outside, a set;
* a segment that is exactly `**` matches zero or more whole segments, so `tests/fixtures/**`
  matches `tests/fixtures` itself and everything below it;
* there is no escape character: write `[*]` for a literal star;
* matching is case-sensitive on every platform, so a pattern means the same thing everywhere.

A pattern is refused (fail closed) when it is empty, over-long, holds a control character or a
backslash, starts with `/`, has an empty, `.` or `..` segment, or has a malformed set. The cost of
a match is bounded by pattern length times path length (both are limited), never exponential:
single-character items let the star backtracking stay linear in each segment.
"""

from __future__ import annotations

from collections.abc import Iterable, Sequence
from dataclasses import dataclass

from secret_scanner.core.errors import ConfigError
from secret_scanner.core.limits import DEFAULT_LIMITS, Limits

GLOBSTAR = "**"


@dataclass(frozen=True, slots=True)
class _Item:
    """One element of a segment: a literal, `?`, `*` or a `[...]` set."""

    kind: str  # "lit" | "any" | "star" | "set"
    char: str = ""
    negated: bool = False
    ranges: tuple[tuple[int, int], ...] = ()


SegmentPattern = tuple[_Item, ...]


@dataclass(frozen=True, slots=True)
class Glob:
    """A compiled pattern. `segments` holds `None` for a `**` segment."""

    source: str
    segments: tuple[SegmentPattern | None, ...]

    def matches(self, path: str) -> bool:
        """True when `path` (relative, `/`-separated, no leading slash) matches as a whole."""
        parts = path.split("/")
        count = len(parts)
        reachable = [False] * (count + 1)
        reachable[0] = True
        for segment in self.segments:
            following = [False] * (count + 1)
            if segment is None:
                if True not in reachable:
                    return False
                for position in range(reachable.index(True), count + 1):
                    following[position] = True
            else:
                for position in range(count):
                    if reachable[position] and _segment_matches(segment, parts[position]):
                        following[position + 1] = True
            reachable = following
        return reachable[count]


def _item_matches(item: _Item, char: str) -> bool:
    if item.kind == "lit":
        return item.char == char
    if item.kind == "any":
        return True
    code = ord(char)  # a set
    inside = any(low <= code <= high for low, high in item.ranges)
    return inside != item.negated


def _segment_matches(pattern: SegmentPattern, text: str) -> bool:
    """Match one segment: greedy, with a single backtrack point for the last star."""
    p = t = 0
    star_p = -1
    star_t = 0
    size = len(pattern)
    length = len(text)
    while t < length:
        if p < size and pattern[p].kind == "star":
            star_p = p
            star_t = t
            p += 1
        elif p < size and _item_matches(pattern[p], text[t]):
            p += 1
            t += 1
        elif star_p != -1:
            p = star_p + 1
            star_t += 1
            t = star_t
        else:
            return False
    while p < size and pattern[p].kind == "star":
        p += 1
    return p == size


def _refuse(reason: str) -> ConfigError:
    # The pattern itself is not echoed: a mistyped entry can be a pasted secret, and error text
    # reaches terminals and CI logs. `compile_globs` adds the position of the entry instead.
    return ConfigError(f"glob {reason}")


def _parse_set(text: str, start: int) -> tuple[_Item, int]:
    """Parse a `[...]` set starting at `text[start] == "["`; return the item and the index after
    its closing bracket."""
    position = start + 1
    negated = False
    if position < len(text) and text[position] in "!^":
        negated = True
        position += 1
    ranges: list[tuple[int, int]] = []
    first = True
    while position < len(text):
        char = text[position]
        if char == "]" and not first:
            return _Item("set", negated=negated, ranges=tuple(ranges)), position + 1
        first = False
        if position + 2 < len(text) and text[position + 1] == "-" and text[position + 2] != "]":
            low, high = ord(char), ord(text[position + 2])
            if low > high:
                raise _refuse("a set range runs backwards")
            ranges.append((low, high))
            position += 3
        else:
            ranges.append((ord(char), ord(char)))
            position += 1
    raise _refuse("a set is not closed")


def _parse_segment(text: str) -> SegmentPattern:
    items: list[_Item] = []
    position = 0
    while position < len(text):
        char = text[position]
        if char == "*":
            if not items or items[-1].kind != "star":  # `**` inside a segment is one star
                items.append(_Item("star"))
            position += 1
        elif char == "?":
            items.append(_Item("any"))
            position += 1
        elif char == "[":
            item, position = _parse_set(text, position)
            items.append(item)
        else:
            items.append(_Item("lit", char=char))
            position += 1
    return tuple(items)


def compile_glob(source: str, limits: Limits = DEFAULT_LIMITS) -> Glob:
    """Compile one pattern or raise `ConfigError` naming the reason (never the pattern)."""
    if not isinstance(source, str):
        raise ConfigError("glob must be a string")
    if not source:
        raise _refuse("is empty")
    if len(source) > limits.max_glob_chars:
        raise _refuse(f"is longer than {limits.max_glob_chars} characters")
    if any(ord(char) < 0x20 or ord(char) == 0x7F for char in source):
        raise _refuse("contains a control character")
    if "\\" in source:
        raise _refuse("contains a backslash (use / as the separator)")
    if source.startswith("/"):
        raise _refuse("must be relative (no leading /)")
    segments: list[SegmentPattern | None] = []
    for text in source.split("/"):
        if text == "":
            raise _refuse("has an empty segment")
        if text in {".", ".."}:
            raise _refuse(f"has a {text!r} segment")
        segments.append(None if text == GLOBSTAR else _parse_segment(text))
    return Glob(source, tuple(segments))


def compile_globs(
    sources: Iterable[str], limits: Limits = DEFAULT_LIMITS, *, what: str = "globs"
) -> tuple[Glob, ...]:
    """Compile a list, refusing more than `limits.max_globs` entries."""
    items = list(sources)
    if len(items) > limits.max_globs:
        raise ConfigError(f"{what}: more than {limits.max_globs} globs")
    compiled: list[Glob] = []
    for index, item in enumerate(items):
        try:
            compiled.append(compile_glob(item, limits))
        except ConfigError as error:
            raise ConfigError(f"{what}[{index}]: {error}") from None
    return tuple(compiled)


def any_match(globs: Sequence[Glob], path: str) -> bool:
    """True when at least one glob matches `path`."""
    return any(glob.matches(path) for glob in globs)
