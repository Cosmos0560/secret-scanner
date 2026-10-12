"""Guarded regular expressions (PLAN.md D3). The only module that imports `re`.

Every pattern of the tool, built-in or supplied by a user, is parsed here by a small own parser for
a restricted grammar and refused, with a named reason, if anything falls outside it. Nothing is
compiled before it passes. The guarantee comes from the grammar, not from timing:

* allowed: literals, escapes (`\\.` is a literal dot, `\\d \\w \\s \\xHH \\t`), character classes,
  non-capturing groups, exactly one named group `secret` (rules only), top-level and in-group
  alternation, the quantifiers `?`, `{n}` and `{m,n}`, the word boundary `\\b`, a leading `(?i)`,
  and a lookbehind or lookahead of a single character (`(?<![A-Za-z0-9])`);
* refused: `.` `*` `+` `{m,}` `^` `$`, lazy and possessive quantifiers, nested quantifiers (a
  quantified group that holds a quantifier), alternation inside a quantified group,
  backreferences, conditionals, capturing groups, inline flags other than a leading `(?i)`,
  every escape not listed above, non-ASCII or control characters, empty matches and empty
  alternatives;
* limits: at most `max_pattern_chars` characters, a maximum match width of at most
  `max_match_chars`, and a static cost (maximum width times the number of alternation paths) of at
  most `max_pattern_cost`;
* no ambiguity between neighbours: two variable-width items that follow each other (an optional
  item does not separate them) must not be able to match the same byte, so the point where the
  first ends is forced and backtracking never multiplies. `[a-z]{1,9}[a-z]{1,9}` is refused;
  `[0-9]{10,13}-[0-9]{10,13}` and `[a-z]{1,9}[0-9]{1,9}` are accepted.

Patterns are compiled as byte patterns: detection runs on bytes (PLAN.md D15), where `\\w`, `\\d`
and `(?i)` are ASCII-only.
"""

from __future__ import annotations

import math
import re
from collections.abc import Iterator
from dataclasses import dataclass
from enum import StrEnum
from typing import TypeAlias

from secret_scanner.core.errors import ConfigError
from secret_scanner.core.limits import DEFAULT_LIMITS, Limits

SECRET_GROUP = "secret"
MAX_GROUP_DEPTH = 6
MAX_PUBLIC_SET = 8  # a class with at most this many members carries no secret bits worth hiding

_ALL_BYTES = frozenset(range(256))
_DIGITS = frozenset(b"0123456789")
_WORD = frozenset(b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789_")
_SPACE = frozenset(b" \t\n\r\f\v")
_CLASS_ESCAPES: dict[str, frozenset[int]] = {
    "d": _DIGITS,
    "D": _ALL_BYTES - _DIGITS,
    "w": _WORD,
    "W": _ALL_BYTES - _WORD,
    "s": _SPACE,
    "S": _ALL_BYTES - _SPACE,
}
_BACKREFERENCE_DIGITS = frozenset("123456789")
_ANCHOR_ESCAPES = frozenset("AZz")
_FLAG_LETTERS = frozenset("aiLmsux")
_SET_OPERATORS = ("--", "&&", "||", "~~")  # Python warns that these may change meaning


class GuardReason(StrEnum):
    """Why a pattern was refused. Stable names: tests and docs refer to them."""

    TOO_LONG = "too-long"
    NOT_ASCII = "not-ascii"
    UNESCAPED_DOT = "unescaped-dot"
    ANCHOR = "anchor"
    UNBOUNDED_QUANTIFIER = "unbounded-quantifier"
    BAD_QUANTIFIER = "bad-quantifier"
    LAZY_QUANTIFIER = "lazy-or-possessive-quantifier"
    NESTED_QUANTIFIER = "nested-quantifier"
    ALTERNATION_IN_QUANTIFIED_GROUP = "alternation-in-quantified-group"
    BACKREFERENCE = "backreference"
    CONDITIONAL = "conditional"
    INLINE_FLAG = "inline-flag"
    UNSUPPORTED_GROUP = "unsupported-group"
    UNSUPPORTED_ESCAPE = "unsupported-escape"
    BAD_CLASS = "bad-character-class"
    LOOKAROUND_FORM = "lookaround-form"
    UNBALANCED = "unbalanced"
    TOO_DEEP = "too-deeply-nested"
    EMPTY_MATCH = "empty-match-or-alternative"
    TOO_WIDE = "too-wide"
    TOO_COSTLY = "too-costly"
    ADJACENT_VARIABLE = "adjacent-variable-width"
    SECRET_GROUP = "secret-group"
    NOT_COMPILABLE = "not-compilable"


class PatternRefusedError(ConfigError):
    """A pattern outside the allowed grammar or budget. `reason` names the rule it broke."""

    def __init__(self, reason: GuardReason, detail: str, offset: int | None = None) -> None:
        where = "" if offset is None else f" at offset {offset}"
        super().__init__(f"pattern refused ({reason.value}){where}: {detail}")
        self.reason = reason


# -- syntax tree ----------------------------------------------------------------------------


@dataclass(frozen=True, slots=True)
class _Atom:
    """Exactly one byte out of `members`."""

    members: frozenset[int]


@dataclass(frozen=True, slots=True)
class _Zero:
    """`\\b` or a lookaround: matches no characters."""


@dataclass(frozen=True, slots=True)
class _Seq:
    items: tuple[_Node, ...]


@dataclass(frozen=True, slots=True)
class _Alt:
    branches: tuple[_Node, ...]


@dataclass(frozen=True, slots=True)
class _Repeat:
    body: _Node
    low: int
    high: int


_Node: TypeAlias = _Atom | _Zero | _Seq | _Alt | _Repeat


def _children(node: _Node) -> tuple[_Node, ...]:
    if isinstance(node, _Seq):
        return node.items
    if isinstance(node, _Alt):
        return node.branches
    if isinstance(node, _Repeat):
        return (node.body,)
    return ()


def _width(node: _Node) -> tuple[int, int]:
    if isinstance(node, _Atom):
        return (1, 1)
    if isinstance(node, _Zero):
        return (0, 0)
    if isinstance(node, _Seq):
        widths = [_width(item) for item in node.items]
        return (sum(low for low, _ in widths), sum(high for _, high in widths))
    if isinstance(node, _Alt):
        alternatives = [_width(branch) for branch in node.branches]
        return (min(low for low, _ in alternatives), max(high for _, high in alternatives))
    low, high = _width(node.body)
    return (low * node.low, high * node.high)


def _paths(node: _Node) -> int:
    """Number of alternation paths through the node (1 without alternation)."""
    if isinstance(node, _Alt):
        return sum(_paths(branch) for branch in node.branches)
    total = 1
    for child in _children(node):
        total *= _paths(child)  # a quantified group holds no alternation (refused earlier)
    return total


def _bits(node: _Node) -> float:
    """Entropy bits of the shortest match, treating every byte of a class as equally likely."""
    if isinstance(node, _Atom):
        return math.log2(len(node.members))
    if isinstance(node, _Zero):
        return 0.0
    if isinstance(node, _Seq):
        return sum(_bits(item) for item in node.items)
    if isinstance(node, _Alt):
        return min(_bits(branch) for branch in node.branches)
    return node.low * _bits(node.body)


def _public_prefix(node: _Node) -> tuple[int, bool]:
    """(characters at the start that carry no secret bits, whether the whole node is public)."""
    if isinstance(node, _Atom):
        return (1, True) if len(node.members) <= MAX_PUBLIC_SET else (0, False)
    if isinstance(node, _Zero):
        return (0, True)
    if isinstance(node, _Seq):
        count = 0
        for item in node.items:
            added, whole = _public_prefix(item)
            count += added
            if not whole:
                return (count, False)
        return (count, True)
    if isinstance(node, _Alt):
        parts = [_public_prefix(branch) for branch in node.branches]
        return (min(added for added, _ in parts), False)
    added, whole = _public_prefix(node.body)
    if whole and node.low == node.high:
        return (added * node.low, True)
    return (added * node.low if whole else 0, False)


def _members(node: _Node) -> frozenset[int]:
    """Every byte any part of the node can match."""
    if isinstance(node, _Atom):
        return node.members
    return frozenset().union(*(_members(child) for child in _children(node)))


def _contains(node: _Node, kind: type) -> bool:
    return isinstance(node, kind) or any(_contains(child, kind) for child in _children(node))


def _contains_node(node: _Node, target: _Node) -> bool:
    return node is target or any(_contains_node(child, target) for child in _children(node))


def _delimit(node: _Node, pending: frozenset[int] | None) -> frozenset[int] | None:
    """Walk the pattern in match order. `pending` is the byte set of the variable-width items that
    no required character outside their set has followed yet. A variable-width item that can
    match a byte of a pending one is the shape that multiplies backtracking, and is refused."""
    if isinstance(node, _Atom):
        if pending is not None and node.members.isdisjoint(pending):
            return None
        return pending
    if isinstance(node, _Zero):
        return pending
    if isinstance(node, _Seq):
        for item in node.items:
            pending = _delimit(item, pending)
        return pending
    if isinstance(node, _Alt):
        outcomes = [_delimit(branch, pending) for branch in node.branches]
        left = [outcome for outcome in outcomes if outcome is not None]
        return frozenset().union(*left) if left else None
    if node.low == node.high:
        return _delimit(node.body, pending)
    members = _members(node.body)
    if pending is not None and not members.isdisjoint(pending):
        raise PatternRefusedError(
            GuardReason.ADJACENT_VARIABLE,
            "two adjacent variable-width items must not match the same characters",
        )
    # An item that may be empty does not separate what came before from what follows.
    return members if node.low > 0 or pending is None else pending | members


# -- parser ---------------------------------------------------------------------------------


class _Parser:
    def __init__(self, source: str, limits: Limits) -> None:
        self.source = source
        self.limits = limits
        self.pos = 0
        self.secret_groups = 0
        self.in_secret = False
        self.secret: _Repeat | None = None  # the secret group, as a transparent {1,1} repeat
        self.ignore_case = False

    def error(
        self, reason: GuardReason, detail: str, offset: int | None = None
    ) -> PatternRefusedError:
        return PatternRefusedError(reason, detail, self.pos if offset is None else offset)

    def peek(self, offset: int = 0) -> str:
        index = self.pos + offset
        return self.source[index] if index < len(self.source) else ""

    def parse(self) -> _Node:
        if self.source.startswith("(?i)"):
            self.ignore_case = True
            self.pos = 4
        node = self.alternation(0)
        if self.pos != len(self.source):
            raise self.error(GuardReason.UNBALANCED, "unmatched )")
        return node

    # -- structure -------------------------------------------------------------------------
    def alternation(self, depth: int) -> _Node:
        branches = [self.sequence(depth)]
        while self.peek() == "|":
            self.pos += 1
            branches.append(self.sequence(depth))
        return branches[0] if len(branches) == 1 else _Alt(tuple(branches))

    def sequence(self, depth: int) -> _Node:
        start = self.pos
        items: list[_Node] = []
        while self.pos < len(self.source) and self.peek() not in {"|", ")"}:
            items.append(self.quantified(depth))
        if not items:
            raise self.error(GuardReason.EMPTY_MATCH, "empty alternative or group", start)
        return items[0] if len(items) == 1 else _Seq(tuple(items))

    def quantified(self, depth: int) -> _Node:
        start = self.pos
        atom = self.atom(depth)
        char = self.peek()
        if char not in {"?", "{", "*", "+"}:
            return atom
        if isinstance(atom, _Zero):
            raise self.error(GuardReason.BAD_QUANTIFIER, "an assertion cannot be quantified")
        if self.secret is not None and _contains_node(atom, self.secret):
            raise self.error(GuardReason.SECRET_GROUP, "the secret group cannot be quantified")
        low, high = self.quantifier()
        if not isinstance(atom, _Atom):
            if _contains(atom, _Repeat):
                raise self.error(
                    GuardReason.NESTED_QUANTIFIER, "a quantified group contains a quantifier", start
                )
            if _contains(atom, _Alt):
                raise self.error(
                    GuardReason.ALTERNATION_IN_QUANTIFIED_GROUP,
                    "a quantified group contains an alternation",
                    start,
                )
            if _contains(atom, _Zero):
                raise self.error(
                    GuardReason.BAD_QUANTIFIER, "a quantified group contains an assertion", start
                )
        return _Repeat(atom, low, high)

    def quantifier(self) -> tuple[int, int]:
        char = self.peek()
        if char in {"*", "+"}:
            raise self.error(GuardReason.UNBOUNDED_QUANTIFIER, f"unbounded quantifier {char}")
        if char == "?":
            self.pos += 1
            low, high = 0, 1
        else:
            low, high = self.braces()
        follower = self.peek()
        if follower in {"?", "+"}:
            raise self.error(GuardReason.LAZY_QUANTIFIER, "lazy or possessive quantifier")
        if follower in {"*", "{"}:
            raise self.error(GuardReason.NESTED_QUANTIFIER, "a quantifier follows a quantifier")
        return low, high

    def braces(self) -> tuple[int, int]:
        start = self.pos
        end = self.source.find("}", start)
        body = self.source[start + 1 : end] if end != -1 else ""
        low_text, comma, high_text = body.partition(",")
        if end == -1 or not low_text.isascii() or not low_text.isdigit():
            raise self.error(GuardReason.BAD_QUANTIFIER, "malformed {m,n}", start)
        if comma and not high_text:
            raise self.error(GuardReason.UNBOUNDED_QUANTIFIER, "{m,} is unbounded", start)
        if comma and not (high_text.isascii() and high_text.isdigit()):
            raise self.error(GuardReason.BAD_QUANTIFIER, "malformed {m,n}", start)
        low = int(low_text)
        high = int(high_text) if comma else low
        if high > self.limits.max_match_chars:
            raise self.error(GuardReason.TOO_WIDE, "repeat count above the match width", start)
        if high < 1 or low > high:
            raise self.error(GuardReason.BAD_QUANTIFIER, "repeat range is empty", start)
        self.pos = end + 1
        return low, high

    # -- atoms -----------------------------------------------------------------------------
    def atom(self, depth: int) -> _Node:
        char = self.peek()
        if char == "(":
            return self.group(depth)
        if char == "[":
            return _Atom(self.fold(self.char_class()))
        if char == "\\":
            return self.escape()
        if char == ".":
            raise self.error(GuardReason.UNESCAPED_DOT, "an unescaped . matches any character")
        if char in {"^", "$"}:
            raise self.error(GuardReason.ANCHOR, "anchors are not allowed; lines are searched")
        if char in {"*", "+"}:
            raise self.error(GuardReason.UNBOUNDED_QUANTIFIER, f"unbounded quantifier {char}")
        if char in {"?", "{"}:
            raise self.error(GuardReason.BAD_QUANTIFIER, "a quantifier has nothing to repeat")
        if char in {"]", "}"}:
            raise self.error(GuardReason.UNBALANCED, f"stray {char}")
        self.pos += 1
        return _Atom(self.fold(frozenset({ord(char)})))

    def fold(self, members: frozenset[int]) -> frozenset[int]:
        if not self.ignore_case:
            return members
        extra: set[int] = set()
        for value in members:
            if 0x41 <= value <= 0x5A:
                extra.add(value + 32)
            elif 0x61 <= value <= 0x7A:
                extra.add(value - 32)
        return members | extra

    def escape(self) -> _Node:
        start = self.pos
        follower = self.peek(1)
        self.pos += 2
        if not follower:
            raise self.error(GuardReason.UNBALANCED, "trailing backslash", start)
        if follower == "b":
            return _Zero()
        if follower in _CLASS_ESCAPES:
            return _Atom(_CLASS_ESCAPES[follower])
        return _Atom(self.fold(frozenset({self.escaped_byte(follower, start, in_class=False)})))

    def escaped_byte(self, follower: str, start: int, *, in_class: bool) -> int:
        """The byte a literal escape stands for (`\\.`, `\\xHH`, `\\t`)."""
        if follower in _BACKREFERENCE_DIGITS:
            raise self.error(GuardReason.BACKREFERENCE, "backreferences are not allowed", start)
        if follower in _ANCHOR_ESCAPES or (follower == "B" and not in_class):
            raise self.error(GuardReason.ANCHOR, f"\\{follower} is an anchor", start)
        if follower == "t":
            return 0x09
        if follower == "x":
            digits = self.source[self.pos : self.pos + 2]
            if len(digits) != 2 or any(c not in "0123456789abcdefABCDEF" for c in digits):
                raise self.error(GuardReason.UNSUPPORTED_ESCAPE, "malformed \\xHH", start)
            self.pos += 2
            value = int(digits, 16)
            if value >= 0x80:
                raise self.error(GuardReason.NOT_ASCII, "\\xHH above 0x7f", start)
            return value
        if follower.isalnum():
            raise self.error(
                GuardReason.UNSUPPORTED_ESCAPE, f"\\{follower} is not supported", start
            )
        return ord(follower)

    def char_class(self) -> frozenset[int]:
        start = self.pos
        self.pos += 1
        negate = self.peek() == "^"
        if negate:
            self.pos += 1
        if self.peek() in {"]", ""}:
            raise self.error(GuardReason.BAD_CLASS, "empty or unterminated class", start)
        members: set[int] = set()
        while True:
            char = self.peek()
            if char == "":
                raise self.error(GuardReason.BAD_CLASS, "unterminated class", start)
            if char == "]":
                self.pos += 1
                break
            if char == "[":
                raise self.error(GuardReason.BAD_CLASS, "nested set or POSIX class", self.pos)
            if self.source.startswith(_SET_OPERATORS, self.pos):
                raise self.error(GuardReason.BAD_CLASS, "ambiguous set operator", self.pos)
            low = self.class_item()
            if isinstance(low, frozenset):
                members |= low
                continue
            if self.peek() == "-" and self.peek(1) not in {"]", ""}:
                self.pos += 1
                high = self.class_item()
                if isinstance(high, frozenset) or high < low:
                    raise self.error(GuardReason.BAD_CLASS, "invalid range", self.pos)
                members.update(range(low, high + 1))
            else:
                members.add(low)
        result = frozenset(members)
        if negate:
            result = _ALL_BYTES - self.fold(result)
        if not result:
            raise self.error(GuardReason.BAD_CLASS, "the class matches nothing", start)
        return result

    def class_item(self) -> int | frozenset[int]:
        char = self.peek()
        if char != "\\":
            self.pos += 1
            return ord(char)
        start = self.pos
        follower = self.peek(1)
        self.pos += 2
        if not follower:
            raise self.error(GuardReason.BAD_CLASS, "trailing backslash", start)
        if follower in _CLASS_ESCAPES:
            return _CLASS_ESCAPES[follower]
        return self.escaped_byte(follower, start, in_class=True)

    # -- groups ----------------------------------------------------------------------------
    def group(self, depth: int) -> _Node:
        start = self.pos
        if depth >= MAX_GROUP_DEPTH:
            raise self.error(GuardReason.TOO_DEEP, "groups are nested too deeply")
        rest = self.source[start + 1 :]
        if not rest.startswith("?"):
            raise self.error(
                GuardReason.UNSUPPORTED_GROUP, "capturing groups are not allowed; use (?:...)"
            )
        if rest.startswith("?:"):
            self.pos += 3
            return self.close(self.alternation(depth + 1))
        if rest.startswith("?P<"):
            return self.named_group(depth)
        lookaround = next(
            (form for form in ("?<=", "?<!", "?=", "?!") if rest.startswith(form)), None
        )
        if lookaround is not None:
            self.pos += 1 + len(lookaround)
            return self.lookaround()
        if rest.startswith("?P="):
            raise self.error(GuardReason.BACKREFERENCE, "named backreference")
        if rest.startswith("?("):
            raise self.error(GuardReason.CONDITIONAL, "conditional groups are not allowed")
        flags = rest[1:].split(")", 1)[0].split(":", 1)[0]
        if flags and all(c in _FLAG_LETTERS or c == "-" for c in flags):
            raise self.error(GuardReason.INLINE_FLAG, "only a leading (?i) is allowed")
        raise self.error(GuardReason.UNSUPPORTED_GROUP, "unsupported group syntax")

    def close(self, node: _Node) -> _Node:
        if self.peek() != ")":
            raise self.error(GuardReason.UNBALANCED, "unterminated group")
        self.pos += 1
        return node

    def named_group(self, depth: int) -> _Node:
        header = f"?P<{SECRET_GROUP}>"
        if not self.source.startswith(header, self.pos + 1):
            raise self.error(
                GuardReason.UNSUPPORTED_GROUP, f"the only named group is {SECRET_GROUP}"
            )
        if self.in_secret or self.secret_groups:
            raise self.error(GuardReason.SECRET_GROUP, "more than one secret group")
        self.secret_groups += 1
        self.pos += 1 + len(header)
        self.in_secret = True
        body = self.alternation(depth + 1)
        self.in_secret = False
        self.secret = _Repeat(self.close(body), 1, 1)
        return self.secret

    def lookaround(self) -> _Node:
        start = self.pos
        char = self.peek()
        if char in {"", ")", "(", "|"}:
            raise self.error(GuardReason.LOOKAROUND_FORM, "a lookaround holds one character class")
        if char == "[":
            self.char_class()
        elif char == "\\":
            node = self.escape()
            if isinstance(node, _Zero):
                raise self.error(GuardReason.LOOKAROUND_FORM, "no \\b inside a lookaround", start)
        elif char in {".", "*", "+", "?", "{", "^", "$"}:
            raise self.error(GuardReason.LOOKAROUND_FORM, "a lookaround holds one character")
        else:
            self.pos += 1
        if self.peek() != ")":
            raise self.error(
                GuardReason.LOOKAROUND_FORM, "a lookaround holds exactly one character class", start
            )
        self.pos += 1
        return _Zero()


# -- public API -----------------------------------------------------------------------------


@dataclass(frozen=True, slots=True)
class PatternMatch:
    """Where a pattern matched in a byte string. The secret span equals the match span for a
    pattern without a `secret` group."""

    start: int
    end: int
    secret_start: int
    secret_end: int


_TOKEN = object()


class GuardedPattern:
    """A compiled pattern that passed the guard. Only `compile_pattern` can make one."""

    __slots__ = (
        "_compiled",
        "_has_secret",
        "alternatives",
        "cost",
        "ignore_case",
        "paths",
        "secret_bits",
        "secret_min_width",
        "secret_public_chars",
        "source",
        "width_max",
        "width_min",
    )

    def __init__(
        self,
        token: object,
        *,
        source: str,
        compiled: re.Pattern[bytes],
        has_secret: bool,
        width: tuple[int, int],
        alternatives: int,
        paths: int,
        secret_bits: float,
        secret_min_width: int,
        secret_public_chars: int,
        ignore_case: bool,
    ) -> None:
        if token is not _TOKEN:
            raise TypeError("use compile_pattern()")
        self.source = source
        self._compiled = compiled
        self._has_secret = has_secret
        self.width_min, self.width_max = width
        self.alternatives = alternatives
        self.paths = paths
        self.cost = self.width_max * paths
        self.secret_bits = secret_bits
        self.secret_min_width = secret_min_width
        self.secret_public_chars = secret_public_chars
        self.ignore_case = ignore_case

    def __repr__(self) -> str:
        return f"GuardedPattern({self.source!r})"

    def finditer(self, data: bytes) -> Iterator[PatternMatch]:
        """Non-overlapping matches in `data`, which the caller keeps to one bounded line."""
        for found in self._compiled.finditer(data):
            if self._has_secret:
                secret_start, secret_end = found.span(SECRET_GROUP)
            else:
                secret_start, secret_end = found.span()
            yield PatternMatch(found.start(), found.end(), secret_start, secret_end)

    def search(self, data: bytes) -> PatternMatch | None:
        for found in self.finditer(data):
            return found
        return None


def compile_pattern(
    source: str, *, with_secret_group: bool = False, limits: Limits = DEFAULT_LIMITS
) -> GuardedPattern:
    """Parse, check and compile `source`; raise `PatternRefusedError` outside the grammar.

    `with_secret_group=True` is for rules: exactly one `(?P<secret>...)` group is then required.
    Internal patterns have none.
    """
    if len(source) > limits.max_pattern_chars:
        raise PatternRefusedError(
            GuardReason.TOO_LONG, f"{len(source)} characters, at most {limits.max_pattern_chars}"
        )
    if not source:
        raise PatternRefusedError(GuardReason.EMPTY_MATCH, "the pattern is empty")
    if not source.isascii() or any(ord(c) < 0x20 or ord(c) == 0x7F for c in source):
        raise PatternRefusedError(GuardReason.NOT_ASCII, "only printable ASCII is allowed")
    parser = _Parser(source, limits)
    node = parser.parse()
    if with_secret_group and parser.secret_groups != 1:
        raise PatternRefusedError(
            GuardReason.SECRET_GROUP, f"a rule needs one (?P<{SECRET_GROUP}>...)"
        )
    if not with_secret_group and parser.secret_groups:
        raise PatternRefusedError(
            GuardReason.SECRET_GROUP, "this pattern may not have a secret group"
        )
    low, high = _width(node)
    if low < 1:
        raise PatternRefusedError(GuardReason.EMPTY_MATCH, "the pattern can match the empty string")
    if high > limits.max_match_chars:
        raise PatternRefusedError(
            GuardReason.TOO_WIDE, f"match width {high} is above {limits.max_match_chars}"
        )
    paths = _paths(node)
    if high * paths > limits.max_pattern_cost:
        raise PatternRefusedError(
            GuardReason.TOO_COSTLY,
            f"cost {high * paths} is above {limits.max_pattern_cost}",
        )
    _delimit(node, None)
    secret = parser.secret
    body = secret.body if secret is not None else node
    try:
        compiled = re.compile(source.encode("ascii"))
    except (re.error, RecursionError, OverflowError) as error:
        raise PatternRefusedError(GuardReason.NOT_COMPILABLE, type(error).__name__) from error
    alternatives = len(node.branches) if isinstance(node, _Alt) else 1
    return GuardedPattern(
        _TOKEN,
        source=source,
        compiled=compiled,
        has_secret=secret is not None,
        width=(low, high),
        alternatives=alternatives,
        paths=paths,
        secret_bits=_bits(body),
        secret_min_width=_width(body)[0],
        secret_public_chars=_public_prefix(body)[0],
        ignore_case=parser.ignore_case,
    )
