"""High-entropy strings (PLAN.md D5).

Candidates are maximal runs of the base64 / base64url alphabet, cut at quotes, whitespace and other
punctuation; a run that is only hex digits is a hex token. Score: Shannon entropy in bits per
character over the token's own character frequencies. A bare high-entropy string has confidence
low; one that follows an assignment whose key looks like a credential has confidence medium; hex
tokens are reported only with that context, because hashes are everywhere.
"""

from __future__ import annotations

import math
from bisect import bisect_right
from collections import Counter
from collections.abc import Iterator
from dataclasses import dataclass

from secret_scanner.core.detect.match import Match
from secret_scanner.core.errors import ConfigError
from secret_scanner.core.limits import DEFAULT_LIMITS, Limits
from secret_scanner.core.lines import ColumnCursor
from secret_scanner.core.models import Confidence, Detector, Severity
from secret_scanner.core.redact import entropy_shown_chars
from secret_scanner.core.regex_guard import GuardedPattern, compile_pattern
from secret_scanner.core.rules import ENTROPY_BASE64_ID, ENTROPY_HEX_ID, MIN_SECRET_BITS

DEFAULT_BASE64_THRESHOLD = 4.5
DEFAULT_HEX_THRESHOLD = 3.0
DEFAULT_MIN_LENGTH = 20
HEX_MIN_LENGTH = 32
BASE64_THRESHOLD_BOUNDS = (3.5, 6.0)
HEX_THRESHOLD_BOUNDS = (2.5, 4.0)
MIN_LENGTH_BOUNDS = (16, 64)

# `=` is base64 padding only at the end of a token: inside a run it separates a key from its value
# (`API_KEY=value`), so a token starts after it and the assignment keeps its context.
TOKEN_ALPHABET = "A-Za-z0-9+/_-"
TOKEN_PADDING = "="
CONTEXT_GAP_MAX = 8
_GAP_BYTES = frozenset(b" \t\"'")
_HEX_BYTES = b"0123456789abcdefABCDEF"
_UUID_DASHES = (8, 13, 18, 23)
_UUID_LENGTH = 36
_SRI_PREFIXES = (b"sha256-", b"sha384-", b"sha512-")
MAX_PATH_SEPARATORS = 2

# Pattern for the key of an assignment: the key text, then an optional quote, blanks, `:` or `=`.
_CONTEXT_PATTERN = (
    "(?i)(?:secret|token|passw|api_?key|private|credential|auth)"
    "[A-Za-z0-9_.-]{0,40}[\"']?[ \\t]{0,4}[:=]"
)

LOCKFILE_NAMES = frozenset(
    {
        "package-lock.json",
        "yarn.lock",
        "pnpm-lock.yaml",
        "poetry.lock",
        "uv.lock",
        "cargo.lock",
        "go.sum",
        "composer.lock",
        "gemfile.lock",
    }
)
EXCLUDED_SUFFIXES = (".min.js", ".min.css", ".map", ".svg")


@dataclass(frozen=True, slots=True)
class EntropyConfig:
    """Entropy detector settings; values outside the D5 bounds are refused (D19)."""

    enabled: bool = True
    base64_threshold: float = DEFAULT_BASE64_THRESHOLD
    hex_threshold: float = DEFAULT_HEX_THRESHOLD
    min_length: int = DEFAULT_MIN_LENGTH

    def __post_init__(self) -> None:
        _within("entropy base64 threshold", self.base64_threshold, BASE64_THRESHOLD_BOUNDS)
        _within("entropy hex threshold", self.hex_threshold, HEX_THRESHOLD_BOUNDS)
        _within("entropy minimum length", self.min_length, MIN_LENGTH_BOUNDS)


def _within(what: str, value: float, bounds: tuple[float, float]) -> None:
    if isinstance(value, bool) or not bounds[0] <= value <= bounds[1]:
        raise ConfigError(f"{what} must be between {bounds[0]:g} and {bounds[1]:g}")


def shannon_entropy(data: bytes) -> float:
    """Bits per character over the byte frequencies of `data` (0.0 for empty input)."""
    if not data:
        return 0.0
    total = len(data)
    return -sum((count / total) * math.log2(count / total) for count in Counter(data).values())


def path_excluded(path_key: str) -> bool:
    """Files the entropy detector skips by default: lockfiles, minified files, source maps, SVG."""
    name = path_key.rsplit("/", 1)[-1].lower()
    return name in LOCKFILE_NAMES or name.endswith(EXCLUDED_SUFFIXES)


def _is_uuid(token: bytes) -> bool:
    if len(token) != _UUID_LENGTH:
        return False
    return all(
        (byte == 0x2D) if index in _UUID_DASHES else (byte in _HEX_BYTES)
        for index, byte in enumerate(token)
    )


def _character_classes(token: bytes) -> int:
    upper = any(0x41 <= byte <= 0x5A for byte in token)
    lower = any(0x61 <= byte <= 0x7A for byte in token)
    digit = any(0x30 <= byte <= 0x39 for byte in token)
    return int(upper) + int(lower) + int(digit)


class EntropyDetector:
    """Finds high-entropy tokens in one line at a time."""

    def __init__(self, config: EntropyConfig, limits: Limits = DEFAULT_LIMITS) -> None:
        self.config = config
        self._hex_min = max(HEX_MIN_LENGTH, config.min_length)
        run = f"[{TOKEN_ALPHABET}]"
        edge = f"[A-Za-z0-9+/{TOKEN_PADDING}_-]"
        size = f"{{{config.min_length},{limits.max_entropy_token_chars}}}"
        self._tokens: GuardedPattern = compile_pattern(
            f"(?<!{run}){run}{size}{TOKEN_PADDING}{{0,2}}(?!{edge})", limits=limits
        )
        self._context: GuardedPattern = compile_pattern(_CONTEXT_PATTERN, limits=limits)

    def _has_context(self, line: bytes, token_start: int, ends: list[int]) -> bool:
        """True when an assignment key ends just before the token (only blanks and quotes
        between them)."""
        # Only the nearest key that ends before the token can qualify: an earlier one has the
        # nearer key's own text in its gap.
        index = bisect_right(ends, token_start) - 1
        if index < 0:
            return False
        gap = line[ends[index] : token_start]
        return len(gap) <= CONTEXT_GAP_MAX and all(byte in _GAP_BYTES for byte in gap)

    def scan_line(self, line: bytes, number: int) -> Iterator[tuple[int, int, Match]]:
        """Yield `(start, end, match)` byte spans of tokens in `line`."""
        context_ends: list[int] | None = None
        columns = ColumnCursor(line)
        for found in self._tokens.finditer(line):
            token = line[found.start : found.end]
            if token.startswith(_SRI_PREFIXES) or _is_uuid(token):
                continue
            if _character_classes(token) < 2 or token.count(b"/") > MAX_PATH_SEPARATORS:
                continue
            is_hex = not token.translate(None, _HEX_BYTES)
            if is_hex and len(token) < self._hex_min:
                continue
            threshold = self.config.hex_threshold if is_hex else self.config.base64_threshold
            entropy = shannon_entropy(token)
            if entropy < threshold or len(token) * entropy < MIN_SECRET_BITS:
                continue
            if context_ends is None:
                context_ends = [m.end for m in self._context.finditer(line)]
            has_context = self._has_context(line, found.start, context_ends)
            if is_hex and not has_context:
                continue
            yield (
                found.start,
                found.end,
                Match(
                    rule_id=ENTROPY_HEX_ID if is_hex else ENTROPY_BASE64_ID,
                    detector=Detector.ENTROPY,
                    severity=Severity.MEDIUM,
                    confidence=Confidence.MEDIUM if has_context else Confidence.LOW,
                    line=number,
                    col_start=columns.column(found.start),
                    col_end=columns.column(found.end),
                    secret=token,
                    shown_chars=entropy_shown_chars(len(token)),
                ),
            )
