"""Private key blocks (PLAN.md D6): a line-based state machine, not a regex over the file.

A header line (`-----BEGIN <type> PRIVATE KEY-----`, or the PGP block header), then up to
`MAX_KEY_LINES` lines of base64 body (header fields such as `Proc-Type:` and blank lines allowed),
then the matching END line. A finding needs the header plus at least `MIN_BODY_CHARS` base64 body
characters, so documentation and code that only mention a header do not fire.

* complete block (END seen): confidence high; body without END inside the limits: medium;
* ENCRYPTED keys (header type or `Proc-Type: 4,ENCRYPTED`): severity medium, others critical;
* the escaped one-line form of JSON service-account files (a header, then literal backslash-n
  sequences, on a single line) is recognised on that line;
* the "secret" is the body with everything but base64 characters removed, so the same key in LF
  and CRLF files has the same fingerprint. Only the key type, base64 length and hash are shown.

The scanner is fed one line at a time and answers with the byte spans of that line it protects,
so rules and the entropy detector do not report a key's body a second time.
"""

from __future__ import annotations

from dataclasses import dataclass, field

from secret_scanner.core.detect.match import Match
from secret_scanner.core.limits import DEFAULT_LIMITS, Limits
from secret_scanner.core.lines import column_of
from secret_scanner.core.models import Confidence, Detector, Severity
from secret_scanner.core.regex_guard import GuardedPattern, compile_pattern
from secret_scanner.core.rules import PRIVATE_KEY_ID

MIN_BODY_CHARS = 64
HEADER_KEYWORD = b"private key"
END_MARKER = b"-----END"
_BASE64 = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/="
_BASE64_SET = frozenset(_BASE64)
_STRING_END = frozenset(b"\"',;)}]")
_ESCAPED_NEWLINE = b"\\n"
_ESCAPED_RETURN = b"\\r"
_HEADER_PATTERN = (
    "-----BEGIN PRIVATE KEY-----"
    "|-----BEGIN (?:RSA|DSA|EC|OPENSSH|ENCRYPTED) PRIVATE KEY-----"
    "|-----BEGIN PGP PRIVATE KEY BLOCK-----"
)
_NAME_BYTES = frozenset(b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz-")


def _is_base64(text: bytes) -> bool:
    return bool(text) and not text.translate(None, _BASE64)


def _leading_base64(text: bytes) -> bytes:
    """The longest prefix of `text` made of base64 characters."""
    index = 0
    while index < len(text) and text[index] in _BASE64_SET:
        index += 1
    return text[:index]


def _is_header_field(text: bytes) -> bool:
    name, colon, _ = text.partition(b":")
    return bool(colon) and bool(name) and all(byte in _NAME_BYTES for byte in name)


def _label_of(header: bytes) -> str:
    """The key type from a matched header: "", RSA, DSA, EC, OPENSSH, ENCRYPTED or PGP."""
    words = header.strip(b"-").split()
    if words[1] == b"PGP":
        return "PGP"
    return words[1].decode("ascii") if words[1] != b"PRIVATE" else ""


@dataclass(slots=True)
class _Block:
    label: str
    line: int
    col_start: int
    col_end: int
    consumed: int = 0
    encrypted: bool = False
    body: bytearray = field(default_factory=bytearray)


class PrivateKeyScanner:
    """Incremental scanner: `feed` every line in order, then `finish`."""

    def __init__(self, limits: Limits = DEFAULT_LIMITS) -> None:
        self._max_lines = limits.max_key_lines
        self._header: GuardedPattern = compile_pattern(_HEADER_PATTERN, limits=limits)
        self._block: _Block | None = None
        self.matches: list[Match] = []

    # -- results ---------------------------------------------------------------------------
    def _emit(self, block: _Block, *, complete: bool) -> None:
        if len(block.body) < MIN_BODY_CHARS:
            return
        self.matches.append(
            Match(
                rule_id=PRIVATE_KEY_ID,
                detector=Detector.PRIVATE_KEY,
                severity=Severity.MEDIUM if block.encrypted else Severity.CRITICAL,
                confidence=Confidence.HIGH if complete else Confidence.MEDIUM,
                line=block.line,
                col_start=block.col_start,
                col_end=block.col_end,
                secret=bytes(block.body),
                shown_chars=0,
                kind_label=block.label,
            )
        )

    # -- the state machine -----------------------------------------------------------------
    def feed(self, number: int, line: bytes, lowered_line: bytes) -> list[tuple[int, int]]:
        """Consume one line; return the byte spans of it that belong to a key (to be ignored by
        the other detectors)."""
        block = self._block
        if block is not None:
            spans = self._continue(block, line)
            if spans is not None:
                return spans
        if HEADER_KEYWORD not in lowered_line:
            return []
        return self._start(number, line)

    def _continue(self, block: _Block, line: bytes) -> list[tuple[int, int]] | None:
        """Handle a line while `block` is open. None means the line ended the block without
        belonging to it and must be looked at again as an ordinary line."""
        stripped = line.strip()
        whole = [(0, len(line))]
        if stripped.startswith(END_MARKER):
            self._emit(block, complete=True)
            self._block = None
            return whole
        if block.consumed >= self._max_lines:
            self._emit(block, complete=False)
            self._block = None
            return None
        if not stripped:
            block.consumed += 1
            return whole
        if _is_base64(stripped):
            block.body.extend(stripped)
            block.consumed += 1
            return whole
        if _is_header_field(stripped):
            lowered = stripped.lower()
            if lowered.startswith(b"proc-type") and b"encrypted" in lowered:
                block.encrypted = True
            block.consumed += 1
            return whole
        self._emit(block, complete=False)
        self._block = None
        return None

    def _start(self, number: int, line: bytes) -> list[tuple[int, int]]:
        found = self._header.search(line)
        if found is None:
            return []
        label = _label_of(line[found.start : found.end])
        col_start = column_of(line, found.start)
        col_end = column_of(line, found.end)
        tail = line[found.end :]
        if not tail.strip():
            self._block = _Block(label, number, col_start, col_end, encrypted=label == "ENCRYPTED")
            return [(found.start, len(line))]
        segment, end_marker, _ = tail.partition(END_MARKER)
        if _ESCAPED_NEWLINE not in segment:
            return []
        cleaned = segment.replace(_ESCAPED_NEWLINE, b"").replace(_ESCAPED_RETURN, b"").strip()
        body = _leading_base64(cleaned)
        # What follows the body must be the end of the string (a quote, a comma, a bracket), not
        # more prose: a header that is only mentioned is not a key.
        if not body or (cleaned[len(body) :] and cleaned[len(body)] not in _STRING_END):
            return []
        block = _Block(label, number, col_start, col_end, body=bytearray(body))
        block.encrypted = label == "ENCRYPTED"
        self._emit(block, complete=bool(end_marker))
        end = len(line)
        if end_marker:
            end = found.end + len(segment) + len(END_MARKER)
        return [(found.start, end)]

    def finish(self) -> None:
        """Close a block that ran to the end of the input without an END line."""
        if self._block is not None:
            self._emit(self._block, complete=False)
            self._block = None
