"""Fake secrets for tests and the demo (PLAN.md D16). Pure; used only at runtime.

A fake exists only in memory and in temporary directories: it is built from the fragments of a
rule's `fake` spec (prefix parts are stored separately and joined here), its body is derived
deterministically from `sha256(seed)` mapped onto the rule's charset (no `random` module), and,
where the charset allows, it carries the marker `FAKE` (`fa4e` in hex) so a person reading a log
sees what it is. Checksum rules get a correct checksum computed here, or a deliberately wrong one
for the negative case. Private key fakes are random base64 between header and footer lines that
are themselves joined from parts; they are not keys.

Nothing in this module is a secret-shaped string: alphabets, markers and fragments only.
"""

from __future__ import annotations

import base64
import hashlib
from collections.abc import Sequence

from secret_scanner.core.checksums import (
    GITHUB_CHECKSUM_CHARS,
    GITHUB_ENTROPY_CHARS,
    github_checksum,
)
from secret_scanner.core.models import Checksum, FakeSegment, Rule

CHARSETS: dict[str, str] = {
    "base32": "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567",
    "base62": "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789",
    "base64": "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/",
    "base64url": "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789_-",
    "hex": "0123456789abcdef",
    "hex-upper": "0123456789ABCDEF",
    "digits": "0123456789",
}
MARKERS: dict[str, str] = {
    "base32": "FAKE",
    "base62": "FAKE",
    "base64": "FAKE",
    "base64url": "FAKE",
    "hex": "fa4e",
    "hex-upper": "FA4E",
}
MARKER_OFFSET = 2
MIN_LENGTH_FOR_MARKER = 8
MAX_SEGMENT_CHARS = 256

PRIVATE_KEY_LABELS = ("", "RSA", "DSA", "EC", "OPENSSH", "ENCRYPTED", "PGP")
BASE64_BODY_ALPHABET = CHARSETS["base62"] + "+/"


def body(seed: str, charset: str, length: int, *, salt: str = "") -> str:
    """`length` characters of `charset`, derived from the seed (and a per-segment salt)."""
    alphabet = CHARSETS[charset]
    out: list[str] = []
    counter = 0
    while len(out) < length:
        digest = hashlib.sha256(f"{seed}:{salt}:{counter}".encode()).digest()
        counter += 1
        out.extend(alphabet[byte % len(alphabet)] for byte in digest)
    text = "".join(out[:length])
    marker = MARKERS.get(charset)
    if marker is not None and length >= MIN_LENGTH_FOR_MARKER:
        text = text[:MARKER_OFFSET] + marker + text[MARKER_OFFSET + len(marker) :]
    return text


def _wrong_checksum(correct: str) -> str:
    """A checksum that differs from `correct` in its last character, in the same alphabet."""
    last = "0" if correct[-1] != "0" else "1"
    return correct[:-1] + last


def build_fake(rule: Rule, seed: str = "fake", *, valid_checksum: bool = True) -> str:
    """The fake text for `rule`: what its regex matches, with the secret inside it."""
    return assemble(rule.fake, seed, rule.checksum, valid_checksum=valid_checksum)


def assemble(
    segments: Sequence[FakeSegment],
    seed: str,
    checksum: Checksum | None = None,
    *,
    valid_checksum: bool = True,
) -> str:
    pieces: list[str] = []
    for index, segment in enumerate(segments):
        if segment.parts:
            pieces.append("".join(segment.parts))
        else:
            pieces.append(body(seed, segment.charset, segment.length, salt=str(index)))
    text = "".join(pieces)
    if checksum is Checksum.GITHUB_CRC32:
        text = _with_github_checksum(text, valid=valid_checksum)
    return text


def _with_github_checksum(text: str, *, valid: bool) -> str:
    """Replace the last 6 characters with the checksum of the 30 before them."""
    head = text[:-GITHUB_CHECKSUM_CHARS]
    entropy = head[-GITHUB_ENTROPY_CHARS:]
    checksum = github_checksum(entropy.encode("ascii"))
    return head + (checksum if valid else _wrong_checksum(checksum))


def fake_private_key(
    seed: str = "fake",
    *,
    label: str = "RSA",
    body_lines: int = 3,
    line_chars: int = 64,
    newline: str = "\n",
    complete: bool = True,
    header_fields: Sequence[str] = (),
) -> str:
    """A private key block whose header and footer are joined from parts and whose body is random
    base64. `label` is one of `PRIVATE_KEY_LABELS`; `PGP` gives the armored form."""
    if label not in PRIVATE_KEY_LABELS:
        raise ValueError("unknown private key label")
    if label == "PGP":
        kind = "PGP" + " PRIVATE" + " KEY" + " BLOCK"
    elif label:
        kind = label + " PRIVATE" + " KEY"
    else:
        kind = "PRIVATE" + " KEY"
    lines = ["-----BEGIN " + kind + "-----"]
    if header_fields:
        lines.extend(header_fields)
        lines.append("")
    for number in range(body_lines):
        row = "".join(
            BASE64_BODY_ALPHABET[byte % len(BASE64_BODY_ALPHABET)]
            for byte in hashlib.sha256(f"{seed}:key:{number}".encode()).digest() * 2
        )
        lines.append(row[:line_chars])
    if complete:
        lines.append("-----END " + kind + "-----")
    return newline.join(lines) + newline


def fake_entropy_token(seed: str = "fake", *, kind: str = "base64", length: int = 43) -> str:
    """A high-entropy token for the entropy detector: base64url (or hex) of `sha256(seed)`
    outputs, with the marker at offset 2."""
    if kind not in {"base64", "hex"}:
        raise ValueError("kind is base64 or hex")
    parts: list[str] = []
    counter = 0
    while sum(len(part) for part in parts) < length:
        digest = hashlib.sha256(f"{seed}:entropy:{counter}".encode()).digest()
        counter += 1
        if kind == "hex":
            parts.append(digest.hex())
        else:
            parts.append(base64.urlsafe_b64encode(digest).decode("ascii").rstrip("="))
    text = "".join(parts)[:length]
    marker = "fa4e" if kind == "hex" else "FAKE"
    if length >= MIN_LENGTH_FOR_MARKER:
        text = text[:MARKER_OFFSET] + marker + text[MARKER_OFFSET + len(marker) :]
    return text
