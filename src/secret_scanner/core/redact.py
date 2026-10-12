"""Redaction (PLAN.md D7): the only form in which a secret is ever shown.

Shape: `<shown>... [<length> chars, sha256:<8 hex>]`, for example `AKIA... [20 chars,
sha256:1a2b3c4d]`; private keys: `[RSA private key, 1592 base64 chars, sha256:1a2b3c4d]`.

`shown` is a rule's fixed public prefix and carries no secret bits. It can never exceed
`MAX_SHOWN_CHARS` or a quarter of the secret's length, and this module refuses (it raises) rather
than clamps, so a wrong rule definition is noticed instead of leaking quietly.
"""

from __future__ import annotations

import hashlib

from secret_scanner.core.errors import ConfigError
from secret_scanner.core.models import Redacted

DISPLAY_DOMAIN = b"secret-scanner/display/v1\x00"
DISPLAY_HASH_CHARS = 8
MAX_SHOWN_CHARS = 12
ENTROPY_SHOWN_CHARS = 4
ENTROPY_SHOWN_MIN_LENGTH = 32

_PRIVATE_KEY_TEXT: dict[str, str] = {
    "": "private key",
    "RSA": "RSA private key",
    "DSA": "DSA private key",
    "EC": "EC private key",
    "OPENSSH": "OPENSSH private key",
    "ENCRYPTED": "ENCRYPTED private key",
    "PGP": "PGP private key",
}
PRIVATE_KEY_LABELS = frozenset(_PRIVATE_KEY_TEXT)


def display_hash8(secret: bytes) -> str:
    """Domain-separated short hash shown next to a redacted secret."""
    return hashlib.sha256(DISPLAY_DOMAIN + secret).hexdigest()[:DISPLAY_HASH_CHARS]


def max_shown_chars(secret_length: int) -> int:
    """The most characters that may be shown of a secret of this length."""
    return min(MAX_SHOWN_CHARS, secret_length // 4)


def check_shown_chars(shown_chars: int, min_secret_chars: int) -> None:
    """Rule-loader check: `shown_chars` is at most 12 and a quarter of the minimum length."""
    if shown_chars < 0:
        raise ConfigError("shown_chars must not be negative")
    if shown_chars > max_shown_chars(min_secret_chars):
        raise ConfigError("shown_chars exceeds 12 or a quarter of the minimum secret length")


def entropy_shown_chars(token_length: int) -> int:
    """Entropy detector: the first 4 characters if the token has at least 32, else nothing."""
    return ENTROPY_SHOWN_CHARS if token_length >= ENTROPY_SHOWN_MIN_LENGTH else 0


def _printable_ascii(prefix: bytes) -> str:
    return "".join(chr(byte) if 0x20 <= byte < 0x7F else "?" for byte in prefix)


def redact_secret(secret: bytes, shown_chars: int) -> Redacted:
    """Redact a secret, showing its first `shown_chars` bytes (a rule's public prefix)."""
    if not secret:
        raise ValueError("cannot redact an empty secret")
    if shown_chars < 0 or shown_chars > max_shown_chars(len(secret)):
        raise ValueError("shown_chars is outside what may be shown of this secret")
    shown = _printable_ascii(secret[:shown_chars])
    hash8 = display_hash8(secret)
    detail = f"[{len(secret)} chars, sha256:{hash8}]"
    text = f"{shown}... {detail}" if shown else detail
    return Redacted(shown=shown, length=len(secret), hash8=hash8, text=text)


def redact_private_key(body: bytes, label: str) -> Redacted:
    """Redact a private key block: only its type, base64 length and hash are shown.

    `body` is the key's base64 body with every non-base64 character removed (PLAN.md D6), so the
    same key in LF and CRLF files has the same hash. `label` is one of `PRIVATE_KEY_LABELS`.
    """
    kind = _PRIVATE_KEY_TEXT.get(label)
    if kind is None:
        raise ValueError("unknown private key label")
    if not body:
        raise ValueError("cannot redact an empty private key body")
    hash8 = display_hash8(body)
    text = f"[{kind}, {len(body)} base64 chars, sha256:{hash8}]"
    return Redacted(shown="", length=len(body), hash8=hash8, text=text)
