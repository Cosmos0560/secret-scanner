"""Finding fingerprint (PLAN.md D8).

`fingerprint = sha256(b"secret-scanner/fingerprint/v1\\x00" + rule_id + b"\\x00" + path_key +
b"\\x00" + secret)`, first 32 hex digits. Line, column and commit are deliberately not part of it,
so a baseline survives edits and a history scan reports each secret once per path.
"""

from __future__ import annotations

import hashlib
from collections.abc import Sequence

FINGERPRINT_DOMAIN = b"secret-scanner/fingerprint/v1\x00"
FINGERPRINT_HEX_CHARS = 32


def path_key_from_parts(parts: Sequence[str]) -> str:
    """Join path components with `/`, the separator fingerprints are defined over.

    Platform code walks with the native separator and hands the components here, so the same file
    has the same fingerprint on Windows and POSIX.
    """
    if not parts:
        raise ValueError("a path needs at least one component")
    for part in parts:
        if not part or "/" in part:
            raise ValueError("a path component is empty or contains a separator")
    return "/".join(parts)


def fingerprint(rule_id: str, path_key: str, secret: bytes) -> str:
    """Return the 32-hex-digit fingerprint of one secret at one path found by one rule."""
    digest = hashlib.sha256()
    digest.update(FINGERPRINT_DOMAIN)
    digest.update(rule_id.encode("utf-8"))
    digest.update(b"\x00")
    digest.update(path_key.encode("utf-8", errors="surrogateescape"))
    digest.update(b"\x00")
    digest.update(secret)
    return digest.hexdigest()[:FINGERPRINT_HEX_CHARS]
