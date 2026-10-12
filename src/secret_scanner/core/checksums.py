"""Offline token checksums (PLAN.md D4): detection confidence only, never verification of a live
secret. Pure functions over bytes; nothing here touches the network.

GitHub tokens (`ghp_`, `gho_`, `ghu_`, `ghs_`, `ghr_`) are the prefix, 30 characters of entropy
and a 6-character checksum: the CRC32 of those 30 characters, base62 encoded and left-padded with
`0`. The format is taken from GitHub's public description of its token formats; it cannot be
confirmed against a live token offline (listed as a limitation).
"""

from __future__ import annotations

import zlib

BASE62 = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz"
GITHUB_PREFIX_CHARS = 4  # `ghp_`
GITHUB_ENTROPY_CHARS = 30
GITHUB_CHECKSUM_CHARS = 6
GITHUB_BODY_CHARS = GITHUB_ENTROPY_CHARS + GITHUB_CHECKSUM_CHARS


def base62_encode(value: int, width: int) -> str:
    """`value` in base62, left-padded with `0` to `width` characters."""
    if value < 0 or width < 1:
        raise ValueError("value must not be negative and width must be positive")
    digits: list[str] = []
    while value:
        value, remainder = divmod(value, 62)
        digits.append(BASE62[remainder])
    return "".join(reversed(digits)).rjust(width, "0")


def github_checksum(entropy: bytes) -> str:
    """The 6-character checksum of 30 characters of token entropy."""
    if len(entropy) != GITHUB_ENTROPY_CHARS:
        raise ValueError("GitHub token entropy is 30 characters")
    return base62_encode(zlib.crc32(entropy), GITHUB_CHECKSUM_CHARS)


def github_token_checksum_valid(token: bytes) -> bool:
    """True when a `gh?_` + 36 characters token carries a correct checksum."""
    if len(token) != GITHUB_PREFIX_CHARS + GITHUB_BODY_CHARS:
        return False
    body = token[GITHUB_PREFIX_CHARS:]
    expected = github_checksum(body[:GITHUB_ENTROPY_CHARS])
    return body[GITHUB_ENTROPY_CHARS:] == expected.encode("ascii")
