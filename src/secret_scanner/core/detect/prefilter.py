"""Keyword pre-filter (PLAN.md D3, D4): a rule's regex runs only where one of its keywords occurs.

Case-insensitive substring search on bytes. Lower-casing a byte string touches ASCII letters only,
which is exactly what the keywords (lower-case printable ASCII) need.
"""

from __future__ import annotations

from collections.abc import Sequence


def lowered(data: bytes) -> bytes:
    """ASCII lower-case copy used for every keyword test."""
    return data.lower()


def contains_any(haystack_lower: bytes, needles: Sequence[bytes]) -> bool:
    return any(needle in haystack_lower for needle in needles)


def contains_all(haystack_lower: bytes, needles: Sequence[bytes]) -> bool:
    return all(needle in haystack_lower for needle in needles)
