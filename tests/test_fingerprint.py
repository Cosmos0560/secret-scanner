"""Fingerprints: golden vectors, domain separation, and platform independence."""

from __future__ import annotations

import hashlib

import pytest

from secret_scanner.core.fingerprint import (
    FINGERPRINT_DOMAIN,
    fingerprint,
    path_key_from_parts,
)
from secret_scanner.core.redact import display_hash8

SECRET = b"golden-vector-secret-0001"  # neutral test material, not shaped like a token
RULE = "aws-access-key-id"
PATH = "config/settings.py"

GOLDEN = "a59a85d9f7760495ac6d7dda35bff66d"
GOLDEN_DISPLAY_HASH = "8344f2b7"
GOLDEN_SURROGATE_PATH = "7c5add01012a4db2aefb2766111ea35b"


def test_golden_vector() -> None:
    assert fingerprint(RULE, PATH, SECRET) == GOLDEN
    assert display_hash8(SECRET) == GOLDEN_DISPLAY_HASH


def test_independent_recomputation() -> None:
    material = b"secret-scanner/fingerprint/v1\x00" + RULE.encode() + b"\x00" + PATH.encode()
    expected = hashlib.sha256(material + b"\x00" + SECRET).hexdigest()[:32]
    assert fingerprint(RULE, PATH, SECRET) == expected
    assert len(expected) == 32


def test_each_input_changes_the_fingerprint() -> None:
    base = fingerprint(RULE, PATH, SECRET)
    assert fingerprint("github-token", PATH, SECRET) != base
    assert fingerprint(RULE, "config/other.py", SECRET) != base
    assert fingerprint(RULE, PATH, SECRET + b"x") != base


def test_field_boundaries_cannot_be_shifted() -> None:
    assert fingerprint("ab", "c", b"d") != fingerprint("a", "bc", b"d")
    assert fingerprint("a", "b", b"cd") != fingerprint("a", "bc", b"d")


def test_domain_separation_from_the_display_hash() -> None:
    assert FINGERPRINT_DOMAIN != b"secret-scanner/display/v1\x00"
    assert not fingerprint(RULE, PATH, SECRET).startswith(display_hash8(SECRET))
    plain = hashlib.sha256(SECRET).hexdigest()[:32]
    assert fingerprint(RULE, PATH, SECRET) != plain


def test_non_utf8_path_bytes_are_exact() -> None:
    surrogate_path = "dir/na" + chr(0xDC80) + "me.txt"
    assert fingerprint("github-token", surrogate_path, SECRET) == GOLDEN_SURROGATE_PATH
    raw = b"secret-scanner/fingerprint/v1\x00github-token\x00dir/na\x80me.txt\x00" + SECRET
    assert hashlib.sha256(raw).hexdigest()[:32] == GOLDEN_SURROGATE_PATH


def test_line_column_and_commit_are_not_inputs() -> None:
    # The function has no such parameter, so moving a secret within a file or across commits
    # cannot change its fingerprint (PLAN.md D8). Same inputs, same value, on every call.
    assert fingerprint(RULE, PATH, SECRET) == fingerprint(RULE, PATH, SECRET)


def test_path_key_is_built_with_forward_slashes_on_every_platform() -> None:
    assert path_key_from_parts(["config", "settings.py"]) == PATH
    assert fingerprint(RULE, path_key_from_parts(["config", "settings.py"]), SECRET) == GOLDEN
    assert path_key_from_parts(["single"]) == "single"


@pytest.mark.parametrize("parts", [[], [""], ["a", ""], ["a/b"], ["a", "b/c"]])
def test_path_key_refuses_malformed_components(parts: list[str]) -> None:
    with pytest.raises(ValueError, match="path"):
        path_key_from_parts(parts)
