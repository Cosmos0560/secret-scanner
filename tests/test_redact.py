"""Redaction: format, shown-character rules, and that nothing beyond the allowance is shown."""

from __future__ import annotations

import hashlib
from collections.abc import Callable

import pytest

from secret_scanner.core import redact
from secret_scanner.core.errors import ConfigError
from secret_scanner.core.redact import (
    MAX_SHOWN_CHARS,
    check_shown_chars,
    display_hash8,
    entropy_shown_chars,
    max_shown_chars,
    redact_private_key,
    redact_secret,
)

# Neutral test material: not shaped like any provider's token.
BODY = bytes(range(65, 65 + 20)) + b"-tail-of-neutral-bytes"


def test_format_with_a_shown_prefix() -> None:
    result = redact_secret(BODY, 4)
    digest = hashlib.sha256(b"secret-scanner/display/v1\x00" + BODY).hexdigest()[:8]
    assert result.shown == BODY[:4].decode()
    assert result.length == len(BODY)
    assert result.hash8 == digest
    assert result.text == f"{BODY[:4].decode()}... [{len(BODY)} chars, sha256:{digest}]"


def test_format_without_a_prefix_has_no_dots() -> None:
    result = redact_secret(BODY, 0)
    assert result.shown == ""
    assert result.text == f"[{len(BODY)} chars, sha256:{result.hash8}]"
    assert "..." not in result.text


def test_hash_is_deterministic_and_secret_dependent() -> None:
    assert redact_secret(BODY, 0).hash8 == redact_secret(BODY, 0).hash8
    assert redact_secret(BODY, 0).hash8 != redact_secret(BODY + b"x", 0).hash8
    assert display_hash8(BODY) == redact_secret(BODY, 0).hash8


def test_display_hash_is_domain_separated_from_a_plain_sha256() -> None:
    assert display_hash8(BODY) != hashlib.sha256(BODY).hexdigest()[:8]
    assert redact.DISPLAY_DOMAIN.startswith(b"secret-scanner/display/v1")


@pytest.mark.parametrize("length", [4, 8, 20, 47, 48, 49, 100, 256])
def test_never_shows_more_than_a_quarter_or_twelve_characters(length: int) -> None:
    secret = (b"abcdefghij" * 30)[:length]
    limit = max_shown_chars(length)
    assert limit == min(MAX_SHOWN_CHARS, length // 4)
    shown_max = redact_secret(secret, limit)
    assert len(shown_max.shown) == limit
    assert len(shown_max.shown) <= MAX_SHOWN_CHARS
    assert len(shown_max.shown) * 4 <= length
    with pytest.raises(ValueError, match="shown_chars"):
        redact_secret(secret, limit + 1)


def test_shown_prefix_outside_printable_ascii_is_masked() -> None:
    secret = b"\x00\x1b[31m\xff" + b"A" * 40
    result = redact_secret(secret, 6)
    assert result.shown == "??[31m"
    assert "\x1b" not in result.text


def test_refuses_empty_and_negative() -> None:
    with pytest.raises(ValueError, match="empty"):
        redact_secret(b"", 0)
    with pytest.raises(ValueError, match="shown_chars"):
        redact_secret(BODY, -1)


def test_rule_loader_check_for_shown_chars() -> None:
    check_shown_chars(4, 16)
    check_shown_chars(12, 48)
    check_shown_chars(0, 1)
    with pytest.raises(ConfigError):
        check_shown_chars(13, 200)
    with pytest.raises(ConfigError):
        check_shown_chars(5, 16)
    with pytest.raises(ConfigError):
        check_shown_chars(-1, 16)


def test_entropy_detector_shows_four_characters_only_for_long_tokens() -> None:
    assert entropy_shown_chars(31) == 0
    assert entropy_shown_chars(32) == 4
    assert entropy_shown_chars(256) == 4
    assert max_shown_chars(32) >= 4


def test_private_key_redaction_shows_only_type_length_and_hash() -> None:
    body = b"QUJD" * 100
    result = redact_private_key(body, "RSA")
    assert result.shown == ""
    assert result.length == 400
    assert result.text == f"[RSA private key, 400 base64 chars, sha256:{result.hash8}]"
    assert redact_private_key(body, "").text.startswith("[private key, 400 base64 chars")
    for label in redact.PRIVATE_KEY_LABELS:
        assert "base64 chars" in redact_private_key(body, label).text


def test_private_key_redaction_refuses_unknown_labels_and_empty_bodies() -> None:
    with pytest.raises(ValueError, match="label"):
        redact_private_key(b"QUJD", "SOMETHING")
    with pytest.raises(ValueError, match="empty"):
        redact_private_key(b"", "RSA")


def test_no_output_contains_the_secret(assert_not_leaked: Callable[..., None]) -> None:
    secret = bytes(range(33, 33 + 60))
    text = redact_secret(secret, 4).text
    assert_not_leaked(text, secret, allowed_shown=4)
