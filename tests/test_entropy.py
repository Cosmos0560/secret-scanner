"""The entropy detector (PLAN.md D5): known values, thresholds per alphabet, context, every
exclusion, and the bounds of the configurable values."""

from __future__ import annotations

import math
from collections.abc import Callable
from dataclasses import replace
from typing import Any

import pytest

from secret_scanner.core.detect.engine import Engine
from secret_scanner.core.detect.entropy import (
    EntropyConfig,
    EntropyDetector,
    path_excluded,
    shannon_entropy,
)
from secret_scanner.core.errors import ConfigError
from secret_scanner.core.fakes import fake_entropy_token
from secret_scanner.core.limits import DEFAULT_LIMITS
from secret_scanner.core.models import Confidence, Detector, Severity

DETECTOR = EntropyDetector(EntropyConfig())


def _hits(line: str, detector: EntropyDetector = DETECTOR) -> list:  # type: ignore[type-arg]
    return [match for _, _, match in detector.scan_line(line.encode("utf-8"), 1)]


def _b64(seed: str = "e", length: int = 43) -> str:
    return fake_entropy_token(seed, length=length)


def _hex(seed: str = "e", length: int = 40) -> str:
    return fake_entropy_token(seed, kind="hex", length=length)


# -- entropy values ---------------------------------------------------------------------------


def test_shannon_entropy_of_known_inputs() -> None:
    assert shannon_entropy(b"") == 0.0
    assert shannon_entropy(b"aaaaaaaa") == 0.0
    assert shannon_entropy(b"abab") == pytest.approx(1.0)
    assert shannon_entropy(b"abcd") == pytest.approx(2.0)
    assert shannon_entropy(bytes(range(64))) == pytest.approx(6.0)
    assert shannon_entropy(b"aab") == pytest.approx(
        -(2 / 3 * math.log2(2 / 3) + 1 / 3 * math.log2(1 / 3))
    )


def test_a_base64_token_under_23_characters_cannot_reach_the_default_threshold() -> None:
    assert math.log2(22) < 4.5 < math.log2(23)
    token = "".join(chr(c) for c in range(65, 87))  # 22 distinct characters: the best case
    assert len(token) == 22
    assert _hits(f"x = {token}") == []


# -- candidates, confidence and context -------------------------------------------------------


def test_a_bare_base64_token_has_low_confidence() -> None:
    token = _b64()
    (match,) = _hits(f"value {token} end")
    assert match.rule_id == "entropy-base64"
    assert match.detector is Detector.ENTROPY
    assert match.severity is Severity.MEDIUM
    assert match.confidence is Confidence.LOW
    assert match.secret == token.encode()
    assert match.shown_chars == 4  # 32 characters or more
    assert (match.line, match.col_start, match.col_end) == (1, 7, 7 + len(token))


@pytest.mark.parametrize(
    "template",
    [
        'api_key = "{t}"',
        "API_KEY={t}",
        "apikey: {t}",
        "SECRET_TOKEN = '{t}'",
        '{{"password": "{t}"}}',
        "client_secret:{t}",
        "private_key={t}",
        "credentials = {t}",
        "auth_token: {t}",
        "db.passwd = {t}",
        "token='{t}'",
    ],
)
def test_assignment_context_raises_confidence_to_medium(template: str) -> None:
    token = _b64("ctx")
    (match,) = _hits(template.format(t=token))
    assert match.confidence is Confidence.MEDIUM


@pytest.mark.parametrize(
    "template",
    [
        "name = {t}",
        "Authorization: Bearer {t}",  # words between the key and the value
        "{t} # api_key",  # the key comes after the value
        "api_key = other, {t}",
        "x = {t} # token",
    ],
)
def test_no_context_means_low_confidence(template: str) -> None:
    (match,) = _hits(template.format(t=_b64("noctx")))
    assert match.confidence is Confidence.LOW


def test_context_must_be_close_to_the_token() -> None:
    token = _b64("gap")
    (near,) = _hits("api_key" + " " * 3 + f"= {token}")
    assert near.confidence is Confidence.MEDIUM  # a few blanks before `=` are still an assignment
    (far,) = _hits("api_key" + " " * 40 + f"= {token}")
    assert far.confidence is Confidence.LOW
    (not_near,) = _hits(f"api_key = max(a, b) + {token}")
    assert not_near.confidence is Confidence.LOW


def test_the_second_assignment_on_a_line_can_provide_the_context() -> None:
    token = _b64("two")
    (match,) = _hits(f"name=alice password={token}")
    assert match.confidence is Confidence.MEDIUM


def test_tokens_are_cut_at_quotes_whitespace_and_punctuation() -> None:
    first, second = _b64("one"), _b64("two")
    hits = _hits(f"\"{first}\" , '{second}' ({first})")
    assert [h.secret for h in hits] == [first.encode(), second.encode(), first.encode()]


# -- hex --------------------------------------------------------------------------------------


def test_hex_tokens_are_reported_only_with_context() -> None:
    token = _hex()
    assert _hits(f"checksum {token}") == []
    (match,) = _hits(f"secret = {token}")
    assert match.rule_id == "entropy-hex"
    assert match.confidence is Confidence.MEDIUM


def test_hex_needs_32_characters() -> None:
    assert _hits(f"secret = {_hex(length=31)}") == []
    assert len(_hits(f"secret = {_hex(length=32)}")) == 1


def test_hex_threshold_is_lower_than_base64() -> None:
    low = "0123456789abcdef" * 2  # entropy 4.0
    assert len(_hits(f"token = {low}")) == 1
    repeating = "abababababababababababababababababab"  # entropy 1.0
    assert _hits(f"token = {repeating}") == []
    two_classes = "A1" * 20  # entropy 1.0
    assert _hits(f"token = {two_classes}") == []


# -- exclusions -------------------------------------------------------------------------------


def test_uuids_are_not_reported() -> None:
    uuid = "123e4567-e89b-12d3-a456-426614174000"
    assert _hits(f"id = {uuid}") == []
    assert _hits(f"secret = {uuid}") == []
    upper = uuid.upper()
    assert _hits(f"id = {upper}") == []


def test_a_near_uuid_is_not_excluded() -> None:
    near = "123e4567-e89b-12d3-a456-4266141740001ZxQk"  # longer than a UUID
    assert len(_hits(f"id = {near}")) in (0, 1)  # judged on its own entropy, not by the UUID rule


def test_sri_integrity_values_are_not_reported() -> None:
    value = fake_entropy_token("sri", length=64)
    for prefix in ("sha256-", "sha384-", "sha512-"):
        assert _hits(f'integrity="{prefix}{value}"') == []
    assert len(_hits(f'integrity="sha1-{value}"')) == 1


def test_tokens_with_fewer_than_two_character_classes_are_not_reported() -> None:
    lower = "kjhgfdsaqwertyuiopzxcvbnmlkjhgfdsaqwertyuiop"
    assert shannon_entropy(lower.encode()) > 4.0
    assert _hits(f"x = {lower}") == []
    assert _hits(f"x = {lower.upper()}") == []
    digits = "7391846205" * 4
    assert _hits(f"x = {digits}") == []
    assert len(_hits(f"x = {lower[:-1]}Q")) == 1  # a second class makes it a candidate


def test_path_like_tokens_are_not_reported() -> None:
    token = "usr/local/lib/python3/site-packages/aBcDeFgHiJkLmNoP"
    assert _hits(f"x = {token}") == []
    assert len(_hits(f"x = {_b64('p')[:30]}/{_b64('q')[:30]}")) == 1  # two slashes at most


def test_over_long_runs_and_short_runs_are_not_candidates() -> None:
    assert _hits(f"x = {_b64('long', 300)}") == []
    assert len(_hits(f"x = {_b64('limit', 256)}")) == 1
    assert _hits(f"x = {_b64('short', 19)}") == []


def test_the_64_bit_floor_holds_even_with_lowered_thresholds() -> None:
    config = EntropyConfig(base64_threshold=3.5, min_length=16)
    detector = EntropyDetector(config)
    sixteen = "aB3dE5gH7jK9mN1p"  # 16 distinct characters: 4 bits each, 64 bits in total
    assert _hits(f"x = {sixteen}", detector) != []
    below = "aB3dE5gH7jK9mN1paB3dE5gH7jK9mN1p"[:16]
    assert len(below) == 16
    weak = "aaaaBBBB1111cccc"  # 2 bits per character: 32 bits
    assert _hits(f"x = {weak}", detector) == []


# -- configuration ----------------------------------------------------------------------------


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("base64_threshold", 3.4),
        ("base64_threshold", 6.1),
        ("hex_threshold", 2.4),
        ("hex_threshold", 4.1),
        ("min_length", 15),
        ("min_length", 65),
        ("base64_threshold", True),
    ],
)
def test_config_values_outside_the_documented_bounds_are_refused(field: str, value: object) -> None:
    kwargs: dict[str, Any] = {field: value}
    with pytest.raises(ConfigError, match="must be between"):
        EntropyConfig(**kwargs)


def test_bounds_are_inclusive() -> None:
    assert EntropyConfig(base64_threshold=3.5, hex_threshold=2.5, min_length=16)
    assert EntropyConfig(base64_threshold=6.0, hex_threshold=4.0, min_length=64)


def test_a_lower_minimum_length_admits_shorter_tokens() -> None:
    token = "aB3dE5gH7jK9mN1pQ"  # 17 distinct characters
    assert _hits(f"x = {token}") == []
    short = EntropyDetector(EntropyConfig(base64_threshold=3.5, min_length=16))
    assert len(_hits(f"x = {token}", short)) == 1


def test_a_higher_minimum_length_raises_the_hex_minimum_too() -> None:
    detector = EntropyDetector(EntropyConfig(min_length=40))
    assert _hits(f"secret = {_hex(length=36)}", detector) == []
    assert len(_hits(f"secret = {_hex(length=40)}", detector)) == 1


def test_the_token_length_ceiling_comes_from_the_limits() -> None:
    limits = replace(DEFAULT_LIMITS, max_entropy_token_chars=40)
    detector = EntropyDetector(EntropyConfig(), limits)
    assert len(_hits(f"x = {_b64('a', 40)}", detector)) == 1
    assert _hits(f"x = {_b64('a', 41)}", detector) == []


def test_the_engine_can_switch_the_detector_off() -> None:
    token = _b64("off")
    on = Engine([], entropy=EntropyConfig())
    off = Engine([], entropy=EntropyConfig(enabled=False))
    assert [m.rule_id for m in on.scan(token.encode()).matches] == ["entropy-base64"]
    assert off.scan(token.encode()).matches == ()
    assert on.entropy_enabled
    assert not off.entropy_enabled
    assert on.scan(token.encode(), use_entropy=False).matches == ()


# -- excluded paths ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "path",
    [
        "package-lock.json",
        "web/yarn.lock",
        "a/b/pnpm-lock.yaml",
        "poetry.lock",
        "uv.lock",
        "Cargo.lock",
        "go.sum",
        "composer.lock",
        "Gemfile.lock",
        "static/app.min.js",
        "static/app.min.css",
        "dist/app.js.map",
        "img/logo.svg",
        "IMG/LOGO.SVG",
    ],
)
def test_default_path_excludes_for_the_entropy_detector(path: str) -> None:
    assert path_excluded(path)


@pytest.mark.parametrize(
    "path", ["src/app.py", "package.json", "lock.txt", "my-yarn.lock.bak", "x.map.txt"]
)
def test_ordinary_paths_are_not_excluded(path: str) -> None:
    assert not path_excluded(path)


def test_lockfile_exclusion_applies_to_the_name_not_the_directory() -> None:
    assert not path_excluded("package-lock.json/real.py")


# -- leak -------------------------------------------------------------------------------------


def test_entropy_match_repr_is_safe(assert_not_leaked: Callable[..., None]) -> None:
    token = _b64("leak")
    (match,) = _hits(f"api_key={token}")
    assert_not_leaked(repr(match), token.encode())


def test_equals_is_padding_only_at_the_end_of_a_token() -> None:
    body = _b64("pad", 40)
    (padded,) = _hits(f"x {body}==")
    assert padded.secret == (body + "==").encode()
    (assigned,) = _hits(f"API_KEY={body}")
    assert assigned.secret == body.encode()
    assert assigned.confidence is Confidence.MEDIUM
    assert _hits(f"x {body}===") == []  # three signs are not padding


def test_an_assignment_after_the_token_does_not_give_it_context() -> None:
    token = _b64("after")
    (match,) = _hits(f"{token} password=abc")
    assert match.confidence is Confidence.LOW
