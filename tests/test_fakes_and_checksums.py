"""The fake generator (PLAN.md D16), the GitHub checksum, `Match` and `to_finding`.

Fakes are built at runtime and live only in memory here; nothing below writes one to a file.
"""

from __future__ import annotations

import dataclasses
from collections.abc import Callable

import pytest

from secret_scanner.core import checksums, fakes
from secret_scanner.core.detect.match import Match
from secret_scanner.core.findings import redact_match, to_finding
from secret_scanner.core.fingerprint import fingerprint
from secret_scanner.core.models import Checksum, Confidence, Detector, FakeSegment, Severity
from secret_scanner.core.redact import redact_private_key, redact_secret
from secret_scanner.services.loader import load_builtin_rules

RULES = {rule.id: rule for rule in load_builtin_rules().rules}
# Built from fragments at import time: no complete secret-shaped literal exists in this file.
SAMPLE_SECRET = b"AK" + b"IA" + b"FAKE" * 4

# -- checksums --------------------------------------------------------------------------------


def test_base62_encoding_pads_and_round_trips_known_values() -> None:
    assert checksums.base62_encode(0, 6) == "000000"
    assert checksums.base62_encode(61, 1) == "z"
    assert checksums.base62_encode(62, 2) == "10"
    assert checksums.base62_encode(62**6 - 1, 6) == "zzzzzz"
    assert checksums.base62_encode(1, 6) == "000001"
    with pytest.raises(ValueError, match="negative"):
        checksums.base62_encode(-1, 6)
    with pytest.raises(ValueError, match="width"):
        checksums.base62_encode(1, 0)


def test_github_checksum_is_the_base62_crc32_of_the_entropy() -> None:
    import zlib

    entropy = b"abcdefghijklmnopqrstuvwxyz0123"
    expected = checksums.base62_encode(zlib.crc32(entropy), 6)
    assert checksums.github_checksum(entropy) == expected
    assert len(expected) == 6
    with pytest.raises(ValueError, match="30"):
        checksums.github_checksum(b"short")


def test_github_token_validation_accepts_correct_and_rejects_wrong_checksums() -> None:
    entropy = b"A1b2C3d4E5f6G7h8I9j0K1l2M3n4O5"
    good = b"ghp_" + entropy + checksums.github_checksum(entropy).encode()
    assert checksums.github_token_checksum_valid(good)
    wrong = good[:-1] + (b"0" if good[-1:] != b"0" else b"1")
    assert not checksums.github_token_checksum_valid(wrong)
    assert not checksums.github_token_checksum_valid(good[:-1])
    assert not checksums.github_token_checksum_valid(good + b"a")
    assert not checksums.github_token_checksum_valid(b"")


# -- fakes ------------------------------------------------------------------------------------


def test_body_is_deterministic_seeded_and_in_its_charset() -> None:
    first = fakes.body("seed", "base62", 40)
    assert first == fakes.body("seed", "base62", 40)
    assert first != fakes.body("other", "base62", 40)
    assert set(first) <= set(fakes.CHARSETS["base62"])
    assert len(fakes.body("seed", "base32", 100)) == 100


def test_body_carries_the_marker_where_the_charset_allows() -> None:
    assert fakes.body("s", "base62", 20)[2:6] == "FAKE"
    assert fakes.body("s", "hex", 20)[2:6] == "fa4e"
    assert fakes.body("s", "hex-upper", 20)[2:6] == "FA4E"
    assert "FAKE" not in fakes.body("s", "digits", 20)
    assert fakes.body("s", "base62", 7).count("FAKE") == 0  # too short for a marker


@pytest.mark.parametrize("rule_id", sorted(RULES))
def test_every_builtin_rule_has_a_fake_its_own_regex_matches(rule_id: str) -> None:
    rule = RULES[rule_id]
    for seed in ("a", "b", "c"):
        fake = fakes.build_fake(rule, seed)
        assert rule.pattern.search(fake.encode("ascii")) is not None
    assert fakes.build_fake(rule, "a") != fakes.build_fake(rule, "b")


def test_checksum_fakes_are_correct_or_deliberately_wrong() -> None:
    rule = RULES["github-token"]
    assert rule.checksum is Checksum.GITHUB_CRC32
    good = fakes.build_fake(rule, "z")
    bad = fakes.build_fake(rule, "z", valid_checksum=False)
    assert checksums.github_token_checksum_valid(good.encode())
    assert not checksums.github_token_checksum_valid(bad.encode())
    assert good[:-1] == bad[:-1]
    assert rule.pattern.search(bad.encode()) is not None  # still matches, with low confidence


def test_wrong_checksum_differs_even_when_the_last_character_is_zero() -> None:
    assert fakes._wrong_checksum("abcde0") == "abcde1"
    assert fakes._wrong_checksum("abcdez") == "abcde0"


def test_assemble_joins_parts_and_generated_segments() -> None:
    segments = (FakeSegment(parts=("ab", "cd")), FakeSegment(charset="digits", length=5))
    text = fakes.assemble(segments, "s")
    assert text.startswith("abcd")
    assert len(text) == 9
    assert text[4:].isdigit()


@pytest.mark.parametrize("label", fakes.PRIVATE_KEY_LABELS)
def test_private_key_fake_forms(label: str) -> None:
    block = fakes.fake_private_key("s", label=label)
    lines = block.split("\n")
    assert lines[0].startswith("-----BEGIN ")
    assert lines[0].endswith("-----")
    assert lines[-2].startswith("-----END ")
    assert lines[-1] == ""
    assert len(lines) == 3 + 2 + 1
    assert all(len(line) == 64 for line in lines[1:4])
    if label == "PGP":
        assert "PGP PRIVATE KEY BLOCK" in lines[0]
    elif label:
        assert f"BEGIN {label} PRIVATE KEY" in lines[0]
    else:
        assert lines[0] == "-----BEGIN PRIVATE KEY-----"


def test_private_key_fake_options() -> None:
    crlf = fakes.fake_private_key("s", newline="\r\n")
    assert crlf.count("\r\n") == 5
    truncated = fakes.fake_private_key("s", complete=False)
    assert "-----END" not in truncated
    fields = fakes.fake_private_key("s", header_fields=("Proc-Type: 4,ENCRYPTED",))
    assert fields.split("\n")[1] == "Proc-Type: 4,ENCRYPTED"
    assert fields.split("\n")[2] == ""
    assert fakes.fake_private_key("s", body_lines=7).count("\n") == 7 + 2
    with pytest.raises(ValueError, match="label"):
        fakes.fake_private_key("s", label="DSS")


def test_entropy_fakes() -> None:
    token = fakes.fake_entropy_token("s", length=43)
    assert len(token) == 43
    assert token[2:6] == "FAKE"
    assert set(token) <= set(fakes.CHARSETS["base64url"])
    hex_token = fakes.fake_entropy_token("s", kind="hex", length=40)
    assert len(hex_token) == 40
    assert hex_token[2:6] == "fa4e"
    assert set(hex_token) <= set(fakes.CHARSETS["hex"])
    assert (
        fakes.fake_entropy_token("s", length=100)[:2]
        == fakes.fake_entropy_token("s", length=100)[:2]
    )
    assert len(fakes.fake_entropy_token("s", length=100)) == 100
    assert fakes.fake_entropy_token("s", length=5)[2:6] != "FAKE"
    with pytest.raises(ValueError, match="base64 or hex"):
        fakes.fake_entropy_token("s", kind="base32")


# -- Match and to_finding ---------------------------------------------------------------------


def _match(secret: bytes = SAMPLE_SECRET, **overrides: object) -> Match:
    values: dict[str, object] = {
        "rule_id": "aws-access-key-id",
        "detector": Detector.RULE,
        "severity": Severity.HIGH,
        "confidence": Confidence.HIGH,
        "line": 3,
        "col_start": 7,
        "col_end": 27,
        "secret": secret,
        "shown_chars": 4,
    }
    values.update(overrides)
    return Match(**values)  # type: ignore[arg-type]


def test_match_repr_and_str_never_show_the_secret(assert_not_leaked: Callable[..., None]) -> None:
    secret = fakes.body("repr", "base62", 40).encode()
    match = _match(secret)
    for text in (repr(match), str(match), f"{match!r}", repr([match]), repr({"m": match})):
        assert_not_leaked(text, secret)
    assert "rule_id='aws-access-key-id'" in repr(match)


def test_match_is_frozen() -> None:
    match = _match()
    with pytest.raises(dataclasses.FrozenInstanceError):
        match.line = 9  # type: ignore[misc]


def test_to_finding_redacts_and_fingerprints() -> None:
    secret = SAMPLE_SECRET
    finding = to_finding(_match(secret), path_key="src/a.py", path="src/a.py")
    assert finding.redacted == redact_secret(secret, 4)
    assert finding.fingerprint == fingerprint("aws-access-key-id", "src/a.py", secret)
    assert (finding.location.line, finding.location.column, finding.location.end_column) == (
        3,
        7,
        27,
    )
    assert finding.location.commit is None
    assert finding.suppressed_by is None
    assert finding.severity is Severity.HIGH
    assert finding.detector is Detector.RULE


def test_to_finding_carries_commit_data_and_keeps_the_exact_path_for_the_fingerprint() -> None:
    secret = SAMPLE_SECRET
    finding = to_finding(
        _match(secret),
        path_key="d/\udcff.txt",
        path="d/\\udcff.txt",
        commit="a" * 40,
        commit_time=7,
    )
    assert finding.location.path == "d/\\udcff.txt"
    assert finding.location.commit == "a" * 40
    assert finding.location.commit_time == 7
    assert finding.fingerprint == fingerprint("aws-access-key-id", "d/\udcff.txt", secret)


def test_private_keys_are_redacted_by_type_length_and_hash() -> None:
    body = b"A" * 100
    match = _match(
        body,
        rule_id="private-key",
        detector=Detector.PRIVATE_KEY,
        shown_chars=0,
        kind_label="RSA",
    )
    assert redact_match(match) == redact_private_key(body, "RSA")
    assert "RSA private key, 100 base64 chars" in redact_match(match).text


def test_a_finding_for_one_secret_is_independent_of_line_and_column() -> None:
    secret = SAMPLE_SECRET
    one = to_finding(_match(secret, line=1, col_start=1, col_end=21), path_key="p", path="p")
    two = to_finding(_match(secret, line=40, col_start=9, col_end=29), path_key="p", path="p")
    assert one.fingerprint == two.fingerprint
