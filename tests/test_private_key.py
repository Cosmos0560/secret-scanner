"""The private key detector (PLAN.md D6): every header type, encrypted keys, CRLF, truncated
blocks, header-only negatives, the escaped JSON form and the line limit."""

from __future__ import annotations

from collections.abc import Callable
from dataclasses import replace

import pytest

from secret_scanner.core.detect.engine import Engine
from secret_scanner.core.detect.entropy import EntropyConfig
from secret_scanner.core.detect.match import Match
from secret_scanner.core.detect.private_key import MIN_BODY_CHARS, PrivateKeyScanner
from secret_scanner.core.fakes import PRIVATE_KEY_LABELS, fake_private_key
from secret_scanner.core.findings import to_finding
from secret_scanner.core.limits import DEFAULT_LIMITS
from secret_scanner.core.models import Confidence, Detector, Severity
from secret_scanner.core.redact import redact_private_key

BS = chr(92)
ENGINE = Engine([], entropy=EntropyConfig(enabled=False))
WITH_ENTROPY = Engine([], entropy=EntropyConfig())
HEADER = "-----BEGIN " + "RSA PRIVATE" + " KEY-----"
FOOTER = "-----END " + "RSA PRIVATE" + " KEY-----"


def _keys(text: str, engine: Engine = ENGINE) -> list[Match]:
    return [m for m in engine.scan(text.encode()).matches if m.rule_id == "private-key"]


def _body_of(block: str) -> bytes:
    inner = [
        line.strip()
        for line in block.splitlines()
        if line.strip() and not line.startswith("-----") and ":" not in line
    ]
    return "".join(inner).encode()


# -- every header type ------------------------------------------------------------------------


@pytest.mark.parametrize("label", PRIVATE_KEY_LABELS)
def test_every_header_type_is_found_with_its_label(label: str) -> None:
    block = fake_private_key("hdr", label=label)
    (match,) = _keys(block)
    assert match.kind_label == label
    assert match.detector is Detector.PRIVATE_KEY
    assert match.confidence is Confidence.HIGH
    assert match.line == 1
    assert (match.col_start, match.col_end) == (1, len(block.split("\n")[0]) + 1)
    assert match.secret == _body_of(block)
    expected = Severity.MEDIUM if label == "ENCRYPTED" else Severity.CRITICAL
    assert match.severity is expected
    assert match.shown_chars == 0


def test_the_secret_is_the_base64_body_only() -> None:
    block = fake_private_key("body", body_lines=4)
    (match,) = _keys(block)
    assert len(match.secret) == 4 * 64
    assert b"-----" not in match.secret
    assert b"\n" not in match.secret


def test_a_key_inside_other_text_is_found_at_its_line_and_column() -> None:
    block = fake_private_key("embedded")
    text = "first = 1\nsecond = 2\n  " + block + "tail = 3\n"
    (match,) = _keys(text)
    assert match.line == 3
    assert match.col_start == 3
    # the body lines are indented too in a YAML block scalar: leading blanks are fine
    indented = "\n".join("    " + line for line in block.split("\n"))
    (again,) = _keys(indented)
    assert again.secret == match.secret


# -- encrypted --------------------------------------------------------------------------------


def test_proc_type_encrypted_makes_the_severity_medium() -> None:
    block = fake_private_key(
        "enc", header_fields=("Proc-Type: 4,ENCRYPTED", "DEK-Info: AES-128-CBC,0011223344556677")
    )
    (match,) = _keys(block)
    assert match.severity is Severity.MEDIUM
    assert match.kind_label == "RSA"
    assert match.confidence is Confidence.HIGH


def test_other_header_fields_do_not_make_a_key_encrypted() -> None:
    block = fake_private_key("fields", header_fields=("Comment: personal laptop",))
    (match,) = _keys(block)
    assert match.severity is Severity.CRITICAL


def test_encrypted_marker_in_a_non_proc_type_field_is_ignored() -> None:
    block = fake_private_key("fields2", header_fields=("Comment: ENCRYPTED backup",))
    assert _keys(block)[0].severity is Severity.CRITICAL


# -- line endings and the fingerprint ---------------------------------------------------------


def test_crlf_and_lf_files_give_the_same_secret_and_fingerprint() -> None:
    lf = fake_private_key("eol")
    crlf = fake_private_key("eol", newline="\r\n")
    (a,) = _keys(lf)
    (b,) = _keys(crlf)
    assert a.secret == b.secret
    fa = to_finding(a, path_key="k.pem", path="k.pem")
    fb = to_finding(b, path_key="k.pem", path="k.pem")
    assert fa.fingerprint == fb.fingerprint
    assert fa.redacted == fb.redacted


def test_redacted_form_shows_type_length_and_hash_only(
    assert_not_leaked: Callable[..., None],
) -> None:
    block = fake_private_key("redact", label="OPENSSH")
    (match,) = _keys(block)
    finding = to_finding(match, path_key="k", path="k")
    assert finding.redacted == redact_private_key(match.secret, "OPENSSH")
    assert finding.redacted.text.startswith("[OPENSSH private key, 192 base64 chars, sha256:")
    assert_not_leaked(finding.redacted.text, match.secret)
    assert_not_leaked(repr(match), match.secret)


# -- truncated, header only, prose ------------------------------------------------------------


def test_a_body_without_an_end_line_is_medium_confidence() -> None:
    block = fake_private_key("trunc", complete=False)
    (match,) = _keys(block)
    assert match.confidence is Confidence.MEDIUM
    assert match.severity is Severity.CRITICAL
    assert len(match.secret) == 3 * 64


def test_a_body_ended_by_prose_is_medium_and_the_prose_line_is_scanned_normally() -> None:
    block = fake_private_key("prose", complete=False) + "this line is not base64\n"
    (match,) = _keys(block)
    assert match.confidence is Confidence.MEDIUM


def test_header_alone_and_header_with_footer_are_not_findings() -> None:
    assert _keys(HEADER + "\n") == []
    assert _keys(HEADER + "\n" + FOOTER + "\n") == []
    assert _keys(HEADER + "\n\n" + FOOTER + "\n") == []


def test_a_body_below_the_minimum_is_not_a_finding_and_the_minimum_is() -> None:
    short = HEADER + "\n" + "A" * (MIN_BODY_CHARS - 1) + "\n" + FOOTER + "\n"
    exact = HEADER + "\n" + "A" * MIN_BODY_CHARS + "\n" + FOOTER + "\n"
    assert _keys(short) == []
    assert len(_keys(exact)) == 1


def test_documentation_that_mentions_a_header_is_not_a_finding() -> None:
    prose = [
        "The block starts with " + HEADER + " and then base64 text follows in a real key.\n",
        "`"
        + HEADER
        + "`\n"
        + "A" * 80
        + "\n",  # a code span, then something that looks like a body
        "Run: head -1 key.pem  # prints " + HEADER + " as the first line\n",
        HEADER + " is the first line.\n" + "A" * 80 + "\n",
        "-----BEGIN " + "CERTIFICATE" + "-----\n" + "A" * 80 + "\n-----END CERTIFICATE-----\n",
        "-----BEGIN " + "PUBLIC" + " KEY-----\n" + "A" * 80 + "\n",
    ]
    for text in prose:
        assert _keys(text) == [], text[:0]


def test_pgp_armor_with_headers_and_a_checksum_line() -> None:
    block = fake_private_key("pgp", label="PGP", header_fields=("Version: GnuPG v2",))
    lines = block.split("\n")
    lines.insert(-2, "=ab12")  # the armor checksum line is base64 with a leading `=`
    (match,) = _keys("\n".join(lines))
    assert match.kind_label == "PGP"
    assert match.confidence is Confidence.HIGH
    assert match.secret.endswith(b"=ab12")


# -- the escaped one-line form ----------------------------------------------------------------


def test_the_escaped_json_form_is_found_on_one_line() -> None:
    block = fake_private_key("json", label="")
    escaped = block.strip().replace("\n", BS + "n")
    line = '{"type": "service_account", "private_key": "' + escaped + '", "client_email": "x"}\n'
    (match,) = _keys(line)
    assert match.line == 1
    assert match.confidence is Confidence.HIGH
    assert match.kind_label == ""
    assert match.secret == _body_of(block)
    assert match.col_start == line.index("-----BEGIN") + 1


def test_escaped_form_without_an_end_marker_is_medium() -> None:
    block = fake_private_key("json2", complete=False)
    escaped = block.strip().replace("\n", BS + "n")
    (match,) = _keys('key = "' + escaped + '"\n')
    assert match.confidence is Confidence.MEDIUM


def test_escaped_form_with_crlf_escapes_matches_the_plain_secret() -> None:
    block = fake_private_key("json3")
    escaped = block.strip().replace("\n", BS + "r" + BS + "n")
    (match,) = _keys('"k": "' + escaped + '"\n')
    assert match.secret == _body_of(block)


def test_a_header_followed_by_prose_on_the_same_line_is_not_a_key() -> None:
    assert _keys(HEADER + " " + "A" * 100 + " not escaped\n") == []
    assert _keys('"' + HEADER + BS + "n" + "not base64 !!!" + '"\n') == []


def test_an_escaped_header_without_a_body_is_not_a_finding() -> None:
    assert _keys('"' + HEADER + BS + "n" + FOOTER + '"\n') == []


# -- limits -----------------------------------------------------------------------------------


def test_the_body_stops_at_max_key_lines_and_is_medium() -> None:
    limits = replace(DEFAULT_LIMITS, max_key_lines=5)
    engine = Engine([], entropy=EntropyConfig(enabled=False), limits=limits)
    block = fake_private_key("limit", body_lines=20)
    (match,) = _keys(block, engine)
    assert len(match.secret) == 5 * 64
    assert match.confidence is Confidence.MEDIUM


def test_a_body_exactly_at_the_limit_with_its_end_line_is_complete() -> None:
    limits = replace(DEFAULT_LIMITS, max_key_lines=5)
    engine = Engine([], entropy=EntropyConfig(enabled=False), limits=limits)
    (match,) = _keys(fake_private_key("exact", body_lines=5), engine)
    assert match.confidence is Confidence.HIGH
    assert len(match.secret) == 5 * 64


def test_the_default_limit_is_two_hundred_lines() -> None:
    assert DEFAULT_LIMITS.max_key_lines == 200
    (match,) = _keys(fake_private_key("big", body_lines=250))
    assert len(match.secret) == 200 * 64
    assert match.confidence is Confidence.MEDIUM


# -- interplay with the other detectors -------------------------------------------------------


def test_the_key_body_is_not_reported_again_by_the_entropy_detector() -> None:
    block = fake_private_key("quiet", body_lines=4)
    matches = WITH_ENTROPY.scan(block.encode()).matches
    assert [m.rule_id for m in matches] == ["private-key"]


def test_text_around_a_key_is_still_scanned() -> None:
    from secret_scanner.core.fakes import fake_entropy_token

    token = fake_entropy_token("around")
    text = f"before = {token}\n" + fake_private_key("around") + f"after = {token}\n"
    matches = WITH_ENTROPY.scan(text.encode()).matches
    assert [(m.rule_id, m.line) for m in matches] == [
        ("entropy-base64", 1),
        ("private-key", 2),
        ("entropy-base64", 7),
    ]


def test_two_keys_in_one_file() -> None:
    text = fake_private_key("one") + "\n" + fake_private_key("two", label="EC")
    matches = _keys(text)
    assert [m.kind_label for m in matches] == ["RSA", "EC"]
    assert matches[0].secret != matches[1].secret


def test_a_second_header_inside_an_open_block_starts_a_new_one() -> None:
    first = fake_private_key("a", complete=False)
    second = fake_private_key("b", label="DSA")
    matches = _keys(first + second)
    assert [m.kind_label for m in matches] == ["RSA", "DSA"]
    assert matches[0].confidence is Confidence.MEDIUM
    assert matches[1].confidence is Confidence.HIGH


def test_scanner_can_be_driven_line_by_line() -> None:
    scanner = PrivateKeyScanner()
    lines = fake_private_key("manual").split("\n")
    spans = [
        scanner.feed(n, line.encode(), line.lower().encode()) for n, line in enumerate(lines, 1)
    ]
    assert spans[0] == [(0, len(lines[0]))]
    assert all(
        span == [(0, len(line))] for span, line in zip(spans[1:-1], lines[1:-1], strict=True)
    )
    assert spans[-1] == []  # the empty line after the footer is outside the block
    scanner.finish()
    assert len(scanner.matches) == 1


def test_finish_closes_an_open_block() -> None:
    scanner = PrivateKeyScanner()
    block = fake_private_key("open", complete=False).strip().split("\n")
    for number, line in enumerate(block, start=1):
        scanner.feed(number, line.encode(), line.lower().encode())
    assert scanner.matches == []
    scanner.finish()
    assert len(scanner.matches) == 1
    scanner.finish()
    assert len(scanner.matches) == 1
