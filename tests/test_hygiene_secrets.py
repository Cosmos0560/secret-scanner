"""Secret-shaped strings must never be committed (PLAN.md D16 point 4, CLAUDE.md section 4).

Phase 1 uses the minimal hard-coded set of format checks (AWS key id, GitHub token, private key
block, Slack token, Stripe key). Phase 2 switches this test to the engine. There is no allowlist:
a hit is removed from the file, never excused. Every positive control builds its fake at runtime,
from fragments, inside a temporary repository.
"""

from __future__ import annotations

from collections.abc import Callable
from pathlib import Path

import pytest

from tests import hygiene
from tests.gitrepo import GitRepo
from tests.helpers import PROJECT_ROOT

pytestmark = pytest.mark.requires_git

BACKSLASH_N = chr(92) + "n"


def _repo(tmp_path: Path) -> GitRepo:
    return GitRepo.create(tmp_path / "control", tmp_path)


def _checks(hits: list[hygiene.Hit]) -> list[str]:
    return [hit.check for hit in hits]


# -- the real repository --------------------------------------------------------------------


def test_repository_has_no_secret_shaped_strings(tmp_path: Path) -> None:
    hits = hygiene.check_repository(PROJECT_ROOT, tmp_path)
    secret_hits = [hit for hit in hits if hit.check in {name for name, _ in hygiene.FORMAT_CHECKS}]
    secret_hits += [hit for hit in hits if hit.check == "private-key"]
    assert secret_hits == [], "\n".join(hit.format() for hit in secret_hits)


@pytest.mark.parametrize("name", ["CLAUDE.md", "PLAN.md"])
def test_plan_and_working_rules_mention_formats_without_containing_secrets(name: str) -> None:
    text = (PROJECT_ROOT / name).read_text(encoding="utf-8")
    assert hygiene.secret_shaped_strings(name, text) == []


# -- positive controls: a generated fake is caught --------------------------------------------


@pytest.mark.parametrize("kind", hygiene.FAKE_KINDS)
def test_control_catches_a_generated_fake_in_a_temporary_repository(
    kind: str, tmp_path: Path, assert_not_leaked: Callable[..., None]
) -> None:
    repo = _repo(tmp_path)
    fake = hygiene.fake_secret(kind)
    repo.write("config/settings.txt", "setting = " + fake + "\nother = value\n")
    hits = hygiene.check_repository(repo.path, tmp_path)
    assert _checks(hits) == [kind]
    assert hits[0].path == "config/settings.txt"
    assert hits[0].line == 1
    assert_not_leaked("\n".join(hit.format() for hit in hits), fake)


def test_control_also_catches_a_staged_and_committed_fake(tmp_path: Path) -> None:
    repo = _repo(tmp_path)
    repo.write("a.txt", "token: " + hygiene.fake_secret("github-token") + "\n")
    repo.add("a.txt")
    assert _checks(hygiene.check_repository(repo.path, tmp_path)) == ["github-token"]
    repo.commit("add")
    assert _checks(hygiene.check_repository(repo.path, tmp_path)) == ["github-token"]


def test_control_catches_the_private_key_forms(tmp_path: Path) -> None:
    repo = _repo(tmp_path)
    block = hygiene.fake_secret("private-key")
    repo.write("lf.pem.txt", block)
    repo.write("crlf.txt", block.replace("\n", "\r\n"))
    escaped = block.strip().replace("\n", BACKSLASH_N)
    repo.write("service.json", '{"private_key": "' + escaped + '"}\n')
    hits = hygiene.check_repository(repo.path, tmp_path)
    assert sorted((hit.path, hit.check) for hit in hits) == [
        ("crlf.txt", "private-key"),
        ("lf.pem.txt", "private-key"),
        ("service.json", "private-key"),
    ]


def test_control_catches_a_key_with_header_fields(tmp_path: Path) -> None:
    repo = _repo(tmp_path)
    lines = hygiene.fake_secret("private-key").split("\n")
    with_fields = [lines[0], "Proc-Type: 4,ENCRYPTED", "DEK-Info: AES-128-CBC,0011", "", *lines[1:]]
    repo.write("enc.txt", "\n".join(with_fields))
    assert _checks(hygiene.check_repository(repo.path, tmp_path)) == ["private-key"]


def test_hit_detail_is_redacted_for_every_kind(tmp_path: Path) -> None:
    repo = _repo(tmp_path)
    for kind in hygiene.FAKE_KINDS:
        repo.write(f"{kind}.txt", hygiene.fake_secret(kind))
    hits = hygiene.check_repository(repo.path, tmp_path)
    assert sorted(_checks(hits)) == sorted(hygiene.FAKE_KINDS)
    assert all("sha256:" in hit.detail for hit in hits)


# -- negative controls: near misses and prose do not fire -------------------------------------


def test_fake_generator_is_deterministic_and_seeded() -> None:
    assert hygiene.fake_secret("github-token") == hygiene.fake_secret("github-token")
    assert hygiene.fake_secret("github-token", "a") != hygiene.fake_secret("github-token", "b")
    with pytest.raises(ValueError, match="unknown fake kind"):
        hygiene.fake_secret("nope")


def test_near_misses_do_not_fire(tmp_path: Path) -> None:
    aws = hygiene.fake_secret("aws-access-key-id")
    github = hygiene.fake_secret("github-token")
    stripe = hygiene.fake_secret("stripe-secret-key")
    slack = hygiene.fake_secret("slack-token")
    near_misses = [
        aws[:-1],  # one character short
        aws + "A",  # one character long (word-bounded)
        "x" + aws,  # glued to a preceding word character
        aws.lower(),  # wrong case
        github[:-1],  # one character short
        github + "a",  # one character long
        github.replace("gh", "GH", 1),  # prefix in the wrong case
        stripe[:12],  # far too short
        slack[:9],  # prefix and fragments only
        "xoxb-",
        "AKIA",
        "ghp_",
        "sk_live_",
    ]
    for index, text in enumerate(near_misses):
        assert hygiene.secret_shaped_strings(f"f{index}.txt", text) == [], index


def test_prose_header_and_header_without_body_do_not_fire() -> None:
    header = "-----BEGIN " + "RSA PRIVATE" + " KEY-----"
    footer = "-----END " + "RSA PRIVATE" + " KEY-----"
    cases = [
        header,  # header alone
        header + "\n" + footer + "\n",  # header and footer, no body
        "The block starts with " + header + " and then base64 text follows in a real key.\n",
        header + "\nthis is prose, not base64\n" + "A" * 80 + "\n",  # body line after prose
        "-----BEGIN " + "CERTIFICATE" + "-----\n" + "A" * 80 + "\n",  # not a private key
        header + "\n" + "A" * 63 + "\n" + footer,  # one character below the minimum
    ]
    for index, text in enumerate(cases):
        assert hygiene.secret_shaped_strings(f"f{index}.txt", text) == [], index


def test_body_of_exactly_the_minimum_fires() -> None:
    header = "-----BEGIN " + "RSA PRIVATE" + " KEY-----"
    body = "A" * hygiene.MIN_KEY_BODY_CHARS
    hits = hygiene.secret_shaped_strings("k.txt", header + "\n" + body + "\n")
    assert _checks(hits) == ["private-key"]


def test_every_minimal_check_has_a_fake_kind() -> None:
    names = {name for name, _ in hygiene.FORMAT_CHECKS} | {"private-key"}
    assert names == set(hygiene.FAKE_KINDS)
