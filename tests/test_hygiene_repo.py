"""Repository hygiene (CLAUDE.md section 7): characters, secret files, emails.

Each check runs over the real repository (tracked and untracked-not-ignored files) and has a
positive control in a temporary repository built with tests/gitrepo.py, so a check that silently
stopped detecting anything would fail here.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from tests import hygiene
from tests.gitrepo import GitRepo
from tests.helpers import PROJECT_ROOT, account_names, local_traces

pytestmark = pytest.mark.requires_git

BIDI = [0x202A, 0x202B, 0x202C, 0x202D, 0x202E, 0x2066, 0x2067, 0x2068, 0x2069, 0x200E, 0x200F]
ZERO_WIDTH = [0x200B, 0x200C, 0x200D, 0x2060, 0xFEFF]


def _fail_with(hits: list[hygiene.Hit]) -> str:
    return "\n".join(hit.format() for hit in hits)


# -- the real repository --------------------------------------------------------------------


def test_repository_files_are_listed(tmp_path: Path) -> None:
    names = hygiene.repository_files(PROJECT_ROOT, tmp_path)
    assert "CLAUDE.md" in names
    assert "PLAN.md" in names
    assert not any(name.startswith(".venv/") for name in names)


def test_no_forbidden_characters_in_the_repository(tmp_path: Path) -> None:
    names = hygiene.repository_files(PROJECT_ROOT, tmp_path)
    hits: list[hygiene.Hit] = []
    for name, text in hygiene.read_text_files(PROJECT_ROOT, names):
        if text is not None:
            hits += hygiene.forbidden_characters(name, text)
    assert hits == [], _fail_with(hits)


def test_no_key_or_secret_files_are_tracked_or_staged(tmp_path: Path) -> None:
    names = hygiene.repository_files(PROJECT_ROOT, tmp_path)
    hits = hygiene.secret_file_names(names)
    assert hits == [], _fail_with(hits)


def test_no_email_addresses_in_the_repository(tmp_path: Path) -> None:
    names = hygiene.repository_files(PROJECT_ROOT, tmp_path)
    hits: list[hygiene.Hit] = []
    for name, text in hygiene.read_text_files(PROJECT_ROOT, names):
        if text is not None:
            hits += hygiene.email_addresses(name, text)
    assert hits == [], _fail_with(hits)


def test_no_file_names_this_machines_account_temporary_directory_or_checkout(
    tmp_path: Path,
) -> None:
    """Nothing tracked (or about to be) says where it was written: not the account's profile
    directory (`Users/<name>`, `home/<name>`), not the system temporary directory, not the
    absolute path of this checkout. Example paths in tests use invented names."""
    names = hygiene.repository_files(PROJECT_ROOT, tmp_path)
    assert account_names(), "the account name could not be read: the check would prove nothing"
    found = [
        f"{name}: {trace}"
        for name, text in hygiene.read_text_files(PROJECT_ROOT, names)
        if text is not None
        for trace in local_traces(text, PROJECT_ROOT, absolute_paths=False)
    ]
    assert found == []


def test_all_text_files_are_valid_utf8(tmp_path: Path) -> None:
    names = hygiene.repository_files(PROJECT_ROOT, tmp_path)
    unreadable = []
    for name in names:
        path = PROJECT_ROOT / name
        if not path.is_file():
            continue
        data = path.read_bytes()
        if b"\0" in data[: hygiene.BINARY_PROBE_BYTES]:
            continue
        try:
            data.decode("utf-8")
        except UnicodeDecodeError:
            unreadable.append(name)
    assert unreadable == []


@pytest.mark.parametrize("name", ["CLAUDE.md", "PLAN.md"])
def test_plan_and_working_rules_are_pure_ascii_without_cr(name: str) -> None:
    data = (PROJECT_ROOT / name).read_bytes()
    assert data.isascii()
    assert b"\r" not in data
    assert not any(byte < 0x20 and byte not in (9, 10) for byte in data)
    assert not data.startswith(b"\xef\xbb\xbf")


# -- positive controls in temporary repositories ----------------------------------------------


def _repo(tmp_path: Path) -> GitRepo:
    return GitRepo.create(tmp_path / "control", tmp_path)


def test_forbidden_character_control_detects_each(tmp_path: Path) -> None:
    # One repository for every code point (a git process per case would dominate the gate time);
    # each code point still has its own file and must be reported at its own line, alone.
    repo = _repo(tmp_path)
    code_points = [*BIDI, *ZERO_WIDTH, 0x07, 0x1B, 0x7F, 0x85]
    for code_point in code_points:
        repo.write(f"notes-{code_point:04x}.txt", "fine line\nbad" + chr(code_point) + "line\n")
    hits = hygiene.check_repository(repo.path, tmp_path)
    assert sorted((hit.check, hit.path, hit.line) for hit in hits) == sorted(
        ("forbidden-character", f"notes-{code_point:04x}.txt", 2) for code_point in code_points
    )
    assert all("bad" not in hit.format() for hit in hits)  # findings never carry file content


def test_allowed_whitespace_is_not_flagged(tmp_path: Path) -> None:
    repo = _repo(tmp_path)
    repo.write("notes.txt", "tab\there\r\nnext line\n")
    assert hygiene.check_repository(repo.path, tmp_path) == []


SECRET_FILE_NAMES = [
    "server.key",
    "cert.pem",
    "store.p12",
    "store.pfx",
    "id_rsa",
    "id_rsa.pub",
    "id_ed25519",
    "keys/id_ed25519.bak",
    ".env",
    ".env.production",
    "release.keystore",
    "release.jks",
    "UPPER.PEM",
]


def test_secret_file_control_detects_each_name(tmp_path: Path) -> None:
    # One repository for every name; each name must be reported, as a secret file, once.
    repo = _repo(tmp_path)
    for name in SECRET_FILE_NAMES:
        repo.write(name, "placeholder\n")
    hits = hygiene.check_repository(repo.path, tmp_path)
    assert sorted((hit.check, hit.path) for hit in hits) == sorted(
        ("secret-file", name) for name in SECRET_FILE_NAMES
    )


def test_secret_file_control_ignores_ordinary_names(tmp_path: Path) -> None:
    repo = _repo(tmp_path)
    for name in ["keys.md", "environment.txt", "pemfile.txt", "src/monkey.py", "env.py"]:
        repo.write(name, "x\n")
    assert hygiene.check_repository(repo.path, tmp_path) == []


def test_ignored_secret_file_is_not_listed_but_a_staged_one_is(tmp_path: Path) -> None:
    repo = _repo(tmp_path)
    repo.write(".gitignore", "*.pem\n")
    repo.write("ignored.pem", "x\n")
    assert hygiene.check_repository(repo.path, tmp_path) == []
    repo.git("add", "--force", "--", "ignored.pem")
    hits = hygiene.check_repository(repo.path, tmp_path)
    assert [hit.check for hit in hits] == ["secret-file"]


def test_email_control_detects_an_address_built_at_runtime(tmp_path: Path) -> None:
    repo = _repo(tmp_path)
    address = "someone" + "@" + "example" + "." + "invalid"
    repo.write("docs.md", "contact: " + address + "\nno address here\n")
    hits = hygiene.check_repository(repo.path, tmp_path)
    assert [(hit.check, hit.line) for hit in hits] == [("email-address", 1)]
    assert address not in hits[0].format()


def test_email_check_ignores_at_signs_in_ordinary_text(tmp_path: Path) -> None:
    repo = _repo(tmp_path)
    lines = [
        "uses: actions/checkout@v5",
        "uses: actions/setup-python@v6",
        "@pytest.mark.slow",
        "a @ b matrix multiplication",
    ]
    repo.write("ci.yml", "\n".join(lines) + "\n")
    assert hygiene.check_repository(repo.path, tmp_path) == []


def test_untracked_files_are_checked_and_deleted_tracked_files_are_skipped(
    tmp_path: Path,
) -> None:
    repo = _repo(tmp_path)
    repo.write("gone.txt", "x\n")
    repo.add("gone.txt")
    repo.commit("add")
    (repo.path / "gone.txt").unlink()
    assert hygiene.check_repository(repo.path, tmp_path) == []
    repo.write("new/untracked.txt", "a" + chr(0x200B) + "b\n")
    hits = hygiene.check_repository(repo.path, tmp_path)
    assert [hit.path for hit in hits] == ["new/untracked.txt"]


def test_binary_and_non_utf8_files_are_not_text_checked(tmp_path: Path) -> None:
    repo = _repo(tmp_path)
    repo.write("blob.bin", b"\x00" + chr(0x202E).encode("utf-8") + b"\x00")
    repo.write("latin1.txt", b"caf\xe9\n")
    assert hygiene.check_repository(repo.path, tmp_path) == []


def test_check_repository_runs_all_checks_together(tmp_path: Path) -> None:
    repo = _repo(tmp_path)
    repo.write("a.pem", "x\n")
    repo.write("b.txt", "z" + chr(0x202E) + "\n")
    hits = hygiene.check_repository(repo.path, tmp_path)
    assert {hit.check for hit in hits} == {"secret-file", "forbidden-character"}
