"""`scan-git` and `scan --gitignore` against real throw-away repositories (PLAN.md Phase 4).

Every repository is created in `tmp_path` by `tests/gitrepo.py`: argument lists, a from-scratch
environment, the D17 identity through the subprocess environment only, no hooks. These tests build
real history (many git processes each), so they are `slow`: the full gate and CI run them; the
default gate runs the smoke test in `test_git_smoke.py`, the hostile-repository test and the
scripted-process tests of the same code.
"""

from __future__ import annotations

import hashlib
import json
import os
import shutil
from collections.abc import Callable
from pathlib import Path
from typing import Any

import pytest

from secret_scanner.app.scan import ScanRequest, run_scan
from secret_scanner.app.scan_git import GitScanRequest, run_scan_git
from secret_scanner.cli import main as cli_main
from secret_scanner.core.errors import ExitCode, GitError, UsageError
from secret_scanner.core.fakes import build_fake, fake_private_key
from secret_scanner.core.models import IssueKind, Target
from secret_scanner.services import git_scanner
from secret_scanner.services.loader import dump_yaml, load_builtin_rules
from tests.conftest import leak_check
from tests.gitrepo import GitRepo, run_git
from tests.helpers import FakeClock

pytestmark = [pytest.mark.requires_git, pytest.mark.slow]

RULES = {rule.id: rule for rule in load_builtin_rules().rules}
LF = chr(10)
Cli = Callable[..., tuple[int, str, str]]


def secret(rule_id: str = "npm-token", seed: str = "git") -> str:
    return build_fake(RULES[rule_id], seed)


@pytest.fixture
def home(tmp_path: Path) -> Path:
    directory = tmp_path / "githome"
    directory.mkdir()
    return directory


@pytest.fixture
def repo(tmp_path: Path, home: Path) -> GitRepo:
    return GitRepo.create(tmp_path / "repo", home)


@pytest.fixture
def cli(capsys: pytest.CaptureFixture[str]) -> Cli:
    def invoke(*argv: str) -> tuple[int, str, str]:
        code = cli_main.main(list(argv))
        captured = capsys.readouterr()
        return code, captured.out, captured.err

    return invoke


def scan(path: Path, **options: Any) -> Any:
    return run_scan_git(GitScanRequest(path=str(path), **options), FakeClock())


def snapshot(root: Path) -> dict[str, tuple[int, str, int]]:
    """Every file under `root` (git directory included): size, content hash, mtime_ns; plus every
    directory's mtime_ns. Equal snapshots mean nothing was created, changed or removed."""
    state: dict[str, tuple[int, str, int]] = {}
    for current, directories, files in os.walk(root):
        for name in directories:
            path = Path(current) / name
            state[str(path.relative_to(root)) + "/"] = (0, "", path.stat().st_mtime_ns)
        for name in files:
            path = Path(current) / name
            data = path.read_bytes()
            info = path.stat()
            state[str(path.relative_to(root))] = (
                len(data),
                hashlib.sha256(data).hexdigest(),
                info.st_mtime_ns,
            )
    return state


# -- what history scanning must get right ------------------------------------------------------


def test_a_secret_added_and_deleted_later_is_found_with_its_commit(repo: GitRepo) -> None:
    repo.commit_files("start", {"README.md": "hello" + LF})
    added = repo.commit_files("add settings", {"config/app.env": f"TOKEN={secret()}" + LF})
    repo.commit_files("remove the token", {"config/app.env": "TOKEN=from-vault" + LF})
    outcome = scan(repo.path)
    assert outcome.exit_code == ExitCode.FINDINGS
    report = outcome.report
    assert report.target is Target.GIT
    assert report.history_complete is True
    assert [f.rule_id for f in report.findings] == ["npm-token"]
    finding = report.findings[0]
    assert finding.location.commit == added
    assert finding.location.path == "config/app.env"
    assert finding.location.commit_time is not None
    assert report.stats.commits == 3
    # the working tree is clean of the secret: only history shows it
    assert secret() not in (repo.path / "config" / "app.env").read_text("utf-8")


def test_the_table_names_the_commit(repo: GitRepo, cli: Cli) -> None:
    commit = repo.commit_files("add", {"a.env": f"TOKEN={secret()}" + LF})
    code, out, err = cli("scan-git", str(repo.path))
    assert code == ExitCode.FINDINGS
    assert err == ""
    assert f"a.env:1:7@{commit[:12]}" in out
    assert "history of" in out
    assert "history complete: yes" in out


def test_a_secret_kept_for_many_commits_is_one_finding_at_the_first(repo: GitRepo) -> None:
    body = f"TOKEN={secret()}" + LF
    first = repo.commit_files("one", {"a.env": body})
    for number in range(4):
        repo.commit_files(f"edit {number}", {"a.env": f"# edit {number}" + LF + body})
    outcome = scan(repo.path)
    assert [f.location.commit for f in outcome.report.findings] == [first]
    assert outcome.report.stats.blobs_scanned == 5


def test_a_secret_present_only_in_a_merge_resolution_is_found(repo: GitRepo) -> None:
    repo.commit_files("base", {"a.txt": "a" + LF})
    repo.git("checkout", "-q", "-b", "side")
    repo.commit_files("side work", {"b.txt": "b" + LF})
    repo.git("checkout", "-q", "main")
    repo.commit_files("main work", {"c.txt": "c" + LF})
    repo.git("merge", "-q", "--no-ff", "--no-commit", "side")
    repo.write("merged.env", f"TOKEN={secret()}" + LF)
    repo.add("merged.env")
    merge = repo.commit("merge with a resolution")
    outcome = scan(repo.path)
    findings = outcome.report.findings
    assert [f.location.path for f in findings] == ["merged.env"]
    assert findings[0].location.commit == merge


def test_a_secret_in_the_root_commit(repo: GitRepo) -> None:
    root = repo.commit_files("root", {"k.env": f"TOKEN={secret()}" + LF})
    repo.commit_files("later", {"x.txt": "x" + LF})
    outcome = scan(repo.path)
    assert [f.location.commit for f in outcome.report.findings] == [root]


def test_a_rename_is_a_new_path_and_so_a_new_fingerprint(repo: GitRepo) -> None:
    repo.commit_files("add", {"old.env": f"TOKEN={secret()}" + LF})
    repo.git("mv", "old.env", "new.env")
    renamed = repo.commit("rename")
    outcome = scan(repo.path)
    paths = {f.location.path: f for f in outcome.report.findings}
    assert set(paths) == {"old.env", "new.env"}
    assert paths["new.env"].location.commit == renamed
    assert paths["old.env"].fingerprint != paths["new.env"].fingerprint


def test_the_same_blob_at_two_paths_is_read_once(repo: GitRepo) -> None:
    body = f"TOKEN={secret()}" + LF
    repo.commit_files("two copies", {"one.env": body, "sub/two.env": body})
    outcome = scan(repo.path)
    assert sorted(f.location.path for f in outcome.report.findings) == ["one.env", "sub/two.env"]
    assert outcome.report.stats.blobs_scanned == 1
    assert outcome.report.stats.blobs_from_cache == 1


def test_a_binary_blob_is_counted_and_not_scanned(repo: GitRepo) -> None:
    repo.commit_files("blob", {"data.bin": b"\x00\x01\x02" + secret().encode()})
    outcome = scan(repo.path)
    assert outcome.exit_code == ExitCode.OK
    assert outcome.report.stats.skipped_binary == 1


def test_a_submodule_entry_and_a_symlink_entry_are_skipped(repo: GitRepo) -> None:
    repo.commit_files("base", {"a.txt": "a" + LF})
    empty_blob = repo.git("rev-parse", "HEAD:a.txt").stdout.strip()
    commit = repo.head()
    repo.git("update-index", "--add", "--cacheinfo", f"160000,{commit},submodule")
    repo.git("update-index", "--add", "--cacheinfo", f"120000,{empty_blob},link")
    repo.commit("add a gitlink and a symlink")
    outcome = scan(repo.path)
    assert outcome.exit_code == ExitCode.OK
    assert (outcome.report.stats.skipped_submodule, outcome.report.stats.skipped_symlink) == (1, 1)


def test_an_oversized_blob_is_an_issue_and_the_rest_is_still_scanned(
    repo: GitRepo, tmp_path: Path
) -> None:
    repo.commit_files("files", {"big.txt": b"x" * 4000, "ok.env": f"TOKEN={secret()}" + LF})
    config = tmp_path / "limits.yaml"
    config.write_bytes(
        dump_yaml({"version": 1, "limits": {"max_file_bytes": 1000}}).encode("ascii")
    )
    outcome = scan(repo.path, config=str(config))
    assert outcome.exit_code == ExitCode.INCOMPLETE
    assert [i.kind for i in outcome.report.issues] == [IssueKind.TOO_LARGE]
    assert [f.location.path for f in outcome.report.findings] == ["ok.env"]
    assert outcome.report.complete is False
    assert outcome.report.history_complete is False


def test_executable_files_and_crlf_content(repo: GitRepo) -> None:
    repo.write("run.env", f"TOKEN={secret()}".encode() + b"\r\n")
    repo.add("run.env")
    repo.git("update-index", "--chmod=+x", "run.env")
    repo.commit("exec bit and CRLF")
    findings = scan(repo.path).report.findings
    assert [(f.location.path, f.location.line) for f in findings] == [("run.env", 1)]


def test_revisions_and_ranges(repo: GitRepo) -> None:
    a = repo.commit_files("a", {"a.txt": "a" + LF})
    b = repo.commit_files("b", {"b.env": f"TOKEN={secret()}" + LF})
    c = repo.commit_files("c", {"c.txt": "c" + LF})
    assert [f.location.commit for f in scan(repo.path, revision=c).report.findings] == [b]
    assert [f.location.commit for f in scan(repo.path, revision="main").report.findings] == [b]
    assert scan(repo.path, revision=a).report.findings == ()
    assert [
        f.location.commit for f in scan(repo.path, revision_range=f"{a}..{b}").report.findings
    ] == [b]
    assert scan(repo.path, revision_range=f"{b}..{c}").report.findings == ()
    assert scan(repo.path, revision_range="main..main").report.stats.commits == 0


def test_unknown_and_malformed_revisions(repo: GitRepo) -> None:
    repo.commit_files("a", {"a.txt": "a" + LF})
    with pytest.raises(GitError, match="does not name a commit"):
        scan(repo.path, revision="no-such-branch")
    for bad in ("--output=x", "-c x", "@{-1}", "a:b", "HEAD~1", "a" * 300):
        with pytest.raises(UsageError):
            scan(repo.path, revision=bad)
    with pytest.raises(UsageError):
        scan(repo.path, revision="main", revision_range="a..b")


def test_replace_refs_are_ignored(repo: GitRepo, tmp_path: Path) -> None:
    secret_commit = repo.commit_files("with the secret", {"s.env": f"TOKEN={secret()}" + LF})
    empty = tmp_path / "empty-tree"
    empty.write_bytes(b"")
    tree = repo.git("hash-object", "-t", "tree", "-w", str(empty)).stdout.strip()
    clean = repo.git("commit-tree", "-m", "clean replacement", tree).stdout.strip()
    repo.git("replace", secret_commit, clean)
    # git itself, honouring the replace ref, sees an empty commit
    assert ":" not in repo.git("log", "--raw", "--format=%H", "main").stdout
    outcome = scan(repo.path)
    assert [f.location.commit for f in outcome.report.findings] == [secret_commit]


def test_only_the_repository_root_is_a_repository(repo: GitRepo) -> None:
    repo.commit_files("a", {"sub/a.txt": "a" + LF})
    with pytest.raises(GitError, match="not a git repository"):
        scan(repo.path / "sub")


def test_a_bare_repository_and_a_git_directory_can_be_scanned(
    repo: GitRepo, tmp_path: Path, home: Path
) -> None:
    commit = repo.commit_files("a", {"a.env": f"TOKEN={secret()}" + LF})
    bare = tmp_path / "bare.git"
    clone(repo.path, bare, home, "--bare")
    assert [f.location.commit for f in scan(bare).report.findings] == [commit]
    assert [f.location.commit for f in scan(repo.path / ".git").report.findings] == [commit]


def test_the_scan_changes_nothing_in_the_repository(repo: GitRepo, tmp_path: Path) -> None:
    repo.commit_files("a", {"a.env": f"TOKEN={secret()}" + LF, "b.txt": "b" + LF})
    repo.write("untracked.txt", "u" + LF)
    before = snapshot(repo.path)
    assert scan(repo.path).exit_code == ExitCode.FINDINGS
    run_scan(
        ScanRequest(path=str(repo.path), gitignore=True),
        FakeClock(),
    )
    assert snapshot(repo.path) == before


# -- repository states --------------------------------------------------------------------------


def clone(source: Path, destination: Path, home: Path, *flags: str) -> None:
    run_git(
        destination.parent,
        home,
        "clone",
        "-q",
        *flags,
        source.as_uri(),
        str(destination),
        extra_config=(("protocol.file.allow", "always"),),
    )


def test_a_shallow_clone_is_incomplete_unless_allowed(
    repo: GitRepo, tmp_path: Path, home: Path
) -> None:
    repo.commit_files("one", {"a.txt": "a" + LF})
    repo.commit_files("two", {"b.env": f"TOKEN={secret()}" + LF})
    shallow = tmp_path / "shallow"
    clone(repo.path, shallow, home, "--depth", "1")
    outcome = scan(shallow)
    assert outcome.exit_code == ExitCode.INCOMPLETE
    assert [i.kind for i in outcome.report.issues] == [IssueKind.SHALLOW_HISTORY]
    assert outcome.report.history_complete is False
    allowed = scan(shallow, allow_shallow=True)
    assert allowed.exit_code == ExitCode.FINDINGS  # the secret is in the one commit that exists
    assert allowed.report.history_complete is False
    assert any("shallow" in notice for notice in allowed.notices)
    assert allowed.report.issues == ()


def test_a_partial_clone_reports_missing_blobs_and_never_fetches(
    repo: GitRepo, tmp_path: Path, home: Path
) -> None:
    from tests.hostile import Markers

    repo.git("config", "uploadpack.allowFilter", "true")
    repo.git("config", "uploadpack.allowAnySHA1InWant", "true")
    repo.commit_files("files", {"a.env": f"TOKEN={secret()}" + LF, "b.txt": "b" + LF})
    partial = tmp_path / "partial"
    clone(repo.path, partial, home, "--no-checkout", "--filter=blob:none")
    markers = Markers(tmp_path / "markers")
    run_git(partial, home, "config", "remote.origin.uploadpack", markers.command("lazy-fetch"))
    run_git(partial, home, "config", "remote.origin.promisor", "true")
    outcome = scan(partial)
    assert outcome.exit_code == ExitCode.INCOMPLETE
    assert {i.kind for i in outcome.report.issues} == {IssueKind.MISSING_OBJECT}
    assert outcome.report.findings == ()
    assert markers.fired() == []  # no lazy fetch was attempted


# -- the refusals before git reads anything ----------------------------------------------------


def test_alternates_grafts_and_links_are_refused(repo: GitRepo, tmp_path: Path) -> None:
    repo.commit_files("a", {"a.txt": "a" + LF})
    info = repo.path / ".git" / "objects" / "info"
    info.mkdir(parents=True, exist_ok=True)
    (info / "alternates").write_bytes(str(tmp_path / "elsewhere" / "objects").encode() + b"\n")
    with pytest.raises(GitError, match="alternates"):
        scan(repo.path)
    (info / "alternates").unlink()
    grafts = repo.path / ".git" / "info" / "grafts"
    grafts.parent.mkdir(exist_ok=True)
    grafts.write_bytes(f"{repo.head()}".encode() + b"\n")
    with pytest.raises(GitError, match="grafts"):
        scan(repo.path)
    grafts.unlink()
    assert scan(repo.path).exit_code == ExitCode.OK


def test_a_gitdir_link_file_is_refused(repo: GitRepo, tmp_path: Path) -> None:
    repo.commit_files("a", {"a.txt": "a" + LF})
    worktree = tmp_path / "wt"
    repo.git("worktree", "add", "-q", str(worktree), "-b", "other")
    assert (worktree / ".git").is_file()
    with pytest.raises(GitError, match="worktree or submodule"):
        scan(worktree)


@pytest.mark.requires_symlinks
def test_a_dot_git_symlink_is_refused(repo: GitRepo, tmp_path: Path) -> None:
    repo.commit_files("a", {"a.txt": "a" + LF})
    outer = tmp_path / "outer"
    outer.mkdir()
    (outer / ".git").symlink_to(repo.path / ".git", target_is_directory=True)
    with pytest.raises(GitError, match="link"):
        scan(outer)


def test_a_missing_git_is_exit_code_three(
    repo: GitRepo, cli: Cli, monkeypatch: pytest.MonkeyPatch
) -> None:
    repo.commit_files("a", {"a.txt": "a" + LF})
    with pytest.raises(GitError, match="not found"):
        run_scan_git(GitScanRequest(path=str(repo.path)), FakeClock(), environment={"PATH": ""})
    monkeypatch.setenv("PATH", "")
    code, out, err = cli("scan-git", str(repo.path))
    assert (code, out) == (ExitCode.GIT, "")
    assert "git was not found" in err


def test_a_git_given_with_dash_dash_git_is_used_and_validated(repo: GitRepo, cli: Cli) -> None:
    repo.commit_files("a", {"a.txt": "a" + LF})
    real = shutil.which("git")
    assert real is not None
    assert cli("scan-git", str(repo.path), "--git", real)[0] == ExitCode.OK
    code, _, err = cli("scan-git", str(repo.path), "--git", "git")
    assert code == ExitCode.USAGE
    assert "absolute" in err


# -- scan --gitignore --------------------------------------------------------------------------


def test_gitignore_filter_reads_only_what_git_lists(repo: GitRepo) -> None:
    repo.commit_files(
        "tracked",
        {
            ".gitignore": "ignored.env" + LF + "build/" + LF,
            "tracked.env": f"TOKEN={secret(seed='tracked')}" + LF,
        },
    )
    repo.write("untracked.env", f"TOKEN={secret(seed='untracked')}" + LF)
    repo.write("ignored.env", f"TOKEN={secret(seed='ignored')}" + LF)
    repo.write("build/out.env", f"TOKEN={secret(seed='build')}" + LF)
    everything = run_scan(ScanRequest(path=str(repo.path)), FakeClock())
    filtered = run_scan(ScanRequest(path=str(repo.path), gitignore=True), FakeClock())
    assert {f.location.path for f in everything.report.findings} == {
        "tracked.env",
        "untracked.env",
        "ignored.env",
        "build/out.env",
    }
    assert {f.location.path for f in filtered.report.findings} == {"tracked.env", "untracked.env"}
    assert filtered.report.stats.skipped_gitignored >= 2


def test_gitignore_works_from_a_subdirectory_of_the_work_tree(repo: GitRepo) -> None:
    repo.commit_files(
        "tracked",
        {".gitignore": "*.skip" + LF, "sub/a.env": f"TOKEN={secret(seed='a')}" + LF},
    )
    repo.write("sub/b.skip", f"TOKEN={secret(seed='b')}" + LF)
    repo.write("top.env", f"TOKEN={secret(seed='top')}" + LF)
    outcome = run_scan(ScanRequest(path=str(repo.path / "sub"), gitignore=True), FakeClock())
    assert [f.location.path for f in outcome.report.findings] == ["a.env"]


def test_gitignore_outside_a_work_tree_is_a_usage_error(tmp_path: Path, cli: Cli) -> None:
    (tmp_path / "plain").mkdir()
    code, _, err = cli("scan", str(tmp_path / "plain"), "--gitignore")
    assert code == ExitCode.USAGE
    assert "not inside a git work tree" in err


# -- baselines and outputs -------------------------------------------------------------------


def test_baseline_round_trip_and_a_directory_baseline_works_for_history(
    repo: GitRepo, tmp_path: Path, cli: Cli
) -> None:
    repo.commit_files("add", {"a.env": f"TOKEN={secret()}" + LF})
    work = tmp_path / "work"
    work.mkdir()
    from_dir = work / "from-scan.yaml"
    assert cli("scan", str(repo.path), "--write-baseline", str(from_dir))[0] == ExitCode.FINDINGS
    code, out, _ = cli("scan-git", str(repo.path), "--baseline", str(from_dir))
    assert code == ExitCode.OK
    assert "1 suppressed (1 by fingerprint" in out
    from_history = work / "from-history.yaml"
    code, _, err = cli("scan-git", str(repo.path), "--write-baseline", str(from_history))
    assert code == ExitCode.FINDINGS
    assert "baseline with 1 entries written" in err
    assert cli("scan-git", str(repo.path), "--baseline", str(from_history))[0] == ExitCode.OK
    assert cli("scan", str(repo.path), "--baseline", str(from_history))[0] == ExitCode.OK


def test_json_report_for_history(repo: GitRepo, cli: Cli) -> None:
    commit = repo.commit_files("add", {"a.env": f"TOKEN={secret()}" + LF})
    code, out, _ = cli("scan-git", str(repo.path), "--format", "json", "--host-label", "ci")
    document = json.loads(out)
    assert code == ExitCode.FINDINGS
    assert document["target"]["kind"] == "git"
    assert document["history_complete"] is True
    assert document["findings"][0]["commit"] == commit
    assert document["stats"]["commits"] == 1
    assert out.isascii()


def test_output_inside_the_repository_is_refused_before_git_runs(repo: GitRepo, cli: Cli) -> None:
    repo.commit_files("a", {"a.txt": "a" + LF})
    code, _, err = cli("scan-git", str(repo.path), "--output", str(repo.path / "report.txt"))
    assert code == ExitCode.USAGE
    assert "inside the scanned tree" in err
    assert not (repo.path / "report.txt").exists()


# -- hostile data in the repository ---------------------------------------------------------------


HOSTILE_NAMES = [
    "evil" + chr(0x202E) + "txt.exe",
    "zero" + chr(0x200B) + "width.env",
    "bom" + chr(0xFEFF) + ".env",
    "line" + chr(0x2028) + "sep.env",
    "caf" + chr(0xE9) + ".env",
    "back" + chr(92) + "slash.env",
]
POSIX_HOSTILE_NAMES = [
    "new" + chr(10) + "line.env",
    "esc" + chr(0x1B) + "[31mred.env",
    "tab" + chr(9) + "name.env",
]


def _forbidden(text: str) -> list[str]:
    bad = []
    for char in text:
        code = ord(char)
        if (
            code in (0x7F,)
            or 0x00 <= code <= 0x08
            or 0x0B <= code <= 0x1F
            or 0x80 <= code <= 0x9F
            or 0x200B <= code <= 0x200F
            or 0x2028 <= code <= 0x202E
            or 0x2060 <= code <= 0x206F
            or code == 0xFEFF
        ):
            bad.append(f"U+{code:04X}")
    return bad


@pytest.mark.parametrize("name", HOSTILE_NAMES)
def test_hostile_path_names_are_inert_in_every_output(repo: GitRepo, cli: Cli, name: str) -> None:
    repo.commit_files("hostile", {name: f"TOKEN={secret()}" + LF})
    code, table, err = cli("scan-git", str(repo.path))
    assert code == ExitCode.FINDINGS
    code, document, _ = cli("scan-git", str(repo.path), "--format", "json")
    assert document.isascii()
    json.loads(document)
    for text in (table, err):
        assert _forbidden(text.replace(LF, "")) == []


@pytest.mark.posix_only
@pytest.mark.parametrize("name", POSIX_HOSTILE_NAMES)
def test_posix_hostile_path_names_are_inert(repo: GitRepo, cli: Cli, name: str) -> None:
    repo.commit_files("hostile", {name: f"TOKEN={secret()}" + LF})
    code, table, _ = cli("scan-git", str(repo.path))
    assert code == ExitCode.FINDINGS
    rows = [line for line in table.splitlines() if "npm-token" in line]
    assert len(rows) == 1  # a newline in a name cannot forge a second row
    assert _forbidden(table.replace(LF, "")) == []


def test_commit_messages_and_author_names_never_reach_an_output(
    repo: GitRepo, cli: Cli, tmp_path: Path
) -> None:
    message = (
        "subject " + chr(0x1B) + "[2J" + chr(0x202E) + " " + secret(seed="in-message") + LF + "body"
    )
    author = "Eve " + chr(0x1B) + "]0;owned" + chr(7) + chr(0x202E)
    repo.write("a.env", f"TOKEN={secret(seed='in-file')}" + LF)
    repo.add("a.env")
    repo.commit(message, author=author)
    work = tmp_path / "work"
    work.mkdir()
    outputs = []
    for argv in (
        ("scan-git", str(repo.path)),
        ("scan-git", str(repo.path), "--format", "json"),
        ("scan-git", str(repo.path), "--write-baseline", str(work / "b.yaml")),
    ):
        _, out, err = cli(*argv)
        outputs += [out, err]
    outputs.append((work / "b.yaml").read_text("utf-8"))
    for text in outputs:
        assert chr(0x1B) not in text
        assert chr(0x202E) not in text
        assert "subject" not in text
        assert "Eve" not in text
        assert leak_check(text, secret(seed="in-message")) is None


# -- no full secret anywhere ----------------------------------------------------------------------


def _write(path: Path, document: dict[str, Any]) -> str:
    path.write_bytes(dump_yaml(document).encode("ascii"))
    return str(path)


REPRESENTATIVE = ["aws-access-key-id", "npm-token", "private-key", "entropy-base64"]


@pytest.mark.parametrize("name", REPRESENTATIVE)
def test_nothing_that_scan_git_emits_contains_the_secret(
    repo: GitRepo, tmp_path: Path, cli: Cli, monkeypatch: pytest.MonkeyPatch, name: str
) -> None:
    from secret_scanner.core.fakes import fake_entropy_token

    if name == "private-key":
        value = fake_private_key("gitleak", label="RSA")
        needle = "".join(row for row in value.splitlines() if not row.startswith("-----"))
        text, allowed = value, 0
    elif name == "entropy-base64":
        needle = fake_entropy_token("gitleak")
        text, allowed = f"api_token = {needle}" + LF, 4
    else:
        needle = secret(name, "gitleak")
        text, allowed = f"aws_secret_access_key = {needle}" + LF, RULES[name].shown_chars
    repo.commit_files("add", {"s.txt": text})
    repo.commit_files("remove", {"s.txt": "gone" + LF})
    work = tmp_path / "work"
    work.mkdir()
    pieces: list[tuple[str, str]] = []

    def run(label: str, *argv: str) -> int:
        code, out, err = cli(*argv)
        pieces.append((f"{label}: stdout", out))
        pieces.append((f"{label}: stderr", err))
        return code

    assert run("table", "scan-git", str(repo.path), "--min-confidence", "low") == 1
    run("json", "scan-git", str(repo.path), "--format", "json", "--min-confidence", "low")
    report, baseline = work / "r.json", work / "b.yaml"
    run(
        "files",
        "scan-git",
        str(repo.path),
        "--format",
        "json",
        "--min-confidence",
        "low",
        "--output",
        str(report),
        "--write-baseline",
        str(baseline),
    )
    pieces.append(("report", report.read_text("utf-8")))
    pieces.append(("baseline", baseline.read_text("utf-8")))
    run(
        "suppressed",
        "scan-git",
        str(repo.path),
        "--baseline",
        str(baseline),
        "--show-suppressed",
        "--min-confidence",
        "low",
    )
    bad = _write(work / "bad.yaml", {"version": 1, needle: True})
    assert run("config", "scan-git", str(repo.path), "--config", bad) == 2
    bad_baseline = _write(
        work / "bad-b.yaml", {"version": 1, "suppress": [{"fingerprint": needle}]}
    )
    assert run("baseline", "scan-git", str(repo.path), "--baseline", bad_baseline) == 2
    assert run("output-exists", "scan-git", str(repo.path), "--output", str(report)) == 2

    def explode(*args: object, **kwargs: object) -> object:
        raise RuntimeError(needle)

    monkeypatch.setattr(git_scanner, "scan_history", explode)
    from secret_scanner.app import scan_git as app_module

    monkeypatch.setattr(app_module, "scan_history", explode)
    assert run("internal", "scan-git", str(repo.path)) == 2

    for label, piece in pieces:
        problem = leak_check(piece, needle, allowed_shown=allowed)
        if problem is not None:
            pytest.fail(f"{name} / {label}: {problem}", pytrace=False)
    # nothing but the report and the baseline was left behind
    assert sorted(path.name for path in work.iterdir() if "bad" not in path.name) == [
        "b.yaml",
        "r.json",
    ]


# -- SHA-256 repositories --------------------------------------------------------------------------


@pytest.mark.requires_git_sha256
def test_a_sha256_repository(tmp_path: Path, home: Path) -> None:
    path = tmp_path / "sha256"
    path.mkdir()
    run_git(
        path, home, "init", "-q", "-b", "main", "--template=", "--object-format=sha256", str(path)
    )
    repository = GitRepo(path, home)
    commit = repository.commit_files("add", {"a.env": f"TOKEN={secret()}" + LF})
    assert len(commit) == 64
    outcome = scan(path)
    assert [f.location.commit for f in outcome.report.findings] == [commit]
    assert outcome.exit_code == ExitCode.FINDINGS


# -- bounds against a real repository ---------------------------------------------------------


def test_commit_and_blob_limits_from_a_configuration_file(repo: GitRepo, tmp_path: Path) -> None:
    for number in range(4):
        repo.commit_files(
            f"c{number}", {f"f{number}.env": f"TOKEN={secret(seed=str(number))}" + LF}
        )
    config = tmp_path / "limits.yaml"
    config.write_bytes(dump_yaml({"version": 1, "limits": {"max_git_commits": 2}}).encode("ascii"))
    outcome = scan(repo.path, config=str(config))
    assert outcome.exit_code == ExitCode.INCOMPLETE
    assert [i.kind for i in outcome.report.issues] == [IssueKind.LIMIT_REACHED]
    assert len(outcome.report.findings) == 2  # the two commits that were walked
    assert outcome.report.history_complete is False


def test_fail_on_decides_the_exit_code_of_a_history_scan(repo: GitRepo) -> None:
    repo.commit_files("add", {"a.env": f"TOKEN={secret()}" + LF})
    from secret_scanner.core.models import Severity

    assert scan(repo.path).exit_code == ExitCode.FINDINGS
    assert scan(repo.path, fail_on=Severity.CRITICAL).exit_code == ExitCode.OK


def test_the_walk_order_is_stable_between_runs(repo: GitRepo) -> None:
    for number in range(3):
        repo.commit_files(
            f"c{number}", {f"f{number}.env": f"TOKEN={secret(seed=str(number))}" + LF}
        )
    first = [(f.location.path, f.location.commit) for f in scan(repo.path).report.findings]
    second = [(f.location.path, f.location.commit) for f in scan(repo.path).report.findings]
    assert first == second
    assert len(first) == 3
