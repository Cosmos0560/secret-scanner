"""A hostile repository (PLAN.md D2, threat model "A hostile repository runs code through git").

The repository's own configuration, attributes, hooks and objects try every documented mechanism to
make git run a program or reach the network, and each program is a marker that writes a sentinel
file. Scanning it must leave the marker directory exactly as it was, complete (or fail safely), and
still find the secret in the history. A positive control proves that the same repository does fire
markers when git runs without the tool's protections, so a silent test harness cannot pass.
"""

from __future__ import annotations

import _socket  # the unpatched C type: the autouse fixture only replaces `socket.socket`
import os
import shutil
import subprocess
import threading
from collections.abc import Iterator
from pathlib import Path

import pytest

from secret_scanner.app.common import open_runner
from secret_scanner.app.scan import ScanRequest, run_scan
from secret_scanner.app.scan_git import GitScanRequest, run_scan_git
from secret_scanner.core.errors import ExitCode
from secret_scanner.core.fakes import build_fake
from secret_scanner.core.limits import DEFAULT_LIMITS
from secret_scanner.core.models import IssueKind
from secret_scanner.services.loader import load_builtin_rules
from tests.conftest import leak_check
from tests.gitrepo import GitRepo, git_binary, git_environment
from tests.helpers import FakeClock
from tests.hostile import Markers, make_executable

pytestmark = pytest.mark.requires_git

LF = chr(10)
RULES = {rule.id: rule for rule in load_builtin_rules().rules}
SECRET = build_fake(RULES["npm-token"], "hostile")

HOOK_NAMES = (
    "pre-commit",
    "prepare-commit-msg",
    "commit-msg",
    "post-commit",
    "post-checkout",
    "post-merge",
    "post-rewrite",
    "post-index-change",
    "reference-transaction",
    "fsmonitor-watchman",
    "pre-auto-gc",
    "pre-push",
    "pre-rebase",
    "update",
    "pre-receive",
    "post-receive",
    "push-to-checkout",
    "applypatch-msg",
)


class Listener:
    """A TCP listener on the loopback interface that records connection attempts."""

    def __init__(self) -> None:
        self._socket = _socket.socket(_socket.AF_INET, _socket.SOCK_STREAM)
        self._socket.bind(("127.0.0.1", 0))
        self._socket.listen(8)
        self._socket.settimeout(0.2)
        self.port: int = self._socket.getsockname()[1]
        self.connections = 0
        self._stop = threading.Event()
        self._thread = threading.Thread(target=self._run, daemon=True)
        self._thread.start()

    def _run(self) -> None:
        while not self._stop.is_set():
            try:
                descriptor, _ = self._socket._accept()  # type: ignore[attr-defined]  # C-level accept: (fd, address)
            except TimeoutError:
                continue
            except OSError:
                return
            self.connections += 1
            _socket.close(descriptor)

    def close(self) -> None:
        self._stop.set()
        self._thread.join(timeout=5)
        self._socket.close()


def _quote(value: str) -> str:
    return '"' + value.replace(chr(92), chr(92) * 2).replace('"', chr(92) + '"') + '"'


def config_text(settings: dict[str, str]) -> str:
    """The settings as the text of a git config file (`section.subsection.name = value`)."""
    grouped: dict[tuple[str, str | None], list[tuple[str, str]]] = {}
    for key, value in settings.items():
        section, _, rest = key.partition(".")
        subsection, dot, name = rest.rpartition(".")
        if not dot:
            subsection, name = "", rest
        grouped.setdefault((section, subsection or None), []).append((name, value))
    lines: list[str] = []
    for (group, sub), entries in grouped.items():
        lines.append(f"[{group}]" if sub is None else f"[{group} {_quote(sub)}]")
        lines += [f"{chr(9)}{name} = {_quote(value)}" for name, value in entries]
    return LF.join(lines) + LF


def configure(repo: GitRepo, markers: Markers, listener: Listener) -> None:
    """Write every hostile setting into the repository's own configuration."""
    command = markers.command
    posix = str(repo.path).replace(os.sep, "/")
    included = repo.path / ".git" / "hostile-include"
    included.write_text(config_text({"core.fsmonitor": command("include-fsmonitor")}), "utf-8")
    settings = {
        "core.repositoryformatversion": "1",
        "core.fsmonitor": command("fsmonitor"),
        "core.hooksPath": posix + "/hostile-hooks",
        "core.pager": command("pager"),
        "core.editor": command("editor"),
        "core.sshCommand": command("ssh"),
        "core.gitProxy": command("gitproxy"),
        "core.askPass": command("askpass"),
        "core.untrackedCache": "true",
        "core.alternateRefsCommand": command("alternate-refs"),
        "core.attributesFile": posix + "/hostile-attributes",
        "pager.log": command("pager-log"),
        "pager.cat-file": command("pager-cat-file"),
        "credential.helper": "!" + command("credential"),
        "diff.external": command("external-diff"),
        "diff.danger.textconv": command("textconv"),
        "diff.danger.command": command("diff-driver"),
        "filter.danger.clean": command("filter-clean"),
        "filter.danger.smudge": command("filter-smudge"),
        "filter.danger.process": command("filter-process"),
        "filter.danger.required": "true",
        "merge.danger.driver": command("merge-driver"),
        "log.showSignature": "true",
        "gpg.program": command("gpg"),
        "gpg.ssh.program": command("gpg-ssh"),
        "gpg.x509.program": command("gpg-x509"),
        "alias.log": "!" + command("alias-log"),
        "alias.cat-file": "!" + command("alias-cat-file"),
        "gc.auto": "1",
        "gc.autoDetach": "false",
        "maintenance.auto": "true",
        "uploadpack.packObjectsHook": command("pack-objects-hook"),
        "receive.procReceiveRefs": "refs/",
        "remote.origin.url": f"http://127.0.0.1:{listener.port}/hostile.git",
        "remote.origin.uploadpack": command("uploadpack"),
        "remote.origin.receivepack": command("receivepack"),
        "remote.origin.vcs": "hostile",
        "remote.origin.promisor": "true",
        "remote.origin.partialclonefilter": "blob:none",
        "extensions.partialClone": "origin",
        "protocol.allow": "always",
        "url.http://127.0.0.1:1/.insteadOf": "https://example.invalid/",
        "include.path": str(included).replace(os.sep, "/"),
    }
    with (repo.path / ".git" / "config").open("a", encoding="utf-8", newline=LF) as handle:
        handle.write(config_text(settings))
    # attributes in the tree, in info/attributes and in the file core.attributesFile names
    attributes = "* diff=danger filter=danger merge=danger" + LF
    (repo.path / ".gitattributes").write_text(attributes, "utf-8")
    (repo.path / ".git" / "info").mkdir(exist_ok=True)
    (repo.path / ".git" / "info" / "attributes").write_text(attributes, "utf-8")
    (repo.path / "hostile-attributes").write_text(attributes, "utf-8")
    # hooks, in the default place and where core.hooksPath points
    for directory in (repo.path / ".git" / "hooks", repo.path / "hostile-hooks"):
        directory.mkdir(exist_ok=True)
        for name in HOOK_NAMES:
            hook = directory / name
            hook.write_bytes(markers.shell_script(f"hook-{name}"))
            make_executable(hook)


def build_history(repo: GitRepo) -> str:
    """Two commits, the secret in the first and gone in the second; returns the first."""
    repo.commit_files("files", {"app.env": f"TOKEN={SECRET}" + LF, "notes.txt": "notes" + LF})
    first = repo.head()
    repo.commit_files("scrub", {"app.env": "TOKEN=from-the-vault" + LF})
    return first


def build_hostile(root: Path, markers: Markers, listener: Listener) -> tuple[GitRepo, str]:
    home = root / "githome"
    home.mkdir()
    repo = GitRepo.create(root / "hostile-repo", home)
    first = build_history(repo)
    configure(repo, markers, listener)
    return repo, first


@pytest.fixture(scope="module")
def shared(
    tmp_path_factory: pytest.TempPathFactory,
) -> Iterator[tuple[GitRepo, str, Markers, Listener]]:
    """One hostile repository for the tests that only read it (building it costs a second)."""
    root = tmp_path_factory.mktemp("hostile-shared")
    markers = Markers(root / "markers")
    server = Listener()
    repo, first = build_hostile(root, markers, server)
    assert markers.fired() == []  # building it ran nothing: the test's own git is pinned too
    yield repo, first, markers, server
    server.close()


def drop_loose_blob(repo: GitRepo, treeish_path: str) -> None:
    """Delete one loose blob, as if a partial clone had never fetched it."""
    blob = repo.git("rev-parse", f"HEAD~1:{treeish_path}").stdout.strip()
    target = repo.path / ".git" / "objects" / blob[:2] / blob[2:]
    target.chmod(0o666)
    target.unlink()


# -- the positive control ---------------------------------------------------------------------


def unprotected(repo: GitRepo, *args: str) -> subprocess.CompletedProcess[bytes]:
    """Git with the repository's configuration as it is: only the user and system config are
    off. This is what the tool must never be."""
    environment = git_environment(repo.home)
    environment.pop("GIT_PAGER", None)
    environment.pop("PAGER", None)
    return subprocess.run(
        [git_binary(), *args],
        cwd=repo.path,
        env=environment,
        capture_output=True,
        check=False,
        timeout=60,
    )


def test_the_hostile_repository_really_does_fire_markers_when_git_is_not_protected(
    tmp_path: Path,
) -> None:
    """If this fails the harness proves nothing: the vectors below must be live."""
    markers = Markers(tmp_path / "control-markers")
    server = Listener()
    try:
        repo, _ = build_hostile(tmp_path, markers, server)
        unprotected(repo, "status")  # fsmonitor (the included file wins), filters
        unprotected(repo, "diff", "HEAD~1", "HEAD", "--", "app.env")  # textconv, external diff
        unprotected(repo, "hook", "run", "--ignore-missing", "pre-commit")  # the hooks directory
    finally:
        server.close()
    fired = set(markers.fired())
    assert fired & {"fsmonitor", "include-fsmonitor"}, sorted(fired)
    assert fired & {"textconv", "external-diff", "diff-driver", "filter-process"}, sorted(fired)
    assert any(label.startswith("hook-") for label in fired), sorted(fired)


# -- the scans ------------------------------------------------------------------------------------


def test_scan_git_runs_nothing_and_still_finds_the_secret(
    shared: tuple[GitRepo, str, Markers, Listener],
) -> None:
    repo, first, markers, listener = shared
    outcome = run_scan_git(GitScanRequest(path=str(repo.path)), FakeClock())
    assert markers.fired() == []
    assert listener.connections == 0
    assert outcome.exit_code == ExitCode.FINDINGS
    assert [f.location.commit for f in outcome.report.findings] == [first]
    assert outcome.report.complete
    # nothing about the hostile configuration, and no full secret, reaches the output
    for text in (outcome.text, *outcome.notices):
        assert leak_check(text, SECRET) is None
        for fragment in (
            "127.0.0.1",
            "uploadpack",
            "fsmonitor",
            "textconv",
            "marker.py",
            "SENTINEL",
        ):
            assert fragment not in text


def test_a_missing_blob_does_not_trigger_a_lazy_fetch_over_any_transport(
    shared: tuple[GitRepo, str, Markers, Listener], tmp_path: Path
) -> None:
    source, _, markers, listener = shared
    copy = tmp_path / "copy"
    shutil.copytree(source.path, copy)
    repo = GitRepo(copy, source.home)
    drop_loose_blob(repo, "notes.txt")
    outcome = run_scan_git(GitScanRequest(path=str(copy)), FakeClock())
    assert markers.fired() == []
    assert listener.connections == 0
    assert outcome.exit_code == ExitCode.INCOMPLETE
    assert IssueKind.MISSING_OBJECT in {issue.kind for issue in outcome.report.issues}
    assert [f.rule_id for f in outcome.report.findings] == ["npm-token"]  # the rest still scanned


def test_scan_gitignore_runs_nothing(shared: tuple[GitRepo, str, Markers, Listener]) -> None:
    repo, _, markers, listener = shared
    outcome = run_scan(ScanRequest(path=str(repo.path), gitignore=True), FakeClock())
    assert markers.fired() == []
    assert listener.connections == 0
    assert outcome.exit_code in (ExitCode.OK, ExitCode.FINDINGS)


def test_the_callers_environment_cannot_make_git_run_anything(
    shared: tuple[GitRepo, str, Markers, Listener], monkeypatch: pytest.MonkeyPatch
) -> None:
    repo, first, markers, _ = shared
    command = markers.command
    for name, value in {
        "GIT_EXTERNAL_DIFF": command("env-external-diff"),
        "GIT_SSH": command("env-ssh"),
        "GIT_SSH_COMMAND": command("env-ssh-command"),
        "GIT_ASKPASS": command("env-askpass"),
        "SSH_ASKPASS": command("env-ssh-askpass"),
        "GIT_PAGER": command("env-pager"),
        "PAGER": command("env-pager2"),
        "GIT_EDITOR": command("env-editor"),
        "GIT_PROXY_COMMAND": command("env-proxy"),
        "GIT_CONFIG_COUNT": "1",
        "GIT_CONFIG_KEY_0": "core.fsmonitor",
        "GIT_CONFIG_VALUE_0": command("env-config"),
        "GIT_CONFIG_PARAMETERS": "'core.fsmonitor=" + command("env-parameters") + "'",
        "GIT_EXEC_PATH": str(markers.directory),
        "GIT_DIR": str(repo.path / "does-not-exist"),
        "GIT_WORK_TREE": str(markers.directory),
        "GIT_ALTERNATE_OBJECT_DIRECTORIES": str(markers.directory),
        "GIT_OBJECT_DIRECTORY": str(markers.directory),
        "GIT_INDEX_FILE": str(markers.directory / "index"),
        "GIT_NAMESPACE": "hostile",
        "GIT_REPLACE_REF_BASE": "refs/hostile/",
        "GIT_TRACE": str(markers.directory / "trace.log"),
        "GIT_TRACE_PACKET": str(markers.directory / "packet.log"),
        "XDG_CONFIG_HOME": str(markers.directory),
    }.items():
        monkeypatch.setenv(name, value)
    outcome = run_scan_git(GitScanRequest(path=str(repo.path)), FakeClock())
    assert markers.fired() == []
    assert sorted(os.listdir(markers.directory)) == ["marker.py"]  # no trace, packet or index file
    assert [f.location.commit for f in outcome.report.findings] == [first]


def test_a_planted_git_program_is_never_chosen(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    markers = Markers(tmp_path / "markers")
    repo = tmp_path / "repo"
    name = "git.exe" if os.name == "nt" else "git"
    for planted in (repo / name, repo / "bin" / name, tmp_path / "cwd" / name):
        planted.parent.mkdir(parents=True, exist_ok=True)
        planted.write_bytes(markers.shell_script("planted-git"))
        make_executable(planted)
    monkeypatch.chdir(tmp_path / "cwd")
    real_directory = str(Path(git_binary()).parent)
    search = os.pathsep.join(["", ".", "bin", str(repo / "bin"), str(repo), real_directory])
    runner = open_runner(
        git=None,
        root=str(repo),
        limits=DEFAULT_LIMITS,
        clock=FakeClock(),
        environment={"PATH": search, "SYSTEMROOT": os.environ.get("SYSTEMROOT", "")},
    )
    assert Path(runner.binary).parent == Path(real_directory)
    assert markers.fired() == []
