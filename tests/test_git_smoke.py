"""One real repository through the real command line, in the default gate: the history scan end to
end (git found on PATH, discovery, history walk, blob reads, the table). The wider matrix of
repository shapes is in `test_git_scan.py` (slow)."""

from __future__ import annotations

from pathlib import Path

import pytest

from secret_scanner.cli import main as cli_main
from secret_scanner.core.errors import ExitCode
from secret_scanner.core.fakes import build_fake
from secret_scanner.services.loader import load_builtin_rules
from tests.conftest import leak_check
from tests.gitrepo import GitRepo

pytestmark = pytest.mark.requires_git

LF = chr(10)


def test_a_secret_added_and_removed_is_found_through_the_command_line(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    rule = next(r for r in load_builtin_rules().rules if r.id == "npm-token")
    secret = build_fake(rule, "smoke")
    home = tmp_path / "githome"
    home.mkdir()
    repo = GitRepo.create(tmp_path / "repo", home)
    repo.commit_files("start", {"README.md": "hello" + LF})
    added = repo.commit_files("add settings", {"config/app.env": f"TOKEN={secret}" + LF})
    repo.commit_files("remove the token", {"config/app.env": "TOKEN=from-vault" + LF})

    code = cli_main.main(["scan-git", str(repo.path)])
    captured = capsys.readouterr()

    assert code == ExitCode.FINDINGS
    assert captured.err == ""
    assert f"config/app.env:1:7@{added[:12]}" in captured.out
    assert "history complete: yes" in captured.out
    assert "3 commits" in captured.out
    assert leak_check(captured.out, secret) is None
