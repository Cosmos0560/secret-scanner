"""The hook launcher (`scripts/hooks/run_guard.sh`): the guard must not turn into "allow
everything" when the project venv is missing, and a missing interpreter must block (exit 2), not
fail with a code Claude Code treats as a non-blocking error."""

from __future__ import annotations

import json
import shutil
import subprocess
from pathlib import Path

import pytest

from tests.helpers import PROJECT_ROOT

pytestmark = pytest.mark.requires_sh

HOOK_DIR = PROJECT_ROOT / "scripts" / "hooks"
LAUNCHER = HOOK_DIR / "run_guard.sh"
CANDIDATES = '"py -3" python3 python'  # the line that names the interpreters the launcher tries
PUSH = json.dumps({"tool_name": "Bash", "tool_input": {"command": "git push"}})
STATUS = json.dumps({"tool_name": "Bash", "tool_input": {"command": "git status"}})


def _sh() -> str:
    found = shutil.which("sh")
    assert found is not None  # requires_sh guarantees it
    return found


def _run(script: Path, payload: str) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        [_sh(), script.as_posix()],
        input=payload,
        capture_output=True,
        text=True,
        timeout=60,
        check=False,
    )


def _copy_launcher(tmp_path: Path, *, candidates: str | None = None) -> Path:
    """A copy of the launcher next to a copy of the hook, in a tree with no .venv."""
    hooks = tmp_path / "scripts" / "hooks"
    hooks.mkdir(parents=True)
    shutil.copy(HOOK_DIR / "guard_gate.py", hooks / "guard_gate.py")
    text = LAUNCHER.read_text(encoding="utf-8")
    if candidates is not None:
        assert CANDIDATES in text
        text = text.replace(CANDIDATES, candidates)
    script = hooks / "run_guard.sh"
    script.write_bytes(text.replace("\r\n", "\n").encode("utf-8"))
    return script


def test_launcher_blocks_and_allows_like_the_hook_itself() -> None:
    blocked = _run(LAUNCHER, PUSH)
    assert blocked.returncode == 2
    assert "BLOCKED" in blocked.stderr
    allowed = _run(LAUNCHER, STATUS)
    assert (allowed.returncode, allowed.stderr) == (0, "")


def test_hook_still_runs_when_the_project_venv_does_not_exist(tmp_path: Path) -> None:
    script = _copy_launcher(tmp_path)
    assert not (tmp_path / ".venv").exists()
    blocked = _run(script, PUSH)
    assert blocked.returncode == 2
    assert "`git push`" in blocked.stderr
    assert _run(script, STATUS).returncode == 0


def test_launcher_works_from_its_own_directory(tmp_path: Path) -> None:
    script = _copy_launcher(tmp_path)
    result = subprocess.run(
        [_sh(), "run_guard.sh"],
        input=PUSH,
        capture_output=True,
        text=True,
        timeout=60,
        cwd=script.parent,
        check=False,
    )
    assert result.returncode == 2
    assert "`git push`" in result.stderr


def test_no_interpreter_at_all_blocks_with_a_clear_message(tmp_path: Path) -> None:
    script = _copy_launcher(tmp_path, candidates="no-such-python-a no-such-python-b")
    result = _run(script, STATUS)  # an innocent command: the missing interpreter is the reason
    assert result.returncode == 2
    assert "BLOCKED" in result.stderr
    assert "No usable Python 3.10+" in result.stderr
    assert "CLAUDE.md section 3" in result.stderr


def test_project_venv_is_the_last_resort(tmp_path: Path) -> None:
    script = _copy_launcher(tmp_path, candidates="no-such-python-a no-such-python-b")
    venv_python = tmp_path / ".venv" / "bin" / "python"
    venv_python.parent.mkdir(parents=True)
    # A stand-in interpreter: succeeds for the version probe (-c), answers for the hook run.
    venv_python.write_bytes(
        b'#!/bin/sh\ncase "$1" in -c) exit 0 ;; esac\necho venv-python-ran >&2\nexit 7\n'
    )
    venv_python.chmod(0o755)
    result = _run(script, STATUS)
    assert result.returncode == 7
    assert "venv-python-ran" in result.stderr


def test_unusable_interpreter_is_skipped_not_run(tmp_path: Path) -> None:
    script = _copy_launcher(tmp_path, candidates="no-such-python-a no-such-python-b")
    venv_python = tmp_path / ".venv" / "bin" / "python"
    venv_python.parent.mkdir(parents=True)
    # Fails the version probe, like a Python that is too old or a Microsoft Store stub.
    venv_python.write_bytes(b"#!/bin/sh\nexit 9\n")
    venv_python.chmod(0o755)
    result = _run(script, STATUS)
    assert result.returncode == 2
    assert "No usable Python 3.10+" in result.stderr


def test_launcher_sources_stay_posix_sh_with_a_blocking_fallback() -> None:
    text = LAUNCHER.read_text(encoding="utf-8")
    assert text.startswith("#!/bin/sh\n")
    assert "\r" not in text
    assert "exit 2" in text
    assert ".venv" in text
    for candidate in ("py -3", "python3", "python"):
        assert candidate in text


def test_settings_json_runs_the_hook_through_the_launcher() -> None:
    settings = json.loads((PROJECT_ROOT / ".claude" / "settings.json").read_text(encoding="utf-8"))
    (entry,) = settings["hooks"]["PreToolUse"]
    (hook,) = entry["hooks"]
    assert hook["command"] == 'sh "$CLAUDE_PROJECT_DIR/scripts/hooks/run_guard.sh"'
    assert LAUNCHER.is_file()
