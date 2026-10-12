"""The PreToolUse hook: every block has planted bad commands and allowed counterexamples, in Bash
and PowerShell syntax; quoted text is data; malformed input is a non-blocking error."""

from __future__ import annotations

import ast
import io
import json
import subprocess
import sys
from pathlib import Path

import pytest

from scripts.hooks import guard_gate
from tests.helpers import PROJECT_ROOT

HOOK = PROJECT_ROOT / "scripts" / "hooks" / "guard_gate.py"
TRAILER = "Co-Authored-By" + ": Someone"

# -- gate.py must run alone -----------------------------------------------------------------

GATE_BLOCKED = [
    # pipes and filters, Bash syntax
    "python scripts/gate.py | tail -5",
    "python scripts/gate.py --full | tee gate.txt",
    "python scripts/gate.py --full | grep -i fail",
    "python scripts/gate.py | head -n 20",
    "python scripts/gate.py | findstr /i error",
    "echo go | python scripts/gate.py",
    "uv run python scripts/gate.py | head",
    "python -m scripts.gate | head",
    "cd scripts && python gate.py | head",
    "./scripts/gate.py | tail",
    "FOO=1 python scripts/gate.py | tail",
    # pipes and filters, PowerShell syntax
    "python scripts/gate.py | Select-Object -Last 5",
    "python scripts/gate.py | Out-Null",
    "python scripts/gate.py | Out-File x.txt",
    "python scripts/gate.py | Tee-Object -FilePath x.txt",
    r".venv\Scripts\python.exe scripts\gate.py --full | Select-String FAIL",
    r"& .venv\Scripts\python.exe scripts\gate.py | Out-Null",
    "python scripts/gate.py; Select-String FAIL gate.log",
    # redirects
    "python scripts/gate.py > out.txt",
    "python scripts/gate.py >> out.txt",
    "python scripts/gate.py 2>&1",
    "python scripts/gate.py 2> err.txt",
    "python scripts/gate.py *> all.txt",
    "python scripts/gate.py &> all.txt",
    # status masking
    "python scripts/gate.py || true",
    "python scripts/gate.py || echo failed",
    "python scripts/gate.py; true",
    "python scripts/gate.py; exit 0",
    "python scripts/gate.py; exit",
    "python scripts/gate.py\ntrue",
    "python scripts/gate.py & true",
    # nested shells
    'bash -c "python scripts/gate.py | tail"',
    "sh -c 'python scripts/gate.py > x'",
    'powershell -NoProfile -Command "python scripts/gate.py | Out-Null"',
    'pwsh -c "python scripts/gate.py | Out-Null"',
    'cmd /c "python scripts/gate.py > x.txt"',
    'wsl -d Ubuntu -e sh -c "python scripts/gate.py --full | tail"',
    "wsl python3 scripts/gate.py | tail",
    'echo "$(python scripts/gate.py | tail)"',
    "Invoke-Expression 'python scripts/gate.py | Out-Null'",
]

GATE_ALLOWED = [
    "python scripts/gate.py",
    "python scripts/gate.py --full",
    "python scripts/gate.py --full --log gate.log",
    r".venv\Scripts\python.exe scripts\gate.py",
    "python scripts/gate.py && git commit -m 'feat: x'",
    'python scripts/gate.py; if ($LASTEXITCODE -eq 0) { git commit -m "feat: x" }',
    "python scripts/gate.py; exit $LASTEXITCODE",
    'wsl -d Ubuntu -e sh -c "cd ~/secret-scanner-linux-check && git fetch -q '
    "/mnt/c/Studies/Projects/secret-scanner main && git reset -q --hard FETCH_HEAD && "
    '~/.venvs/secret-scanner-linux/bin/python scripts/gate.py --full"',
    # looking at the gate script is not running it
    "git diff scripts/gate.py | head -20",
    "cat scripts/gate.py | head -50",
    "grep -n python scripts/gate.py | head",
    "git add -- scripts/gate.py tests/test_gate.py",
    "python -m pytest tests/test_gate.py -q | tail -5",
    "ruff check scripts/gate.py | head",
    # other commands may be piped and filtered
    "python -m pytest -q | tail -5",
    "python scripts/check_architecture.py | head",
    "git log --oneline | head",
    # quoted text is data
    'echo "python scripts/gate.py | tail"',
    "Write-Output 'python scripts/gate.py > x'",
    "git commit -m 'docs: gate.py | tail is blocked'",
]

# -- the machine rules (D20 b) --------------------------------------------------------------

GIT_BLOCKED = [
    "git push",
    "git push origin main",
    "git push --force",
    "git -C . push",
    "git --no-pager push",
    "git -c core.pager=cat push",
    "GIT_TERMINAL_PROMPT=0 git push",
    "env git push",
    "git.exe push",
    "GIT PUSH",
    "git status; git push",
    "git status && git push origin main",
    "echo ok | git push",
    "& git push",
    r'& "C:\Program Files\Git\bin\git.exe" push',
    'bash -c "git push"',
    "sh -c 'git push origin main'",
    'powershell -Command "git push"',
    "wsl git push",
    "wsl -d Ubuntu -e git push",
    "if ($?) { git push }",
    "echo $(git push)",
    'echo "$(git push)"',
    "echo `git push`",
    "git tag",
    "git tag v1.0.0",
    "git tag -a v1 -m release",
    "git -C repo tag -d v1",
    "git add -A",
    "git add --all",
    "git add .",
    "git add -- .",
    "git add ./",
    "git add *",
    "git add -Av",
    "git add -u .",
    "git add src/a.py .",
    "git config user.name someone",
    "git config --global user.email someone",
    "git config --local --unset user.name",
    "git config user.signingkey abc",
    "git config --get user.name",
    f'git commit -m "feat: x" -m "{TRAILER}"',
    f'git commit -m "feat: x\n\n{TRAILER}"',
    f"git commit -m \"$(cat <<'EOF'\nfeat: x\n\n{TRAILER}\nEOF\n)\"",
    f"git commit -F - <<'EOF'\nfeat: x\n\n{TRAILER}\nEOF",
    f"git commit --amend -m 'fix: y {TRAILER}'",
    f"git commit-tree HEAD -m 'z {TRAILER.upper()}'",
    f"git merge other -m 'merge {TRAILER.lower()}'",
]

GIT_ALLOWED = [
    "git status",
    "git status --short",
    "git log --oneline",
    "git diff --stat",
    "git init -b main",
    "git add -- CLAUDE.md PLAN.md",
    "git add src/a.py tests/b.py",
    "git add -- .gitignore .gitattributes",
    "git add -n -- src",
    "git commit -m 'docs: add approved plan and working rules'",
    "git commit -m \"feat: the hook blocks 'git push' and 'git tag'\"",
    "git commit -m 'docs: mention Co-Authored-By trailers are refused'",
    "git config --get core.autocrlf",
    "git config core.autocrlf false",
    "git stash push -m wip",
    "git remote -v",
    "git log --grep 'git push'",
    "git diff -- tests/test_push.py",
    'echo "git push"',
    "echo 'git tag v1'",
    'Write-Output "git add -A"',
    "Write-Output 'git config user.name x'",
    "echo git-push-guard",
    "python -c \"print('git push')\"",
    "python - <<'PY'\nimport subprocess\nsubprocess.run(['git', 'push'])\nPY",
    "@'\ngit push\n'@ | python -",
    "cat <<'EOF' > notes.txt\ngit tag v1\ngit add -A\nEOF",
    "git commit -m \"$(cat <<'EOF'\nfix: x\n\ngit push is never run here\nEOF\n)\"",
]


@pytest.mark.parametrize("command", GATE_BLOCKED)
def test_gate_commands_that_are_filtered_or_masked_are_blocked(command: str) -> None:
    reasons = guard_gate.evaluate(command)
    assert reasons, command
    assert all("gate.py must run alone" in reason for reason in reasons)


@pytest.mark.parametrize("command", GATE_ALLOWED)
def test_gate_commands_that_run_alone_or_are_not_the_gate_are_allowed(command: str) -> None:
    assert guard_gate.evaluate(command) == []


@pytest.mark.parametrize("command", GIT_BLOCKED)
def test_machine_rule_violations_are_blocked(command: str) -> None:
    assert guard_gate.evaluate(command), command


@pytest.mark.parametrize("command", GIT_ALLOWED)
def test_ordinary_git_and_quoted_text_are_allowed(command: str) -> None:
    assert guard_gate.evaluate(command) == []


def test_every_block_family_is_named_in_a_reason() -> None:
    expected = {
        "git push": "`git push`",
        "git tag v1": "`git tag`",
        "git add -A": "`git add -A`",
        "git config user.name x": "`git config user.*`",
        f"git commit -m '{TRAILER}'": "Co-Authored-By trailer",
        "python scripts/gate.py | tail": "a pipe",
        "python scripts/gate.py > x": "a redirect",
        "python scripts/gate.py || true": "`||`",
        "python scripts/gate.py; true": "`; true`",
        "python scripts/gate.py; exit 0": "`; exit 0`",
        "python scripts/gate.py; tail x": "the filter `tail`",
    }
    for command, fragment in expected.items():
        assert any(fragment in reason for reason in guard_gate.evaluate(command)), command


def test_commit_message_file_with_a_trailer_is_blocked(tmp_path: Path) -> None:
    message = tmp_path / "msg.txt"
    message.write_text(f"feat: x\n\n{TRAILER}\n", encoding="utf-8")
    clean = tmp_path / "clean.txt"
    clean.write_text("feat: x\n", encoding="utf-8")
    assert guard_gate.evaluate("git commit -F msg.txt", tmp_path)
    assert guard_gate.evaluate("git commit --file=msg.txt", tmp_path)
    assert guard_gate.evaluate(f"git commit -F {message}")
    assert guard_gate.evaluate("git commit -F clean.txt", tmp_path) == []
    assert guard_gate.evaluate("git commit -F missing.txt", tmp_path) == []
    assert guard_gate.evaluate("git commit -F - ", tmp_path) == []


def test_nesting_is_bounded() -> None:
    command = "git push"
    for _ in range(guard_gate.MAX_NESTING + 3):
        command = 'bash -c "' + command.replace('"', '\\"') + '"'
    # Too deep to analyse: not blocked, and above all no crash or runaway recursion.
    assert guard_gate.evaluate(command) == []
    shallow = 'bash -c "bash -c \\"git push\\""'
    assert guard_gate.evaluate(shallow)


@pytest.mark.parametrize(
    "command",
    [
        "",
        "   ",
        "'unterminated",
        '"unterminated $(git status',
        "echo `unterminated",
        "@'\nunterminated here-string",
        '@"\nunterminated $(x here-string',
        "cat <<EOF\nnever closed",
        "a \\",
        "$(",
        "))((",
        "|| ; &&",
    ],
)
def test_lexer_is_total_on_odd_input(command: str) -> None:
    assert guard_gate.evaluate(command) == []


def test_heredoc_with_dash_strips_leading_tabs() -> None:
    command = "cat <<-END\n\tgit push\n\tEND\ngit status"
    assert guard_gate.evaluate(command) == []
    assert guard_gate.evaluate("cat <<-END\n\tx\n\tEND\ngit push")


def test_line_continuation_joins_words() -> None:
    assert guard_gate.evaluate("git \\\n push")
    assert guard_gate.evaluate("git `\n push")


def test_comments_are_not_commands() -> None:
    assert guard_gate.evaluate("git status # git push") == []
    assert guard_gate.evaluate("git push # comment")


def test_powershell_here_string_is_data_but_expands_substitutions() -> None:
    assert guard_gate.evaluate('@"\n$(git push)\n"@ | python -')
    assert guard_gate.evaluate("@'\n$(git push)\n'@ | python -") == []


# -- hook protocol --------------------------------------------------------------------------


def _run(payload: object) -> tuple[int, str]:
    stdin = io.StringIO(payload if isinstance(payload, str) else json.dumps(payload))
    stderr = io.StringIO()
    code = guard_gate.main(stdin=stdin, stderr=stderr)
    return code, stderr.getvalue()


@pytest.mark.parametrize("tool", ["Bash", "PowerShell"])
def test_blocked_command_exits_two_with_a_reason(tool: str) -> None:
    code, message = _run({"tool_name": tool, "tool_input": {"command": "git push"}})
    assert code == guard_gate.EXIT_BLOCK
    assert "BLOCKED" in message
    assert "git push" in message


@pytest.mark.parametrize("tool", ["Bash", "PowerShell"])
def test_allowed_command_exits_zero_silently(tool: str) -> None:
    code, message = _run({"tool_name": tool, "tool_input": {"command": "git status"}})
    assert (code, message) == (guard_gate.EXIT_ALLOW, "")


def test_other_tools_are_ignored_even_with_a_command_field() -> None:
    payload = {"tool_name": "Read", "tool_input": {"command": "git push"}}
    assert _run(payload) == (guard_gate.EXIT_ALLOW, "")


def test_payload_cwd_is_used_to_find_message_files(tmp_path: Path) -> None:
    (tmp_path / "m.txt").write_text(TRAILER + "\n", encoding="utf-8")
    payload = {
        "tool_name": "Bash",
        "tool_input": {"command": "git commit -F m.txt"},
        "cwd": str(tmp_path),
    }
    assert _run(payload)[0] == guard_gate.EXIT_BLOCK


@pytest.mark.parametrize(
    "payload",
    [
        "not json",
        "",
        "[]",
        '"text"',
        "{}",
        '{"tool_name": 3}',
        '{"tool_name": "Bash"}',
        '{"tool_name": "Bash", "tool_input": []}',
        '{"tool_name": "Bash", "tool_input": {}}',
        '{"tool_name": "PowerShell", "tool_input": {"command": 7}}',
    ],
)
def test_malformed_input_is_a_non_blocking_error(payload: str) -> None:
    code, message = _run(payload)
    assert code == guard_gate.EXIT_ERROR
    assert message.startswith("guard_gate:")


def test_hook_reads_bytes_from_the_real_stdin(monkeypatch: pytest.MonkeyPatch) -> None:
    raw = json.dumps({"tool_name": "Bash", "tool_input": {"command": "git tag x"}}).encode()

    class _Stdin:
        buffer = io.BytesIO(raw)

    monkeypatch.setattr(sys, "stdin", _Stdin())
    stderr = io.StringIO()
    assert guard_gate.main(stderr=stderr) == guard_gate.EXIT_BLOCK
    assert "git tag" in stderr.getvalue()


def test_invalid_utf8_on_stdin_is_a_non_blocking_error(monkeypatch: pytest.MonkeyPatch) -> None:
    class _Stdin:
        buffer = io.BytesIO(b"\xff\xfe{")

    monkeypatch.setattr(sys, "stdin", _Stdin())
    stderr = io.StringIO()
    assert guard_gate.main(stderr=stderr) == guard_gate.EXIT_ERROR


def _spawn(payload: bytes) -> subprocess.CompletedProcess[bytes]:
    return subprocess.run(
        [sys.executable, str(HOOK)],
        input=payload,
        capture_output=True,
        timeout=60,
        cwd=PROJECT_ROOT,
        check=False,
    )


def test_script_exit_codes_through_a_real_process() -> None:
    blocked = _spawn(b'{"tool_name":"Bash","tool_input":{"command":"git add -A"}}')
    assert blocked.returncode == guard_gate.EXIT_BLOCK
    assert b"BLOCKED" in blocked.stderr
    allowed = _spawn(b'{"tool_name":"Bash","tool_input":{"command":"git status"}}')
    assert (allowed.returncode, allowed.stderr) == (guard_gate.EXIT_ALLOW, b"")
    assert _spawn(b"\xff\xfe").returncode == guard_gate.EXIT_ERROR


def test_hook_uses_only_the_standard_library() -> None:
    tree = ast.parse(HOOK.read_text(encoding="utf-8"))
    imported: set[str] = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            imported.update(alias.name.split(".")[0] for alias in node.names)
        elif isinstance(node, ast.ImportFrom) and node.module and node.level == 0:
            imported.add(node.module.split(".")[0])
    assert imported <= set(sys.stdlib_module_names) | {"__future__"}


def test_settings_json_registers_the_hook_for_bash_and_powershell() -> None:
    settings = json.loads((PROJECT_ROOT / ".claude" / "settings.json").read_text(encoding="utf-8"))
    entries = settings["hooks"]["PreToolUse"]
    assert len(entries) == 1
    assert entries[0]["matcher"] == "Bash|PowerShell"
    commands = [hook["command"] for hook in entries[0]["hooks"]]
    assert len(commands) == 1
    assert "scripts/hooks/guard_gate.py" in commands[0]
    assert ".venv" in commands[0]
    assert (PROJECT_ROOT / "scripts" / "hooks" / "guard_gate.py").is_file()
