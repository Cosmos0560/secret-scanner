"""Edge cases of the hook's lexer and command analysis: quoting forms, redirections, wrappers,
shell-in-shell nesting and its bound."""

from __future__ import annotations

import pytest

from scripts.hooks import guard_gate

BS = chr(92)
BACKTICK = chr(96)


def _wrap(command: str, times: int) -> str:
    """Wrap `command` in `sh -c '...'` the given number of times, quoting each level."""
    for _ in range(times):
        command = "sh -c '" + command.replace("'", "'" + BS + "''") + "'"
    return command


@pytest.mark.parametrize("depth", [1, 2, 3, 4])
def test_commands_inside_nested_shells_are_found_up_to_the_bound(depth: int) -> None:
    assert guard_gate.evaluate(_wrap("git push", depth))


@pytest.mark.parametrize("depth", [5, 6, 8])
def test_nesting_beyond_the_bound_is_not_analysed_and_does_not_recurse_forever(
    depth: int,
) -> None:
    assert guard_gate.evaluate(_wrap("git push", depth)) == []


def test_command_substitution_nesting_is_bounded_too() -> None:
    inner = "git push"
    for _ in range(3):
        inner = 'echo "$(' + inner + ')"'
    assert guard_gate.evaluate(inner)
    for _ in range(6):
        inner = 'echo "$(' + inner + ')"'
    assert guard_gate.evaluate(inner) == []


def test_backtick_substitution_inside_double_quotes_executes() -> None:
    assert guard_gate.evaluate('echo "now ' + BACKTICK + "git push" + BACKTICK + ' now"')
    assert guard_gate.evaluate('echo "no closing ' + BACKTICK + 'git push"') == []


def test_nested_parentheses_inside_a_substitution() -> None:
    assert guard_gate.evaluate('echo "$(echo $(git tag x))"')
    assert guard_gate.evaluate('echo "$(echo (( 1 + 2 )) )"') == []


def test_doubled_single_quote_is_a_literal_quote() -> None:
    assert guard_gate.evaluate("git commit -m 'it''s fine'") == []
    assert guard_gate.evaluate("echo 'it''s'; git push")


def test_crlf_line_continuation() -> None:
    assert guard_gate.evaluate("git " + BS + "\r\n push")


def test_here_document_forms() -> None:
    assert guard_gate.evaluate("cat << EOF\ngit push\nEOF\n") == []
    assert guard_gate.evaluate('cat <<-"EOF"\n\tgit push\n\tEOF\n') == []
    assert guard_gate.evaluate("cat <<EOF; git push\nbody\nEOF\n")
    assert guard_gate.evaluate("cat <<") == []
    assert guard_gate.evaluate("cat <<\ngit push\n")


def test_at_signs_that_do_not_start_a_here_string() -> None:
    assert guard_gate.evaluate("Write-Output @(1, 2); git status") == []
    assert guard_gate.evaluate("$h = @{a = 1}; git push")
    assert guard_gate.evaluate("echo @'inline'; git tag x")
    assert guard_gate.evaluate("git log @{u}") == []


def test_here_string_and_input_redirection_are_not_commands() -> None:
    assert guard_gate.evaluate('cat <<< "git push"') == []
    assert guard_gate.evaluate("git status < input.txt") == []
    assert guard_gate.evaluate("git push < input.txt")


def test_assignments_and_wrappers_without_a_program_are_ignored() -> None:
    assert guard_gate.evaluate("FOO=bar") == []
    assert guard_gate.evaluate("env") == []
    assert guard_gate.evaluate("env -i") == []
    assert guard_gate.evaluate("env -i FOO=1 git push")
    assert guard_gate.evaluate("sudo -E git tag v1")
    assert guard_gate.evaluate("python scripts/gate.py; FOO=1; true")


def test_git_without_a_subcommand() -> None:
    assert guard_gate.evaluate("git") == []
    assert guard_gate.evaluate("git --no-pager") == []
    assert guard_gate.evaluate("git -C") == []
    assert guard_gate.evaluate("git --version") == []


def test_shells_without_a_command_string() -> None:
    assert guard_gate.evaluate("bash script.sh") == []
    assert guard_gate.evaluate("bash -c") == []
    assert guard_gate.evaluate("cmd /d") == []
    assert guard_gate.evaluate("powershell -File script.ps1") == []
    assert guard_gate.evaluate("pwsh -NoProfile") == []
    assert guard_gate.evaluate("iex") == []
    assert guard_gate.evaluate("cmd /k git push")
    assert guard_gate.evaluate("bash -lc 'git push'")


def test_wsl_option_forms() -> None:
    assert guard_gate.evaluate("wsl --system git push")
    assert guard_gate.evaluate("wsl -u root git tag v1")
    assert guard_gate.evaluate("wsl --distribution Ubuntu --cd ~ -- git push")
    assert guard_gate.evaluate("wsl -d Ubuntu") == []
    assert guard_gate.evaluate("wsl") == []
    assert guard_gate.evaluate("wsl -e") == []


def test_python_launcher_and_wrapper_forms_of_the_gate() -> None:
    for prefix in ["py -3.13", "python3.13", "uv run --python 3.13 python", "env FOO=1 python"]:
        assert guard_gate.evaluate(prefix + " scripts/gate.py | tail"), prefix


def test_flags_that_only_look_like_the_gate() -> None:
    assert guard_gate.evaluate("python scripts/gate_helper.py | tail") == []
    assert guard_gate.evaluate("python scripts/investigate.py | tail") == []
    assert guard_gate.evaluate("python -m scripts.gate_tools | tail") == []


def test_gate_status_masking_variants() -> None:
    assert guard_gate.evaluate("python scripts/gate.py && true") == []
    assert guard_gate.evaluate("python scripts/gate.py; exit 3") == []
    assert guard_gate.evaluate("python scripts/gate.py; $true")
    assert guard_gate.evaluate("python scripts/gate.py; :")
