"""The command line entry point: `--version`, usage errors, and the top-level error handler."""

from __future__ import annotations

import io
import runpy
import sys

import pytest

from secret_scanner import __version__
from secret_scanner.cli import main as cli_main
from secret_scanner.core.errors import ExitCode, GitError, UsageError


def test_version_prints_the_package_version(capsys: pytest.CaptureFixture[str]) -> None:
    assert cli_main.main(["--version"]) == 0
    assert capsys.readouterr().out == f"secret-scanner {__version__}\n"


def test_version_is_a_semantic_version() -> None:
    parts = __version__.split(".")
    assert len(parts) == 3
    assert all(part.isdigit() for part in parts)


def test_help_exits_zero(capsys: pytest.CaptureFixture[str]) -> None:
    assert cli_main.main(["--help"]) == 0
    assert "secret-scanner" in capsys.readouterr().out


def test_no_arguments_is_a_usage_error(capsys: pytest.CaptureFixture[str]) -> None:
    assert cli_main.main([]) == ExitCode.USAGE
    assert "usage:" in capsys.readouterr().err


def test_unknown_option_is_a_usage_error(capsys: pytest.CaptureFixture[str]) -> None:
    assert cli_main.main(["--definitely-not-an-option"]) == ExitCode.USAGE
    assert "unrecognized arguments" in capsys.readouterr().err


def test_abbreviations_are_not_accepted(capsys: pytest.CaptureFixture[str]) -> None:
    assert cli_main.main(["--vers"]) == ExitCode.USAGE
    capsys.readouterr()


def test_known_errors_map_to_their_exit_code_and_are_sanitised(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    def refuse(*_: object) -> ExitCode:
        raise GitError("git said no " + chr(0x1B) + "[31m")

    monkeypatch.setattr(cli_main, "_dispatch", refuse)
    assert cli_main.main([]) == ExitCode.GIT
    err = capsys.readouterr().err
    assert "git said no" in err
    assert chr(0x1B) not in err

    def usage(*_: object) -> ExitCode:
        raise UsageError("bad option")

    monkeypatch.setattr(cli_main, "_dispatch", usage)
    assert cli_main.main([]) == ExitCode.USAGE


def test_unexpected_exception_exits_two_and_prints_only_the_type(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    def explode(*_: object) -> ExitCode:
        raise RuntimeError("contains file content that must not be printed")

    monkeypatch.setattr(cli_main, "_dispatch", explode)
    assert cli_main.main([]) == ExitCode.USAGE  # never 1, which means "findings"
    err = capsys.readouterr().err
    assert "internal error: RuntimeError" in err
    assert "file content" not in err


def test_streams_are_switched_to_backslashreplace(monkeypatch: pytest.MonkeyPatch) -> None:
    raw = io.BytesIO()
    stream = io.TextIOWrapper(raw, encoding="cp1252", errors="strict", newline="\n")
    monkeypatch.setattr(sys, "stdout", stream)
    cli_main._harden_streams()
    stream.write(chr(0x2713))
    stream.flush()
    assert raw.getvalue() == (chr(92) + "u2713").encode("ascii")


def test_streams_without_reconfigure_are_left_alone(monkeypatch: pytest.MonkeyPatch) -> None:
    class _Plain:
        def write(self, text: str) -> int:
            return len(text)

    monkeypatch.setattr(sys, "stdout", _Plain())
    monkeypatch.setattr(sys, "stderr", _Plain())
    cli_main._harden_streams()  # must not raise


def test_python_dash_m_entry_point(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    monkeypatch.setattr(sys, "argv", ["secret-scanner", "--version"])
    with pytest.raises(SystemExit) as exit_info:
        runpy.run_module("secret_scanner", run_name="__main__")
    assert exit_info.value.code == 0
    assert capsys.readouterr().out.startswith("secret-scanner ")


def test_non_integer_system_exit_code_is_a_usage_error(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    class _Parser:
        def parse_args(self, argv: object) -> None:
            raise SystemExit("message")

    monkeypatch.setattr(cli_main, "build_parser", lambda: _Parser())
    assert cli_main.main([]) == ExitCode.USAGE
