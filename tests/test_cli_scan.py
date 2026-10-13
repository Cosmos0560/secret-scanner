"""The `scan` command through `main(argv)`: options, streams, the exit-code table (PLAN.md D10)
and hostile names in every format (CLAUDE.md section 5, invariants 1 and 5)."""

from __future__ import annotations

import io
import json
import os
import sys
from collections.abc import Callable
from pathlib import Path
from typing import Any

import pytest

from secret_scanner.cli import main as cli_main
from secret_scanner.core.errors import ExitCode
from secret_scanner.core.fakes import build_fake
from secret_scanner.core.sanitize import sanitize
from secret_scanner.services.loader import dump_yaml, load_builtin_rules

RULES = {rule.id: rule for rule in load_builtin_rules().rules}

Cli = Callable[..., tuple[int, str, str]]


def fake(rule_id: str, seed: str = "cli") -> str:
    return build_fake(RULES[rule_id], seed)


@pytest.fixture
def root(tmp_path: Path) -> Path:
    directory = tmp_path / "tree"
    directory.mkdir()
    return directory


@pytest.fixture
def work(tmp_path: Path) -> Path:
    directory = tmp_path / "work"
    directory.mkdir()
    return directory


@pytest.fixture
def cli(capsys: pytest.CaptureFixture[str]) -> Cli:
    def invoke(*argv: str) -> tuple[int, str, str]:
        code = cli_main.main(list(argv))
        captured = capsys.readouterr()
        return code, captured.out, captured.err

    return invoke


def put(root: Path, relative: str, content: str | bytes) -> None:
    path = root / relative
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(content if isinstance(content, bytes) else content.encode("utf-8"))


def write_yaml(path: Path, document: dict[str, Any]) -> str:
    path.write_bytes(dump_yaml(document).encode("ascii"))
    return str(path)


# -- the command ------------------------------------------------------------------------------


def test_scan_prints_the_table_on_stdout_and_nothing_on_stderr(root: Path, cli: Cli) -> None:
    put(root, "src/app.py", f"TOKEN = '{fake('npm-token')}'\n")
    code, out, err = cli("scan", str(root))
    assert code == ExitCode.FINDINGS
    assert err == ""
    assert "npm-token" in out
    assert "src/app.py:1:10" in out
    assert "  complete:  yes" in out.splitlines()


def test_scan_json_is_one_valid_document(root: Path, cli: Cli) -> None:
    put(root, "a.txt", fake("aws-access-key-id"))
    code, out, err = cli("scan", str(root), "--format", "json", "--host-label", "ci-1")
    document = json.loads(out)
    assert (code, err) == (ExitCode.FINDINGS, "")
    assert document["schema"] == "secret-report/1"
    assert document["host"] == "ci-1"
    assert document["findings"][0]["rule_id"] == "aws-access-key-id"
    assert out.isascii()


def test_output_goes_to_the_file_and_a_notice_to_stderr(root: Path, work: Path, cli: Cli) -> None:
    put(root, "a.txt", fake("npm-token"))
    target = work / "r.json"
    code, out, err = cli("scan", str(root), "--format", "json", "--output", str(target))
    assert (code, out) == (ExitCode.FINDINGS, "")
    assert "report written to" in err
    assert json.loads(target.read_text("ascii"))["counts"]["findings"] == 1


def test_baseline_options_round_trip_through_the_command(root: Path, work: Path, cli: Cli) -> None:
    put(root, "a.txt", fake("npm-token"))
    baseline = str(work / "b.yaml")
    code, _, err = cli("scan", str(root), "--write-baseline", baseline)
    assert code == ExitCode.FINDINGS
    assert "baseline with 1 entries written" in err
    code, out, err = cli("scan", str(root), "--baseline", baseline)
    assert (code, err) == (ExitCode.OK, "")
    assert "1 suppressed (1 by fingerprint, 0 by path)" in out
    code, out, _ = cli("scan", str(root), "--baseline", baseline, "--show-suppressed")
    assert code == ExitCode.OK
    assert "[suppressed: fingerprint]" in out


def test_options_reach_the_application(root: Path, work: Path, cli: Cli) -> None:
    put(root, "node_modules/x.js", fake("npm-token"))
    assert cli("scan", str(root))[0] == ExitCode.OK
    assert cli("scan", str(root), "--no-default-excludes")[0] == ExitCode.FINDINGS
    put(root, "a.txt", fake("npm-token", "second"))
    assert cli("scan", str(root), "--fail-on", "critical")[0] == ExitCode.OK
    config = write_yaml(work / "c.yaml", {"version": 1, "fail_on": "critical"})
    assert cli("scan", str(root), "--config", config)[0] == ExitCode.OK
    assert cli("scan", str(root), "--config", config, "--min-confidence", "high")[0] == 0


# -- the exit-code table (D10) ----------------------------------------------------------------


def _clean(root: Path, work: Path) -> list[str]:
    put(root, "readme.md", "nothing\n")
    return ["scan", str(root)]


def _finding(root: Path, work: Path) -> list[str]:
    put(root, "a.txt", fake("npm-token"))
    return ["scan", str(root)]


def _below_fail_on(root: Path, work: Path) -> list[str]:
    put(root, "a.txt", fake("npm-token"))
    return ["scan", str(root), "--fail-on", "critical"]


def _incomplete(root: Path, work: Path) -> list[str]:
    put(root, "big.txt", "x" * 3_000)
    config = write_yaml(work / "c.yaml", {"version": 1, "limits": {"max_file_bytes": 1_000}})
    return ["scan", str(root), "--config", config]


def _incomplete_with_findings(root: Path, work: Path) -> list[str]:
    put(root, "a.txt", fake("npm-token"))
    return _incomplete(root, work)


def _missing_root(root: Path, work: Path) -> list[str]:
    return ["scan", str(root / "nope")]


def _bad_config(root: Path, work: Path) -> list[str]:
    (work / "c.yaml").write_bytes(b"version: 3\n")
    return ["scan", str(root), "--config", str(work / "c.yaml")]


def _bad_baseline(root: Path, work: Path) -> list[str]:
    (work / "b.yaml").write_bytes(b"version: 1\nsuppress: 5\n")
    return ["scan", str(root), "--baseline", str(work / "b.yaml")]


def _output_exists(root: Path, work: Path) -> list[str]:
    (work / "out.txt").write_text("keep", encoding="utf-8")
    return ["scan", str(root), "--output", str(work / "out.txt")]


def _output_inside_tree(root: Path, work: Path) -> list[str]:
    return ["scan", str(root), "--output", str(root / "report.txt")]


def _unknown_option(root: Path, work: Path) -> list[str]:
    return ["scan", str(root), "--no-such-option"]


def _bad_choice(root: Path, work: Path) -> list[str]:
    return ["scan", str(root), "--format", "xml"]


def _no_path(root: Path, work: Path) -> list[str]:
    return ["scan"]


def _abbreviation(root: Path, work: Path) -> list[str]:
    return ["scan", str(root), "--fail"]


EXIT_TABLE: list[tuple[Callable[[Path, Path], list[str]], ExitCode]] = [
    (_clean, ExitCode.OK),
    (_finding, ExitCode.FINDINGS),
    (_below_fail_on, ExitCode.OK),
    (_incomplete, ExitCode.INCOMPLETE),
    (_incomplete_with_findings, ExitCode.INCOMPLETE),  # 4 beats 1
    (_missing_root, ExitCode.USAGE),
    (_bad_config, ExitCode.USAGE),
    (_bad_baseline, ExitCode.USAGE),
    (_output_exists, ExitCode.USAGE),
    (_output_inside_tree, ExitCode.USAGE),
    (_unknown_option, ExitCode.USAGE),
    (_bad_choice, ExitCode.USAGE),
    (_no_path, ExitCode.USAGE),
    (_abbreviation, ExitCode.USAGE),
]


@pytest.mark.parametrize(
    ("setup", "expected"), EXIT_TABLE, ids=[case[0].__name__.strip("_") for case in EXIT_TABLE]
)
def test_exit_codes(
    root: Path, work: Path, cli: Cli, setup: Callable[[Path, Path], list[str]], expected: ExitCode
) -> None:
    argv = setup(root, work)
    code, out, err = cli(*argv)
    assert code == expected
    if expected is ExitCode.USAGE:
        assert out == ""  # a refusal prints nothing on stdout
        assert err != ""
    if expected is ExitCode.INCOMPLETE:
        assert "RESULT: INCOMPLETE" in out
        assert "incomplete" in err
    assert not (work / "out.txt").exists() or (work / "out.txt").read_text("utf-8") == "keep"


def test_every_documented_exit_code_is_in_the_table_or_belongs_to_git() -> None:
    reached = {expected for _, expected in EXIT_TABLE}
    assert reached == set(ExitCode) - {ExitCode.GIT}  # 3 is `scan-git` (Phase 4)


# -- streams and hostile text -----------------------------------------------------------------

WIDE_NAME = chr(0x65E5) + chr(0x672C) + ".txt"  # not representable in cp1252


def test_a_cp1252_console_never_crashes_the_tool(
    root: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    put(root, WIDE_NAME, fake("npm-token"))
    raw_out, raw_err = io.BytesIO(), io.BytesIO()
    out = io.TextIOWrapper(raw_out, encoding="cp1252", errors="strict", newline="\n")
    err = io.TextIOWrapper(raw_err, encoding="cp1252", errors="strict", newline="\n")
    monkeypatch.setattr(sys, "stdout", out)
    monkeypatch.setattr(sys, "stderr", err)
    code = cli_main.main(["scan", str(root)])
    out.flush()
    err.flush()
    text = raw_out.getvalue().decode("cp1252")
    assert code == ExitCode.FINDINGS
    assert chr(92) + "u65e5" in text  # escaped by the stream, not lost and not a crash
    assert WIDE_NAME not in text


def test_argparse_messages_are_escaped(cli: Cli) -> None:
    code, out, err = cli("scan", ".", "--fail-on", "x" + chr(0x1B) + "[31mred")
    assert code == ExitCode.USAGE
    assert out == ""
    assert chr(0x1B) not in err
    assert "invalid choice" in err


def test_a_control_character_in_a_path_option_is_refused_and_not_echoed(
    root: Path, cli: Cli
) -> None:
    code, _, err = cli("scan", str(root), "--output", "bad" + chr(0x1B) + "[31m.txt")
    assert code == ExitCode.USAGE
    assert chr(0x1B) not in err
    assert "control_character" in err


FORBIDDEN_RANGES = [
    (0x00, 0x08),
    (0x0B, 0x1F),
    (0x7F, 0x9F),
    (0x200B, 0x200F),
    (0x2028, 0x202E),
    (0x2060, 0x206F),
    (0xFEFF, 0xFEFF),
    (0xE0000, 0xE007F),
]


def forbidden_characters(text: str) -> list[str]:
    """Characters that must never reach a terminal or a log (`\\n` is the only control allowed)."""
    return [
        f"U+{ord(ch):04X}"
        for ch in text
        if any(low <= ord(ch) <= high for low, high in FORBIDDEN_RANGES)
    ]


PORTABLE_HOSTILE = [
    "evil" + chr(0x202E) + "txt.exe",
    "zero" + chr(0x200B) + "width" + chr(0x2060) + ".txt",
    "bom" + chr(0xFEFF) + ".txt",
    "line" + chr(0x2028) + "sep.txt",
    "isolate" + chr(0x2066) + "x" + chr(0x2069) + ".txt",
    "key" + chr(0x1F511) + ".txt",
]
POSIX_HOSTILE = [
    "new\nline.txt",
    "carriage\r\nreturn.txt",
    "ansi" + chr(0x1B) + "[31mred" + chr(0x1B) + "[0m.txt",
    "osc" + chr(0x1B) + "]0;title" + chr(0x07) + ".txt",
    "backslash-x1b" + chr(92) + "x1b.txt",
    "tab\there.txt",
    "c1" + chr(0x85) + "next.txt",
]


def _hostile_case(root: Path, name: str, cli: Cli, token: str) -> None:
    put(root, name, f"v = {token}\n")
    put(root, "dir-" + name + "/inner.txt", f"v = {token}\n")
    code, out, err = cli("scan", str(root))
    assert code == ExitCode.FINDINGS
    assert forbidden_characters(out) == []
    assert forbidden_characters(err) == []
    shown = sanitize(name, max_chars=1_024)
    assert shown in out
    # one table row per finding: a newline in a name did not start a new row
    assert sum(1 for line in out.splitlines() if "npm-token" in line) == 2

    code, out, err = cli("scan", str(root), "--format", "json")
    document = json.loads(out)  # still one valid document
    assert out.isascii()
    assert forbidden_characters(out) == []
    assert shown in {finding["file"] for finding in document["findings"]}
    assert len(document["findings"]) == 2
    assert err == ""


@pytest.mark.parametrize("name", PORTABLE_HOSTILE, ids=lambda n: "portable-" + str(len(n)))
def test_hostile_names_are_inert_in_table_and_json(root: Path, cli: Cli, name: str) -> None:
    _hostile_case(root, name, cli, fake("npm-token"))


@pytest.mark.posix_only
@pytest.mark.parametrize("name", POSIX_HOSTILE, ids=lambda n: "posix-" + str(len(n)))
def test_posix_hostile_names_are_inert_in_table_and_json(root: Path, cli: Cli, name: str) -> None:
    _hostile_case(root, name, cli, fake("npm-token"))


@pytest.mark.posix_only
def test_a_name_that_is_not_valid_utf8_is_escaped_and_scanned(root: Path, cli: Cli) -> None:
    raw = os.path.join(os.fsencode(str(root)), b"bad" + bytes([0xFF, 0xFE]) + b".txt")
    with open(raw, "wb") as handle:
        handle.write(fake("npm-token").encode())
    code, out, err = cli("scan", str(root), "--format", "json")
    document = json.loads(out)
    assert (code, err) == (ExitCode.FINDINGS, "")
    [finding] = document["findings"]
    assert out.isascii()
    assert "bad" in finding["file"]
    assert "udcff" in finding["file"]  # surrogateescape, escaped
    assert "udcfe" in finding["file"]


def test_hostile_content_never_reaches_the_report(root: Path, cli: Cli) -> None:
    token = fake("npm-token")
    nasty = (chr(0x1B) + "[2J" + chr(0x202E) + "\r\n") * 3
    put(root, "a.txt", f"{nasty}key = {token} {nasty}\n")
    code, out, err = cli("scan", str(root))
    assert code == ExitCode.FINDINGS
    assert forbidden_characters(out) == []
    assert err == ""


def test_a_hostile_host_label_is_refused_or_escaped(root: Path, cli: Cli) -> None:
    code, _, err = cli("scan", str(root), "--format", "json", "--host-label", "a" + chr(0x1B))
    assert code == ExitCode.USAGE
    assert "control characters" in err
    code, out, _ = cli(
        "scan", str(root), "--format", "json", "--host-label", "caf" + chr(0xE9) + chr(0x202E)
    )
    assert code == ExitCode.OK
    assert out.isascii()
    assert json.loads(out)["host"] == "caf" + chr(92) + "xe9" + chr(92) + "u202e"
