"""The four output formats side by side: a hostile file name in every format, and `scan-git`
through the new JSONL and SARIF formats with a secret that was committed and removed again
(PLAN.md Phase 5, threat model rows "terminal, log or report injection" and "the tool leaks a
found secret").

The directory scan of every rule in every format is in tests/test_scan_leakage.py; the table and
JSON formats of `scan-git` are in tests/test_git_scan.py."""

from __future__ import annotations

import json
from collections.abc import Callable
from pathlib import Path
from typing import Any

import pytest

from secret_scanner.cli import main as cli_main
from secret_scanner.core.fakes import build_fake
from secret_scanner.services.loader import load_builtin_rules
from tests.conftest import leak_check
from tests.gitrepo import GitRepo
from tests.helpers import public_prefix_length
from tests.sarif_check import check_sarif
from tests.test_scan_leakage import PLANTED, REPRESENTATIVES, Planted

RLO = chr(0x202E)  # right-to-left override
ZERO_WIDTH_SPACE = chr(0x200B)
BACKSLASH = chr(92)
# A name that is legal on Windows and on POSIX, and hostile in every format: bidirectional and
# zero-width characters, a space, URI syntax and a percent sign.
HOSTILE_DIRECTORY = "d#r%20"
HOSTILE_FILE = "we ird" + RLO + "na%41me" + ZERO_WIDTH_SPACE + "[x]&y.txt"
HOSTILE_PATH = f"{HOSTILE_DIRECTORY}/{HOSTILE_FILE}"
FORBIDDEN_RAW = (RLO, ZERO_WIDTH_SPACE, chr(0x1B), chr(0x7F), chr(0x85))


def cli(capsys: pytest.CaptureFixture[str], *argv: str) -> tuple[int, str, str]:
    code = cli_main.main(list(argv))
    captured = capsys.readouterr()
    return code, captured.out, captured.err


def artifact_uri_of(result: dict[str, Any]) -> str:
    uri = result["locations"][0]["physicalLocation"]["artifactLocation"]["uri"]
    assert isinstance(uri, str)
    return uri


def aws_fake() -> str:
    rule = next(r for r in load_builtin_rules().rules if r.id == "aws-access-key-id")
    return build_fake(rule, "formats")


# -- a hostile name in every format ---------------------------------------------------------------


def test_a_hostile_file_name_is_inert_in_every_format(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    root = tmp_path / "tree"
    target = root / HOSTILE_DIRECTORY / HOSTILE_FILE
    target.parent.mkdir(parents=True)
    target.write_text(f"aws_key = {aws_fake()}\n", encoding="utf-8", newline="\n")
    outputs: dict[str, str] = {}
    for fmt in ("table", "json", "jsonl", "sarif"):
        code, out, err = cli(capsys, "scan", str(root), "--format", fmt)
        assert code == 1
        assert err == ""
        outputs[fmt] = out
        for raw in FORBIDDEN_RAW:
            assert raw not in out, f"{fmt}: a raw {ord(raw):#x} reached the output"
    escaped = (
        HOSTILE_DIRECTORY + "/we ird" + BACKSLASH + "u202ena%41me" + BACKSLASH + "u200b[x]&y.txt"
    )
    assert escaped in outputs["table"]
    document = json.loads(outputs["json"])
    assert document["findings"][0]["file"] == escaped
    finding, summary = (json.loads(line) for line in outputs["jsonl"].splitlines())
    assert finding["secret"]["file"] == escaped
    assert finding["secret"]["file_truncated"] is False
    assert summary["secret"]["findings"] == 1
    sarif = json.loads(outputs["sarif"])
    assert check_sarif(sarif) == []
    uri = sarif["runs"][0]["results"][0]["locations"][0]["physicalLocation"]["artifactLocation"][
        "uri"
    ]
    assert uri == "d%23r%2520/we%20ird%E2%80%AEna%2541me%E2%80%8B%5Bx%5D%26y.txt"
    assert outputs["json"].isascii()
    assert outputs["jsonl"].isascii()
    assert outputs["sarif"].isascii()


# -- scan-git through JSONL and SARIF -------------------------------------------------------------


def _git_cases() -> list[Any]:
    return [
        pytest.param(
            planted,
            id=planted.name,
            marks=() if planted.name == "aws-access-key-id" else pytest.mark.slow,
        )
        for planted in PLANTED
        if planted.name in REPRESENTATIVES or planted.name == "aws-access-key-id"
    ]


@pytest.mark.requires_git
@pytest.mark.parametrize("planted", _git_cases())
def test_scan_git_in_jsonl_and_sarif_names_the_commit_and_carries_no_secret(
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
    assert_not_leaked: Callable[..., None],
    planted: Planted,
) -> None:
    home = tmp_path / "home"
    home.mkdir()
    repo = GitRepo.create(tmp_path / "repo", home)
    added = repo.commit_files("add", {HOSTILE_PATH: planted.file_text})
    repo.commit_files("remove", {HOSTILE_PATH: "gone\n"})
    path, baseline = str(repo.path), tmp_path / "baseline.yaml"
    low = ["--min-confidence", "low"]
    pieces: list[tuple[str, str]] = []

    def run(label: str, *argv: str) -> tuple[int, str]:
        code, out, err = cli(capsys, "scan-git", path, *low, *argv)
        pieces.extend([(f"{label}: stdout", out), (f"{label}: stderr", err)])
        return code, out

    code, jsonl = run("jsonl", "--format", "jsonl", "--write-baseline", str(baseline))
    assert code == 1
    finding, summary = (json.loads(line) for line in jsonl.splitlines())
    assert finding["secret"]["target"] == "git"
    assert finding["secret"]["commit"] == added
    assert finding["secret"]["file"].startswith(HOSTILE_DIRECTORY + "/we ird" + BACKSLASH + "u202e")
    assert finding["message"].endswith(f" in commit {added[:12]}")
    assert summary["secret"]["history_complete"] is True
    assert summary["secret"]["commits"] == 2

    code, sarif_text = run("sarif", "--format", "sarif")
    assert code == 1
    sarif = json.loads(sarif_text)
    assert check_sarif(sarif) == []
    (result,) = sarif["runs"][0]["results"]
    assert result["properties"]["commit"] == added
    assert result["message"]["text"].endswith(f" in commit {added[:12]}")
    assert "%E2%80%AE" in artifact_uri_of(result)

    code, shown = run(
        "shown", "--format", "jsonl", "--baseline", str(baseline), "--show-suppressed"
    )
    assert code == 0
    suppressed = json.loads(shown.splitlines()[0])
    assert suppressed["secret"]["suppressed_by"] == "fingerprint"
    code, hidden = run("hidden", "--format", "sarif", "--baseline", str(baseline))
    assert code == 0
    assert json.loads(hidden)["runs"][0]["results"] == []

    pieces.append(("baseline", baseline.read_text("utf-8")))
    for label, text in pieces:
        problem = leak_check(text, planted.needle, allowed_shown=planted.allowed_shown)
        if problem is not None:
            pytest.fail(f"{planted.name} / {label}: {problem}", pytrace=False)
        for raw in FORBIDDEN_RAW:
            assert raw not in text, f"{label}: a raw {ord(raw):#x} reached the output"
    assert_not_leaked(jsonl, planted.needle, allowed_shown=planted.allowed_shown)


def test_the_leak_allowance_is_only_the_formats_fixed_text() -> None:
    """The allowance in these leak checks is the format's fixed text, nothing more."""
    for rule in load_builtin_rules().rules:
        fake = build_fake(rule, "prefix")
        assert public_prefix_length(rule) < len(fake)
