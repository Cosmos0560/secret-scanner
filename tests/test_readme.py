"""README.md against the code (CLAUDE.md section 10): the examples are the tool's real output, the
options, exit codes, limits and constants are the real ones, every claim names evidence that
exists, and the Limitations the owner asked for are stated.

The examples were pasted from real runs; these tests run the same commands again and compare, so
the README cannot describe output the code no longer produces. Only the time of the run differs.
"""

from __future__ import annotations

import argparse
import re
from pathlib import Path

import pytest
import yaml

from secret_scanner import __version__
from secret_scanner.app.demo import run_demo
from secret_scanner.cli import main as cli_main
from secret_scanner.core import fingerprint, gitparse, limits, lines, redact
from secret_scanner.core.detect import entropy
from secret_scanner.core.errors import ExitCode
from secret_scanner.core.models import Confidence, Detector, OutputFormat, Severity
from secret_scanner.core.ruleinfo import rule_infos
from secret_scanner.fs.walk import DEFAULT_EXCLUDED_DIRECTORIES
from secret_scanner.services.loader import load_builtin_rules
from tests.doc_samples import make_sample_tree, mask_times
from tests.helpers import PROJECT_ROOT, FakeClock, local_traces

README = (PROJECT_ROOT / "README.md").read_text(encoding="utf-8")
FLAT = " ".join(README.split())
UNITS = {"": 1, "KiB": limits.KIB, "MiB": limits.MIB, "GiB": limits.GIB}


def section(heading: str) -> str:
    """The text under `heading` up to the next heading of the same or a higher level."""
    level = len(heading) - len(heading.lstrip("#"))
    rows = README.splitlines()
    start = rows.index(heading)
    body: list[str] = []
    for row in rows[start + 1 :]:
        match = re.match(r"(#+) ", row)
        if match and len(match.group(1)) <= level:
            break
        body.append(row)
    return "\n".join(body)


def console_block(first_command: str) -> dict[str, str]:
    """The fenced block that starts with `$ <first_command>`, as {command: output}."""
    match = re.search(r"```\n(\$ " + re.escape(first_command) + r"\n.*?)\n```", README, re.DOTALL)
    assert match is not None, first_command
    commands: dict[str, str] = {}
    current = ""
    for row in match.group(1).splitlines():
        if row.startswith("$ "):
            current = row[2:]
            commands[current] = ""
        else:
            commands[current] += row + "\n"
    return commands


def table_rows(text: str) -> list[list[str]]:
    """The cells of every table row in `text`, without header and separator rows."""
    rows = [row for row in text.splitlines() if row.startswith("|")]
    cells = [[cell.strip() for cell in row.strip("|").split("|")] for row in rows]
    return [row for row in cells if not set(row[0]) <= set("-") and row[0] not in HEADERS]


HEADERS = {"Option", "Code", "Format", "Claim", "Limit (`limits:` key)"}


# -- the examples are real output -------------------------------------------------------------


def test_the_version_example_is_the_version() -> None:
    assert console_block("secret-scanner --version") == {
        "secret-scanner --version": f"secret-scanner {__version__}\n"
    }
    assert f"Version {__version__}." in FLAT


@pytest.mark.slow
@pytest.mark.requires_git
def test_the_demo_output_is_what_the_demo_prints(tmp_path: Path) -> None:
    shown = console_block("secret-scanner demo")["secret-scanner demo"]
    printed = run_demo(FakeClock(), parent=str(tmp_path)).text
    assert mask_times(shown) == mask_times(printed)
    assert len(re.findall(r"^generated \d{4}-", shown, re.MULTILINE)) == 2


def test_the_scan_examples_are_what_the_commands_print(
    tmp_path: Path, capsys: pytest.CaptureFixture[str], monkeypatch: pytest.MonkeyPatch
) -> None:
    """`project` is the generated sample tree of tests/doc_samples.py; the commands are run as
    written, from the directory that holds it."""
    make_sample_tree(tmp_path / "project")
    monkeypatch.chdir(tmp_path)
    examples = {**console_block("secret-scanner scan project")}
    examples.update(console_block("secret-scanner scan project --write-baseline baseline.yaml"))
    assert list(examples) == [
        "secret-scanner scan project",
        "secret-scanner scan project --write-baseline baseline.yaml",
        "secret-scanner scan project --baseline baseline.yaml",
    ]
    codes = []
    for command, shown in examples.items():
        codes.append(cli_main.main(command.split()[1:]))
        captured = capsys.readouterr()
        # the baseline example shows the notice (standard error) and leaves the table out
        printed = captured.err if "--write-baseline" in command else captured.out
        assert mask_times(shown) == mask_times(printed), command
    assert codes == [1, 1, 0]
    quick_start = " ".join(section("## Quick start").split())
    assert "The exit code of that run is 1" in quick_start
    assert "The second run exits with code 0" in quick_start


def test_the_mini_siem_command_is_the_one_the_mapping_document_tests() -> None:
    mapping = (PROJECT_ROOT / "docs" / "siem-mapping.md").read_text(encoding="utf-8")
    command = re.search(r"```\n(secret-scanner scan [^\n]+\nmini-siem [^\n]+)\n```", mapping)
    assert command is not None
    assert command.group(1) in section("## Feeding findings to mini-siem")


# -- commands, options, vocabularies ----------------------------------------------------------


def _subcommands() -> dict[str, argparse.ArgumentParser]:
    parser = cli_main.build_parser()
    for action in parser._actions:
        if isinstance(action, argparse._SubParsersAction):
            return dict(action.choices)
    raise AssertionError("the parser has no subcommands")


def _options(parser: argparse.ArgumentParser) -> set[str]:
    names = {name for action in parser._actions for name in action.option_strings}
    return {name for name in names if name.startswith("--") and name != "--help"}


def _documented(text: str) -> set[str]:
    return {row[0].strip("`").split()[0] for row in table_rows(text) if row[0].startswith("`--")}


def test_every_option_of_every_command_is_documented() -> None:
    commands = _subcommands()
    assert set(commands) == {"scan", "scan-git", "rules", "demo"}
    report = _documented(section("### Report options of `scan` and `scan-git`"))
    assert len(report) == 10
    assert _documented(section("### `scan PATH`")) | report == _options(commands["scan"])
    assert _documented(section("### `scan-git REPO`")) | report == _options(commands["scan-git"])
    assert _documented(section("### `rules`")) == _options(commands["rules"])
    assert _options(commands["demo"]) == set()
    assert "No options." in section("### `demo`")
    listing = section("## Commands").split("```")[1]
    for name in commands:
        assert f"secret-scanner {name}" in listing


def test_the_vocabularies_are_the_real_ones() -> None:
    options = section("### Report options of `scan` and `scan-git`")
    formats = [f"`{fmt.value}`" for fmt in OutputFormat]
    assert "`table` (default), `json`, `jsonl` or `sarif`" in options
    assert [row[0] for row in table_rows(section("### Output formats"))] == formats
    assert "`low`, `medium` (default) or `high`" in options
    assert [c.value for c in Confidence] == ["low", "medium", "high"]
    assert "`info`, `low` (default), `medium`, `high` or `critical`" in options
    assert [s.value for s in Severity] == ["info", "low", "medium", "high", "critical"]


def test_the_exit_codes_are_the_real_ones() -> None:
    rows = table_rows(section("### Exit codes"))
    assert [int(row[0]) for row in rows] == [*sorted(int(code) for code in ExitCode), 130]
    assert cli_main.INTERRUPTED == 130
    assert "the order is 2, then 3, then 4, then 1, then 0" in FLAT


def _number(cell: str) -> int:
    match = re.fullmatch(r"([\d,]+)(?: (KiB|MiB|GiB))?", cell)
    assert match is not None, cell
    return int(match.group(1).replace(",", "")) * UNITS[match.group(2) or ""]


def test_the_limits_table_is_the_limits_module() -> None:
    specs = {spec.name.lower(): spec for spec in limits.LIMIT_SPECS}
    rows = table_rows(section("### Limits"))
    assert len(rows) == 10
    for row in rows:
        name = re.match(r"`(\w+)`", row[0])
        assert name is not None, row[0]
        spec = specs[name.group(1)]
        assert (_number(row[1]), _number(row[2])) == (spec.default, spec.ceiling), row[0]
        assert name.group(1) in limits.limit_field_names()
    assert f"default time budget of {limits.MAX_RUN_SECONDS} seconds" in FLAT
    assert (
        f"larger than the size limit ({limits.MAX_FILE_BYTES // limits.MIB} MiB by default" in FLAT
    )


def test_the_default_excluded_directories_are_listed() -> None:
    paragraph = " ".join(section("### `scan PATH`").split())
    listed = re.search(r"skipped by default wherever they appear: ([^|]+?)\. \|", paragraph)
    assert listed is not None
    names = {name.strip("`") for name in listed.group(1).split(", ")}
    assert names == set(DEFAULT_EXCLUDED_DIRECTORIES)


def test_the_constants_in_the_text_are_the_codes() -> None:
    infos = rule_infos(load_builtin_rules().rules)
    regex_rules = sum(1 for info in infos if info.detector is Detector.RULE)
    detectors = len(infos) - regex_rules
    major, minor = gitparse.MIN_GIT_VERSION[:2]
    for sentence in (
        f"lists the {regex_rules} token-format rules and the {detectors} detectors",
        f"Only the {regex_rules} formats in",
        f"git {major}.{minor} or newer is needed",
        f"at least version {major}.{minor}",
        f"at most {redact.MAX_SHOWN_CHARS} characters and at most a quarter of the secret",
        f"the first {redact.ENTROPY_SHOWN_CHARS} characters are shown if the string has at least "
        f"{redact.ENTROPY_SHOWN_MIN_LENGTH}",
        f"**The {redact.DISPLAY_HASH_CHARS} hex digits**",
        f"the first {fingerprint.FINGERPRINT_HEX_CHARS} hex digits (128 bits)",
        f"its first {lines.BINARY_PROBE_BYTES:,} bytes contain a NUL byte",
        f"a NUL byte in the first {lines.BINARY_PROBE_BYTES:,} bytes",
        "at least 64 bits of estimated randomness",
    ):
        assert sentence in FLAT, sentence
    assert redact.DISPLAY_DOMAIN == b"secret-scanner/display/v1\x00"
    assert 'sha256("secret-scanner/display/v1" + NUL + secret)' in FLAT
    assert fingerprint.FINGERPRINT_DOMAIN == b"secret-scanner/fingerprint/v1\x00"
    assert '"secret-scanner/fingerprint/v1" + NUL + rule id + NUL + path + NUL + secret' in FLAT
    assert entropy.EXCLUDED_SUFFIXES == (".min.js", ".min.css", ".map", ".svg")


# -- claims and evidence ------------------------------------------------------------------------


def test_every_claim_names_evidence_that_exists() -> None:
    rows = table_rows(section("## Claims and evidence"))
    assert len(rows) >= 20
    for claim, evidence in rows:
        named = re.findall(r"`([^`]+)`", evidence)
        assert named, f"no evidence for: {claim}"
        for name in named:
            path, _, function = name.partition("::")
            file = PROJECT_ROOT / path
            assert file.is_file(), name
            assert path.startswith(("tests/", "docs/", "scripts/")), name
            if function:
                assert re.fullmatch(r"test_\w+", function), name
                source = file.read_text(encoding="utf-8")
                assert f"def {function}(" in source, name
        assert any("::" in name or name.endswith(".md") for name in named), claim


def test_every_document_the_readme_links_exists() -> None:
    links = set(re.findall(r"\]\(((?!#|https?:)[^)]+)\)", README))
    assert len(links) >= 9
    assert sorted(link for link in links if not (PROJECT_ROOT / link).is_file()) == []
    anchors = set(re.findall(r"\]\(#([^)]+)\)", README))
    headings = {
        re.sub(r"[^a-z0-9 -]", "", heading.lower()).replace(" ", "-")
        for heading in re.findall(r"^#+ (.+)$", README, re.MULTILINE)
    }
    assert anchors <= headings


# -- what must be said ----------------------------------------------------------------------------

REQUIRED_LIMITATIONS = (
    "Detection is by pattern and by entropy",
    "False negatives",
    "False positives",
    "not from live verification",
    "never verifies a secret against a live service, by design",
    "commit messages, tag messages",
    "the reflog, unreachable objects",
    "the contents of submodules",
    "Git LFS objects",
    "Refused with exit code 3, deliberately",
    "a worktree or a submodule checkout",
    "alternates",
    "`info/grafts`",
    "time-of-check to time-of-use gap",
    "has not been validated against the official SARIF 2.1.0 schema",
    "has not yet been uploaded to GitHub code scanning",
    "cannot search by the `secret.*` attributes",
    "no mini-siem detection rule ships",
    "`csc.exe`",
    "`/proc/self/fd`",
    "macOS",
    "come from one machine",
    "cannot see shell aliases, variables or an encoded PowerShell command",
    "not in force if `sh` cannot start",
    "A baseline taken from the branch under test",
    "Fingerprints depend on the scan root and the file path",
    "UTF-16 or UTF-32 text without a byte-order mark",
    "archives",
    "split across lines",
    "access time",
    "cannot be scanned completely in one run",
    "can only lower a limit, never raise it",
    "only look alike",
    "git must be trusted",
)


def test_the_limitations_the_owner_asked_for_are_stated() -> None:
    stated = " ".join(section("## Limitations").split())
    assert [phrase for phrase in REQUIRED_LIMITATIONS if phrase not in stated] == []


def test_the_legal_note_and_the_unverified_workflow_are_marked() -> None:
    legal = " ".join(section("## Scan only what you are allowed to scan").split())
    assert (
        "only on code, directories and repositories that you own or are explicitly authorised"
        in (legal)
    )
    ci = section("## Using it in CI")
    assert "**It has not been verified**" in ci
    workflow = yaml.safe_load(re.search(r"```yaml\n(.*?)\n```", ci, re.DOTALL).group(1))  # type: ignore[union-attr]
    steps = workflow["jobs"]["scan"]["steps"]
    assert workflow["permissions"] == {"contents": "read", "security-events": "write"}
    assert [step.get("uses", "").split("@")[0] for step in steps if "uses" in step] == [
        "actions/checkout",
        "actions/setup-python",
        "github/codeql-action/upload-sarif",
    ]
    scan = next(step["run"] for step in steps if step.get("name") == "Scan the checked-out tree")
    arguments = scan.split()
    assert arguments[:3] == ["secret-scanner", "scan", "."]
    parsed = cli_main.build_parser().parse_args(arguments[1:])
    assert parsed.output_format == "sarif"
    assert parsed.output == '"$RUNNER_TEMP/secrets.sarif"', "outside the scanned tree"


def test_the_readme_says_nothing_about_the_machine_it_was_written_on() -> None:
    assert README.isascii()
    assert local_traces(README, PROJECT_ROOT, absolute_paths=False) == []
    assert not re.search(r"[A-Za-z]:\\\\?Users|/home/\w|/Users/\w", README)
    assert "Phase 1 of 6" not in README
    assert "under construction" not in README
    for value in re.findall(r"sha256:([0-9a-f]+)", README):
        assert len(value) == redact.DISPLAY_HASH_CHARS, "only redacted values are shown"
