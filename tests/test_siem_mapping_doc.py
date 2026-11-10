"""Drift tests: docs/siem-mapping.md and the JSONL renderer agree on fields, limits and examples
(CLAUDE.md section 10)."""

from __future__ import annotations

import json
import re
from pathlib import Path

import pytest

from secret_scanner.app.common import display_path
from secret_scanner.app.scan import ScanRequest, run_scan
from secret_scanner.cli import main as cli_main
from secret_scanner.core.models import OutputFormat, Target
from secret_scanner.core.sanitize import sanitize
from secret_scanner.render.jsonl import (
    EVENT_FINDING,
    EVENT_SUMMARY,
    FINDING_FIELDS,
    MAX_FILE_CHARS,
    MAX_VALUE_CHARS,
    SCHEMA,
    SUMMARY_FIELDS,
    TOP_LEVEL_FIELDS,
    render_jsonl,
)
from tests.doc_samples import HOST_LABEL, MASK, make_sample_tree, mask_times
from tests.helpers import PROJECT_ROOT, FakeClock, make_finding, make_report
from tests.test_render_jsonl import (
    MINI_SIEM_ALIASES,
    MINI_SIEM_MAX_ATTR_KEY_CHARS,
    MINI_SIEM_MAX_ATTR_VALUE_CHARS,
    MINI_SIEM_MAX_ATTRS,
    MINI_SIEM_MAX_DEPTH,
    MINI_SIEM_MAX_HOST_CHARS,
    MINI_SIEM_MAX_LINE_BYTES,
    MINI_SIEM_MAX_MESSAGE_CHARS,
    MINI_SIEM_TIME_KEYS,
)

DOC = (PROJECT_ROOT / "docs" / "siem-mapping.md").read_text(encoding="utf-8")
INGESTED_TOOL_VERSION = "0.1.0"  # what the tool reported on 2026-11-09, the day of the real ingest


def section(heading: str) -> str:
    level = len(heading) - len(heading.lstrip("#"))
    lines = DOC.splitlines()
    start = lines.index(heading)
    body: list[str] = []
    for line in lines[start + 1 :]:
        match = re.match(r"(#+) ", line)
        if match and len(match.group(1)) <= level:
            break
        body.append(line)
    return "\n".join(body)


def first_cells(heading: str) -> list[str]:
    """The backticked first cells of the table directly under `heading` (a sub-heading ends it)."""
    own = section(heading).split("\n### ")[0]
    return re.findall(r"^\| `([a-z_0-9]+)` \|", own, flags=re.MULTILINE)


def fenced(under: str) -> list[str]:
    return re.findall(r"```\n(.*?)\n```", section(under), flags=re.DOTALL)


@pytest.fixture(scope="module")
def sample_lines(tmp_path_factory: pytest.TempPathFactory) -> list[str]:
    """The JSONL of the documented example, with the times masked and the scan root shown as `.`
    (the example is produced by running the tool inside the project)."""
    root: Path = tmp_path_factory.mktemp("siem-doc")
    make_sample_tree(root)
    request = ScanRequest(path=str(root), output_format=OutputFormat.JSONL, host_label=HOST_LABEL)
    text = run_scan(request, FakeClock()).text
    shown_root = display_path(str(root), 1_024)
    text = text.replace(f'"target_path":"{shown_root}"', '"target_path":"."')
    return mask_times(text).splitlines()


# -- fields -------------------------------------------------------------------------------------


def test_the_top_level_fields_are_documented_in_order() -> None:
    assert first_cells("## Top-level fields") == [*TOP_LEVEL_FIELDS]


def test_the_finding_fields_are_documented_in_order() -> None:
    assert first_cells("### The finding line, `secret`") == list(FINDING_FIELDS)


def test_the_summary_fields_are_documented_in_order() -> None:
    assert first_cells("### The summary line, `secret`") == list(SUMMARY_FIELDS)


def test_the_schema_and_event_names_are_documented() -> None:
    assert DOC.startswith(f"# JSONL output and mini-siem (`{SCHEMA}`)")
    assert f"`{SCHEMA}`" in section("### The finding line, `secret`")
    assert f"`{EVENT_FINDING}`" in section("## Top-level fields")
    assert f"`{EVENT_SUMMARY}`" in section("## Top-level fields")
    assert f"`{EVENT_FINDING}` and" in DOC
    assert "never a top-level `path`" in " ".join(DOC.split())


# -- mini-siem's rules ----------------------------------------------------------------------------


def test_the_recorded_limits_are_the_ones_the_tests_check() -> None:
    table = section("### Limits recorded")
    rows = dict(re.findall(r"^\| ([^|]+?) \| ([\d ,]+)(?: [a-z]+)? \|", table, flags=re.MULTILINE))
    numbers = {name: int(re.sub(r"\D", "", value)) for name, value in rows.items()}
    assert numbers == {
        "Attributes per event": MINI_SIEM_MAX_ATTRS,
        "Attribute name": MINI_SIEM_MAX_ATTR_KEY_CHARS,
        "Attribute value": MINI_SIEM_MAX_ATTR_VALUE_CHARS,
        "`message`": MINI_SIEM_MAX_MESSAGE_CHARS,
        "`host`": MINI_SIEM_MAX_HOST_CHARS,
        "Line": MINI_SIEM_MAX_LINE_BYTES,
        "Nesting depth": MINI_SIEM_MAX_DEPTH,
    }


def test_the_documented_attribute_counts_are_the_field_counts() -> None:
    table = " ".join(section("### Limits recorded").split())
    assert f"at most {len(FINDING_FIELDS)} attributes plus `declared_event_type`" in table
    assert f"a summary line {len(SUMMARY_FIELDS)} plus it" in table
    assert len(SUMMARY_FIELDS) + 1 <= MINI_SIEM_MAX_ATTRS
    longest = max(f"secret.{name}" for name in (*FINDING_FIELDS, *SUMMARY_FIELDS))
    assert longest == "secret.suppressed_by_fingerprint" or len(longest) <= 40
    assert "secret.suppressed_by_fingerprint" in table
    assert f"cut at {MAX_FILE_CHARS:,}".replace(",", " ") in table
    assert MAX_FILE_CHARS <= MAX_VALUE_CHARS


def test_the_documented_longest_line_holds_for_the_worst_case() -> None:
    worst = sanitize(chr(0x202E) * 700)  # backslashes double again inside JSON
    report = make_report(
        (make_finding(path=worst, commit="f" * 64),),
        target=Target.GIT,
        target_display=worst,
        history_complete=True,
    )
    longest = max(
        len(line.encode("ascii")) for line in render_jsonl(report, "h" * 255).splitlines()
    )
    assert longest < 3_000
    assert "about 3 000 bytes" in " ".join(DOC.split())
    assert longest < MINI_SIEM_MAX_LINE_BYTES


def test_the_reinterpreted_top_level_keys_are_listed() -> None:
    text = " ".join(section("## How mini-siem reads a line").split())
    reinterpreted = {name for names in MINI_SIEM_ALIASES.values() for name in names}
    reinterpreted |= set(MINI_SIEM_TIME_KEYS) - {"timestamp"}
    reinterpreted -= {"message", "host", "timestamp"}  # the ones this tool writes on purpose
    for name in sorted(reinterpreted):
        assert f"`{name}`" in text, name
    for written in TOP_LEVEL_FIELDS:
        assert written not in reinterpreted or written in {"message", "host", "timestamp"}


# -- examples -------------------------------------------------------------------------------------


def test_the_directory_example_is_what_the_tool_writes(sample_lines: list[str]) -> None:
    example = fenced("## Examples")[0].splitlines()
    assert example == sample_lines
    assert all(f'"timestamp":"{MASK}"' in line for line in example)


def test_the_history_example_has_the_documented_shape() -> None:
    line = fenced("## Examples")[1]
    event = json.loads(line)
    assert tuple(event) == TOP_LEVEL_FIELDS
    assert tuple(event["secret"]) == FINDING_FIELDS
    secret = event["secret"]
    assert secret["target"] == "git"
    assert re.fullmatch(r"[0-9a-f]{40}", secret["commit"])
    assert event["message"].endswith(f" in commit {secret['commit'][:12]}")
    assert re.fullmatch(r"[ -~]{0,12}\.\.\. \[\d+ chars, sha256:[0-9a-f]{8}\]", secret["redacted"])
    assert secret["secret_hash8"] in secret["redacted"]
    assert isinstance(secret["commit_time"], int)


def test_the_stored_event_example_matches_the_finding_it_came_from(
    sample_lines: list[str],
) -> None:
    stored = json.loads(fenced("## A real ingest")[-1])
    event = json.loads(sample_lines[0])
    assert stored["event_type"] == "json_event"
    assert stored["message"] == event["message"]
    assert stored["host"] == event["host"]
    attrs = stored["attrs"]
    assert attrs.pop("declared_event_type") == event["event_type"]
    expected = {
        f"secret.{name}": ("true" if value is True else "false" if value is False else str(value))
        for name, value in event["secret"].items()
        if value is not None
    }
    assert list(attrs) == sorted(attrs), "mini-siem lists attributes sorted by name"
    assert list(attrs) == sorted(expected)
    cut = {name for name, value in attrs.items() if value.endswith("...")}
    assert cut == {"secret.file_sha256", "secret.fingerprint"}, "only the long hex values are cut"
    for name, value in attrs.items():
        if name in cut:
            assert expected[name].startswith(value.removesuffix("..."))
            assert len(value) == len("...") + 12
        elif name == "secret.tool_version":
            # the one value that is not regenerated: the ingest is real and was done before the
            # release, so the stored event keeps the version the tool reported on that day
            assert value == INGESTED_TOOL_VERSION
        else:
            assert value == expected[name]
    text = " ".join(section("## A real ingest").split())
    assert f"every line carried `tool_version` `{INGESTED_TOOL_VERSION}`" in text
    assert "The ingest was not repeated for the release" in text
    history = json.loads(fenced("## Examples")[1])
    assert history["secret"]["tool_version"] == INGESTED_TOOL_VERSION
    assert f"reported version `{INGESTED_TOOL_VERSION}`" in " ".join(section("## Examples").split())


def test_the_real_ingest_is_stated_with_its_result() -> None:
    ingest = fenced("## A real ingest")[0]
    assert "5 line(s), 5 record(s), 0 blank, 0 over-long" in ingest
    assert "events: 5 parsed, 5 newly stored, 0 already stored" in ingest
    assert "parse failures: 0" in ingest
    assert "alerts: 0 stored" in ingest
    text = " ".join(section("## A real ingest").split())
    assert "mini-siem 1.0.0 (commit `6adc008`)" in text
    assert "was the same before and after" in text
    assert "outside both repositories" in text
    search = fenced("## A real ingest")[1]
    assert "5 event(s), newest first" in search
    assert len([line for line in search.splitlines() if "json_event" in line]) == 5


def test_the_known_gaps_are_stated() -> None:
    gaps = " ".join(section("## Known gaps").split())
    assert "No mini-siem detection rule is written or tested here" in gaps
    assert "A search by attribute does not work" in gaps


def test_the_document_holds_no_full_secret_and_is_ascii() -> None:
    assert DOC.isascii()
    for value in re.findall(r"sha256:([0-9a-f]+)", DOC):
        assert len(value) == 8
    assert "@" not in DOC.replace("@timestamp", ""), "no email address"


def test_the_documented_command_runs_and_writes_the_documented_lines(
    tmp_path: Path,
    sample_lines: list[str],
    capsys: pytest.CaptureFixture[str],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """The first command of the document, run as written from the directory that holds `project`.
    (Until version 1.0.0 the document showed `scan . --output events.jsonl`, which the tool
    refuses: an output inside the scanned tree.)"""
    command = re.search(r"```\n(secret-scanner scan [^\n]+)\n", DOC)
    assert command is not None
    argv = command.group(1).split()
    assert argv[:3] == ["secret-scanner", "scan", "project"]
    make_sample_tree(tmp_path / "project")
    monkeypatch.chdir(tmp_path)
    assert cli_main.main(argv[1:]) == 1, "the sample project has two findings"
    captured = capsys.readouterr()
    assert captured.out == ""
    assert captured.err == "secret-scanner: report written to events.jsonl\n"
    written = mask_times((tmp_path / "events.jsonl").read_text(encoding="utf-8")).splitlines()
    expected = [
        line.replace('"host":"example-host"', '"host":"build-01"').replace(
            '"target_path":"."', '"target_path":"project"'
        )
        for line in sample_lines
    ]
    assert written == expected
    # what the document says is refused, is refused
    assert cli_main.main(["scan", "project", "--output", "project/events.jsonl"]) == 2
    assert "must not be inside the scanned tree" in capsys.readouterr().err
    assert cli_main.main(["scan", "project", "--output", "../events.jsonl"]) == 2
    assert "path refused" in capsys.readouterr().err
