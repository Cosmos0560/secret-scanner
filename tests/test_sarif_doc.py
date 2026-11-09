"""Drift tests: docs/sarif.md and the SARIF renderer agree on fields, tables and the example
(CLAUDE.md section 10)."""

from __future__ import annotations

import json
import re
from pathlib import Path

import pytest

from secret_scanner.app.scan import ScanRequest, run_scan
from secret_scanner.core.models import OutputFormat, Severity
from secret_scanner.render import sarif
from secret_scanner.render.sarif import (
    FINGERPRINT_KEY,
    INFORMATION_URI,
    LEVELS,
    SARIF_VERSION,
    SCHEMA_URI,
    SECURITY_SEVERITY,
    SOURCE_ROOT_ID,
    artifact_uri,
)
from tests.doc_samples import HOST_LABEL, make_sample_tree, mask_times
from tests.helpers import PROJECT_ROOT, FakeClock

DOC = (PROJECT_ROOT / "docs" / "sarif.md").read_text(encoding="utf-8")


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
    """The backticked first cells of the table directly under `heading`."""
    own = section(heading).split("\n### ")[0]
    return re.findall(r"^\| `([^`]+)` \|", own, flags=re.MULTILINE)


@pytest.fixture(scope="module")
def sample_document(tmp_path_factory: pytest.TempPathFactory) -> dict[str, object]:
    root: Path = tmp_path_factory.mktemp("sarif-doc")
    make_sample_tree(root)
    request = ScanRequest(path=str(root), output_format=OutputFormat.SARIF, host_label=HOST_LABEL)
    outcome = run_scan(request, FakeClock())
    document = json.loads(outcome.text)
    assert isinstance(document, dict)
    return document


def run_of(document: dict[str, object]) -> dict[str, object]:
    runs = document["runs"]
    assert isinstance(runs, list)
    run = runs[0]
    assert isinstance(run, dict)
    return run


def example() -> dict[str, object]:
    match = re.search(r"```json\n(.*?)\n```", section("## Example"), flags=re.DOTALL)
    assert match is not None
    loaded = json.loads(match.group(1))
    assert isinstance(loaded, dict)
    return loaded


def test_the_document_properties_are_documented() -> None:
    cells = first_cells("## Document")
    assert cells[:3] == ["$schema", "version", "runs"]
    text = section("## Document")
    assert f"`{SCHEMA_URI}`" in text
    assert f"`{SARIF_VERSION}`" in text


def test_the_run_properties_are_documented_in_order(sample_document: dict[str, object]) -> None:
    assert first_cells("### `runs[0]`") == list(run_of(sample_document))


def test_the_rule_descriptor_properties_are_documented_in_order(
    sample_document: dict[str, object],
) -> None:
    rules = run_of(sample_document)["tool"]["driver"]["rules"]  # type: ignore[index]
    assert first_cells("### Rule descriptors, `tool.driver.rules[]`") == list(rules[0])
    assert all(list(rule) == list(rules[0]) for rule in rules)


def test_the_result_properties_are_documented_in_order(
    sample_document: dict[str, object],
) -> None:
    results = run_of(sample_document)["results"]
    assert isinstance(results, list)
    documented = first_cells("### Results, `runs[0].results[]`")
    assert documented[:-1] == list(results[0])
    assert documented[-1] == "suppressions"  # only on a suppressed finding


def test_the_driver_properties_are_the_documented_ones(sample_document: dict[str, object]) -> None:
    driver = run_of(sample_document)["tool"]["driver"]  # type: ignore[index]
    text = " ".join(section("### `runs[0]`").split())
    for name in ("name", "version", "semanticVersion", "informationUri", "rules"):
        assert name in driver
        assert f"`{name}`" in text
    assert driver["informationUri"] == INFORMATION_URI


def test_the_severity_table_matches_the_code() -> None:
    rows = re.findall(
        r"^\| `(\w+)` \| `(\w+)` \| (?:`([\d.]+)`|\(none\)) \|",
        section("## Severity mapping"),
        flags=re.MULTILINE,
    )
    assert [row[0] for row in rows] == [s.value for s in reversed(list(Severity))]
    for severity_name, level, score in rows:
        severity = Severity(severity_name)
        assert LEVELS[severity] == level
        assert SECURITY_SEVERITY.get(severity, "") == score


def test_the_uri_examples_are_what_the_code_produces() -> None:
    rows = re.findall(r"^\| `([^`]+)` \| `([^`]+)` \|$", section("## Artifact URIs"), re.MULTILINE)
    assert len(rows) >= 4
    for name, uri in rows:
        assert artifact_uri(name) == uri
    accented = "caf" + chr(0xE9)
    assert artifact_uri(accented) == "caf%C3%A9"
    assert "`caf%C3%A9`" in section("## Artifact URIs")


def test_the_fixed_names_are_documented() -> None:
    assert f"`{FINGERPRINT_KEY}`" in DOC
    assert f"`{SOURCE_ROOT_ID}`" in DOC
    assert "`unicodeCodePoints`" in DOC
    for kind in ("external",):
        assert f"`{kind}`" in DOC
    assert set(sarif.JUSTIFICATIONS) == {"fingerprint", "path"}


def test_the_example_is_what_the_tool_writes(sample_document: dict[str, object]) -> None:
    shown = example()
    produced = json.loads(mask_times(json.dumps(sample_document)))
    # the example cuts the rule list to its first entry; nothing else differs
    shortened = json.loads(json.dumps(produced))
    run_of(shortened)["tool"]["driver"]["rules"] = run_of(shortened)["tool"]["driver"]["rules"][:1]  # type: ignore[index]
    assert shown == shortened
    rules = run_of(produced)["tool"]["driver"]["rules"]  # type: ignore[index]
    assert len(rules) == 16
    assert "of 16" in section("## Example")
    for result in run_of(shown)["results"]:  # type: ignore[attr-defined]
        assert re.fullmatch(r"[0-9a-f]{32}", result["partialFingerprints"][FINGERPRINT_KEY])
        assert re.fullmatch(
            r"[ -~]{0,12}\.\.\. \[\d+ chars, sha256:[0-9a-f]{8}\]", result["properties"]["redacted"]
        )


def test_the_known_gaps_are_stated() -> None:
    gaps = " ".join(section("## Known gaps").split())
    assert "Not validated against the official schema" in gaps
    assert "No upload to GitHub code scanning was done" in gaps


def test_the_document_is_plain_ascii() -> None:
    assert DOC.isascii()
