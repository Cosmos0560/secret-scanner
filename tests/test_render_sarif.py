"""The SARIF renderer: structure field by field, the level and security-severity tables, URI
percent-encoding of hostile names, `columnKind`, suppressions, notifications for issues, and the
absence of anything that could hold a secret (PLAN.md D12, docs/sarif.md).

There is no validation against the official SARIF schema (no PyPI package ships it); the checker
in `tests/sarif_check.py` is written from the specification. That is a documented known gap."""

from __future__ import annotations

import dataclasses
import json
from collections.abc import Callable
from pathlib import Path
from urllib.parse import unquote_to_bytes

import pytest

from secret_scanner.app.scan import ScanRequest, run_scan
from secret_scanner.cli import main as cli_main
from secret_scanner.core.errors import ExitCode
from secret_scanner.core.fakes import build_fake
from secret_scanner.core.models import (
    Confidence,
    Detector,
    IssueKind,
    OutputFormat,
    Redacted,
    ScanIssue,
    Severity,
    SuppressedBy,
    Target,
)
from secret_scanner.core.ruleinfo import DETECTOR_INFOS, RuleInfo, rule_infos
from secret_scanner.core.sanitize import sanitize
from secret_scanner.render import sarif
from secret_scanner.render.sarif import (
    FINGERPRINT_KEY,
    LEVELS,
    SARIF_VERSION,
    SECURITY_SEVERITY,
    artifact_uri,
    render_sarif,
    sarif_document,
)
from secret_scanner.services.loader import dump_yaml, load_builtin_rules
from tests.helpers import FINGERPRINT, HASH8, FakeClock, make_finding, make_report
from tests.sarif_check import URI_REFERENCE, check_sarif, walk_keys

INFOS = rule_infos(load_builtin_rules().rules)
COMMIT = "0123456789abcdef0123456789abcdef01234567"


def document(report: object) -> dict[str, object]:
    text = render_sarif(report, INFOS)  # type: ignore[arg-type]
    loaded = json.loads(text)
    assert isinstance(loaded, dict)
    return loaded


def run_of(doc: dict[str, object]) -> dict[str, object]:
    runs = doc["runs"]
    assert isinstance(runs, list)
    run = runs[0]
    assert isinstance(run, dict)
    return run


def results_of(doc: dict[str, object]) -> list[dict[str, object]]:
    results = run_of(doc)["results"]
    assert isinstance(results, list)
    return results


def only_invocation(doc: dict[str, object]) -> dict[str, object]:
    invocations = run_of(doc)["invocations"]
    assert isinstance(invocations, list)
    assert len(invocations) == 1
    return invocations[0]  # type: ignore[no-any-return]


def driver_rules(doc: dict[str, object]) -> list[dict[str, object]]:
    tool = run_of(doc)["tool"]
    assert isinstance(tool, dict)
    rules = tool["driver"]["rules"]
    assert isinstance(rules, list)
    return rules


# -- structure ----------------------------------------------------------------------------------


def test_the_document_has_the_documented_top_level_shape() -> None:
    doc = document(make_report((make_finding(),)))
    assert list(doc) == ["$schema", "version", "runs"]
    assert doc["version"] == SARIF_VERSION == "2.1.0"
    assert str(doc["$schema"]).endswith("sarif-schema-2.1.0.json")
    run = run_of(doc)
    assert list(run) == ["tool", "columnKind", "invocations", "results", "properties"]
    assert run["columnKind"] == "unicodeCodePoints"
    driver = run["tool"]["driver"]  # type: ignore[index]
    assert list(driver) == [
        "name",
        "version",
        "semanticVersion",
        "informationUri",
        "rules",
    ]
    assert driver["name"] == "secret-scanner"
    assert driver["version"] == driver["semanticVersion"] == "0.1.0"
    assert driver["informationUri"].startswith("https://")


@pytest.mark.parametrize(
    "report",
    [
        make_report(),
        make_report((make_finding(),)),
        make_report((make_finding(commit=COMMIT),), target=Target.GIT, history_complete=True),
        make_report(
            (make_finding(suppressed_by=SuppressedBy.FINGERPRINT), make_finding(line=8)),
            by_fingerprint=1,
        ),
        make_report(
            issues=(
                ScanIssue(IssueKind.UNREADABLE, "a.txt", "permission denied"),
                ScanIssue(IssueKind.LIMIT_REACHED, None, "limit reached"),
            )
        ),
    ],
    ids=["empty", "one-finding", "git", "suppressed", "issues"],
)
def test_every_kind_of_report_passes_the_structural_checks(report: object) -> None:
    assert check_sarif(document(report)) == []


def test_the_checker_itself_rejects_broken_documents() -> None:
    good = document(make_report((make_finding(),)))
    assert check_sarif(good) == []
    broken = json.loads(json.dumps(good))
    results_of(broken)[0]["ruleIndex"] = 999
    results_of(broken)[0]["locations"][0]["physicalLocation"]["artifactLocation"]["uri"] = "a b"  # type: ignore[index]
    results_of(broken)[0]["level"] = "fatal"
    run_of(broken)["columnKind"] = "utf16CodeUnits"
    problems = check_sarif(broken)
    assert any("ruleIndex" in p for p in problems)
    assert any("percent-encoded" in p for p in problems)
    assert any("level" in p for p in problems)
    assert any("columnKind" in p for p in problems)
    snippet = json.loads(json.dumps(good))
    results_of(snippet)[0]["locations"][0]["physicalLocation"]["region"]["snippet"] = {"text": "x"}  # type: ignore[index]
    assert any("region holds exactly" in p for p in check_sarif(snippet))
    assert check_sarif([]) == ["the document is not an object"]
    assert check_sarif({"version": "2.1.0", "$schema": "x", "runs": []})[-1].startswith("exactly")


def test_the_rule_list_has_one_descriptor_per_rule_and_detector_in_order() -> None:
    rules = driver_rules(document(make_report()))
    assert [rule["id"] for rule in rules] == [info.id for info in INFOS]
    assert len(rules) == len(load_builtin_rules().rules) + len(DETECTOR_INFOS)
    for rule, info in zip(rules, INFOS, strict=True):
        assert list(rule) == [
            "id",
            "name",
            "shortDescription",
            "fullDescription",
            "help",
            "defaultConfiguration",
            "properties",
        ]
        assert rule["shortDescription"] == {"text": info.name}
        assert rule["fullDescription"] == {"text": info.description}
        assert rule["help"]["text"] == sarif.HELP_TEXT  # type: ignore[index]
        assert rule["defaultConfiguration"] == {"level": LEVELS[info.severity]}
        assert rule["properties"]["tags"] == ["security", "secret"]  # type: ignore[index]


# -- the severity mapping -----------------------------------------------------------------------


def test_the_level_table_is_the_one_of_the_plan() -> None:
    assert dict(LEVELS) == {
        Severity.CRITICAL: "error",
        Severity.HIGH: "error",
        Severity.MEDIUM: "warning",
        Severity.LOW: "note",
        Severity.INFO: "note",
    }
    assert dict(SECURITY_SEVERITY) == {
        Severity.CRITICAL: "9.5",
        Severity.HIGH: "8.0",
        Severity.MEDIUM: "5.5",
        Severity.LOW: "2.0",
    }
    assert set(LEVELS) == set(Severity)


@pytest.mark.parametrize("severity", list(Severity))
def test_a_result_level_follows_the_findings_severity(severity: Severity) -> None:
    doc = document(make_report((make_finding(severity=severity),)))
    assert results_of(doc)[0]["level"] == LEVELS[severity]


@pytest.mark.parametrize("severity", list(Severity))
def test_a_rule_descriptor_carries_the_level_and_the_security_severity(
    severity: Severity,
) -> None:
    info = RuleInfo("custom-x", "X", "An X.", Detector.RULE, severity, Confidence.MEDIUM, ("x_",))
    doc = json.loads(render_sarif(make_report(), (info,)))
    (rule,) = driver_rules(doc)
    assert rule["defaultConfiguration"] == {"level": LEVELS[severity]}
    properties = rule["properties"]
    assert isinstance(properties, dict)
    if severity is Severity.INFO:
        assert "security-severity" not in properties
    else:
        assert properties["security-severity"] == SECURITY_SEVERITY[severity]
    assert properties["precision"] == "medium"


@pytest.mark.parametrize("confidence", list(Confidence))
def test_precision_follows_the_rules_default_confidence(confidence: Confidence) -> None:
    info = RuleInfo("custom-x", "X", "An X.", Detector.RULE, Severity.HIGH, confidence, ())
    (rule,) = driver_rules(json.loads(render_sarif(make_report(), (info,))))
    assert rule["properties"]["precision"] == confidence.value  # type: ignore[index]


# -- results ------------------------------------------------------------------------------------


def test_a_result_is_laid_out_field_by_field() -> None:
    finding = make_finding(path="src/app.py", line=3, column=9, fingerprint="a" * 32)
    (result,) = results_of(document(make_report((finding,))))
    index = [info.id for info in INFOS].index("npm-token")
    redacted = f"npm_... [40 chars, sha256:{HASH8}]"
    assert result == {
        "ruleId": "npm-token",
        "ruleIndex": index,
        "level": "error",
        "message": {"text": f"{INFOS[index].name}: {redacted}"},
        "locations": [
            {
                "physicalLocation": {
                    "artifactLocation": {"uri": "src/app.py", "uriBaseId": "%SRCROOT%"},
                    "region": {"startLine": 3, "startColumn": 9, "endColumn": 49},
                }
            }
        ],
        "partialFingerprints": {FINGERPRINT_KEY: "a" * 32},
        "properties": {"confidence": "high", "severity": "high", "redacted": redacted},
    }
    assert FINGERPRINT_KEY == "secretScanner/v1"


def test_the_rule_index_is_the_position_in_the_rule_list() -> None:
    findings = (
        make_finding(rule_id="aws-access-key-id", path="a", fingerprint="1" * 32),
        make_finding(rule_id="npm-token", path="b", fingerprint="2" * 32),
    )
    doc = document(make_report(findings))
    rules = driver_rules(doc)
    for result in results_of(doc):
        index = result["ruleIndex"]
        assert isinstance(index, int)
        assert rules[index]["id"] == result["ruleId"]


def test_a_git_result_carries_its_commit_in_the_properties_and_the_message() -> None:
    report = make_report((make_finding(commit=COMMIT),), target=Target.GIT)
    (result,) = results_of(document(report))
    assert result["properties"]["commit"] == COMMIT  # type: ignore[index]
    assert str(result["message"]["text"]).endswith(" in commit 0123456789ab")  # type: ignore[index]
    assert run_of(document(report))["properties"]["target"] == "git"  # type: ignore[index]


def test_a_directory_result_has_no_commit() -> None:
    (result,) = results_of(document(make_report((make_finding(),))))
    assert "commit" not in result["properties"]  # type: ignore[operator]
    assert "commit" not in str(result["message"])


def test_a_result_for_a_detector_names_the_detector_rule() -> None:
    for info in DETECTOR_INFOS:
        report = make_report((make_finding(rule_id=info.id, path="k.txt"),))
        (result,) = results_of(document(report))
        assert result["ruleId"] == info.id
        assert check_sarif(document(report)) == []


def test_a_result_naming_an_unknown_rule_is_refused() -> None:
    report = make_report((make_finding(rule_id="no-such-rule"),))
    with pytest.raises(ValueError, match="not in the rule list"):
        render_sarif(report, INFOS)


def test_a_repeated_rule_id_is_refused() -> None:
    with pytest.raises(ValueError, match="twice"):
        render_sarif(make_report(), (INFOS[0], INFOS[0]))


def test_the_fingerprint_is_the_only_secret_derived_value_besides_the_redacted_form() -> None:
    (result,) = results_of(document(make_report((make_finding(),))))
    assert result["partialFingerprints"] == {FINGERPRINT_KEY: FINGERPRINT}
    assert set(result["properties"]) == {"confidence", "severity", "redacted"}  # type: ignore[call-overload]


def test_no_key_that_could_carry_source_text_exists_anywhere() -> None:
    report = make_report(
        (make_finding(commit=COMMIT), make_finding(suppressed_by=SuppressedBy.PATH, line=2)),
        issues=(ScanIssue(IssueKind.UNREADABLE, "a.txt", "permission denied"),),
    )
    keys = set(walk_keys(document(report)))
    for forbidden in ("snippet", "contextRegion", "markdown", "codeFlows", "fixes", "value"):
        assert forbidden not in keys


# -- suppressions, issues, run properties -------------------------------------------------------


def test_a_listed_suppressed_finding_carries_a_suppression() -> None:
    report = make_report(
        (
            make_finding(suppressed_by=SuppressedBy.FINGERPRINT, line=1),
            make_finding(suppressed_by=SuppressedBy.PATH, line=2, fingerprint="2" * 32),
            make_finding(line=3, fingerprint="3" * 32),
        ),
        by_fingerprint=1,
        by_path=1,
    )
    first, second, third = results_of(document(report))
    assert first["suppressions"] == [
        {"kind": "external", "justification": sarif.JUSTIFICATIONS["fingerprint"]}
    ]
    assert second["suppressions"] == [
        {"kind": "external", "justification": sarif.JUSTIFICATIONS["path"]}
    ]
    assert "suppressions" not in third
    properties = run_of(document(report))["properties"]
    assert properties["suppressedByFingerprint"] == 1  # type: ignore[index]
    assert properties["suppressedByPath"] == 1  # type: ignore[index]


def test_a_report_without_suppressed_findings_lists_none() -> None:
    doc = document(make_report((make_finding(),), by_fingerprint=3))
    assert all("suppressions" not in result for result in results_of(doc))


def test_issues_become_tool_execution_notifications_and_the_run_is_not_successful() -> None:
    report = make_report(
        issues=(
            ScanIssue(IssueKind.UNREADABLE, "dir/a.txt", "permission denied"),
            ScanIssue(IssueKind.TIME_BUDGET, None, "the time budget was reached"),
        )
    )
    invocation = only_invocation(document(report))
    assert invocation["executionSuccessful"] is False
    assert invocation["toolExecutionNotifications"] == [
        {
            "level": "warning",
            "message": {"text": "dir/a.txt: permission denied"},
            "descriptor": {"id": "unreadable"},
        },
        {
            "level": "warning",
            "message": {"text": "the time budget was reached"},
            "descriptor": {"id": "time_budget"},
        },
    ]


def test_a_complete_run_is_successful_and_has_no_notifications() -> None:
    invocation = only_invocation(document(make_report()))
    assert invocation == {"executionSuccessful": True, "toolExecutionNotifications": []}


def test_the_run_properties_state_completeness_and_the_rules_version() -> None:
    report = make_report(
        target=Target.GIT, history_complete=False, truncated=True, stale=None, complete=False
    )
    assert run_of(document(report))["properties"] == {
        "target": "git",
        "complete": False,
        "truncated": True,
        "historyComplete": False,
        "rulesSha256": "ab" * 32,
        "suppressedByFingerprint": 0,
        "suppressedByPath": 0,
        "stale": None,
        "generatedAt": "2026-01-01T00:00:00Z",
    }


def test_the_output_is_deterministic_ascii_and_newline_terminated() -> None:
    report = make_report((make_finding(path="caf" + chr(0xE9) + "/" + chr(0x4E2D) + ".txt"),))
    text = render_sarif(report, INFOS)
    assert text == render_sarif(report, INFOS)
    assert text.isascii()
    assert text.endswith("\n")
    assert sarif_document(report, INFOS) == json.loads(text)


def test_a_string_that_skipped_the_sanitiser_is_refused() -> None:
    finding = make_finding()
    object.__setattr__(finding, "fingerprint", "bad" + chr(0x1B))
    with pytest.raises(ValueError, match="fingerprint"):
        render_sarif(make_report((finding,)), INFOS)
    bad_rule = dataclasses.replace(INFOS[0], description="x" + chr(0x202E))
    with pytest.raises(ValueError, match="rule description"):
        render_sarif(make_report(), (bad_rule,))
    redacted = Redacted("a", 3, HASH8, "a" + chr(0x7F))
    with pytest.raises(ValueError, match="redacted value"):
        render_sarif(make_report((dataclasses.replace(make_finding(), redacted=redacted),)), INFOS)


# -- URI percent-encoding of hostile names ------------------------------------------------------

HOSTILE_PATHS = [
    "plain/dir/file.txt",
    "with space/and#hash/and?query.txt",
    "percent/%41%2f%2F.txt",
    "colon:name/scheme:x.txt",
    "back" + chr(92) + "slash/name.txt",
    "ctl/" + chr(0x1B) + "[31m" + chr(10) + "x" + chr(13) + chr(9) + ".txt",
    "bidi/" + chr(0x202E) + "gnp.exe" + chr(0x200B),
    "uni/caf" + chr(0xE9) + "/" + chr(0x4E2D) + chr(0x6587) + "/" + chr(0x1F600),
    "raw" + chr(0xDCFF) + "byte/x" + chr(0xDC80),
    "dots/.../..hidden/a..b",
    "at@sign/plus+/amp&/eq=/semi;/comma,/paren(x)/brack[y]/star*/bang!/quote'/dq" + chr(34),
    "trailing space /x",
    "~tilde-ok_1.2",
]


@pytest.mark.parametrize("path_key", HOSTILE_PATHS, ids=range(len(HOSTILE_PATHS)))
def test_an_artifact_uri_is_inert_and_round_trips_to_the_exact_path(path_key: str) -> None:
    uri = artifact_uri(path_key)
    assert URI_REFERENCE.match(uri), "only unreserved characters and %XX"
    assert uri.isascii()
    assert unquote_to_bytes(uri) == path_key.encode("utf-8", errors="surrogateescape")
    assert uri.count("/") == path_key.count("/")
    for forbidden in (":", "?", "#", " ", "\\", "@", "&", "=", ";", ",", "(", ")", "[", "]"):
        assert forbidden not in uri


def test_dot_names_cannot_become_dot_segments() -> None:
    # a file called "..." or ".." inside a directory is an ordinary name; a literal ".." component
    # cannot occur in a relative path the walker produced, and a dot inside a name stays a dot
    assert artifact_uri("a/.../b") == "a/.../b"
    assert artifact_uri("..%2f") == "..%252f"


def test_a_result_uri_is_taken_from_the_exact_path_not_from_the_display_form() -> None:
    path_key = "dir/na" + chr(0x202E) + "me" + chr(0xDCFF) + ".txt"
    finding = make_finding(path=sanitize(path_key), path_key=path_key)
    doc = document(make_report((finding,)))
    (result,) = results_of(doc)
    uri = result["locations"][0]["physicalLocation"]["artifactLocation"]["uri"]  # type: ignore[index]
    assert uri == "dir/na%E2%80%AEme%FF.txt"
    assert check_sarif(doc) == []
    # the display form (with its readable escapes) is nowhere in the document
    assert sanitize(path_key) not in json.dumps(doc)


# -- through the real scan and the CLI ----------------------------------------------------------


def _tree(root: Path, name: str = "settings.txt") -> str:
    rule = next(r for r in load_builtin_rules().rules if r.id == "aws-access-key-id")
    secret = build_fake(rule, "sarif")
    root.mkdir()
    (root / name).write_text(f"aws_key = {secret}\n", encoding="utf-8", newline="\n")
    return secret


def test_the_scan_command_writes_valid_looking_sarif_without_the_secret(
    tmp_path: Path, capsys: pytest.CaptureFixture[str], assert_not_leaked: Callable[..., None]
) -> None:
    secret = _tree(tmp_path / "tree")
    code = cli_main.main(["scan", str(tmp_path / "tree"), "--format", "sarif"])
    captured = capsys.readouterr()
    assert code == 1
    assert_not_leaked(captured.out, secret, allowed_shown=4)
    assert_not_leaked(captured.err, secret, allowed_shown=4)
    doc = json.loads(captured.out)
    assert check_sarif(doc) == []
    (result,) = results_of(doc)
    assert result["ruleId"] == "aws-access-key-id"
    assert result["message"]["text"].startswith("AWS access key id: AKIA... [20 chars, sha256:")  # type: ignore[index]
    assert run_of(doc)["invocations"][0]["executionSuccessful"] is True  # type: ignore[index]


def test_the_scan_command_writes_sarif_to_a_file(
    tmp_path: Path, capsys: pytest.CaptureFixture[str], assert_not_leaked: Callable[..., None]
) -> None:
    secret = _tree(tmp_path / "tree")
    out = tmp_path / "scan.sarif"
    tree = str(tmp_path / "tree")
    assert cli_main.main(["scan", tree, "--format", "sarif", "--output", str(out)]) == 1
    assert capsys.readouterr().out == ""
    data = out.read_bytes()
    assert_not_leaked(data, secret, allowed_shown=4)
    assert check_sarif(json.loads(data)) == []


def test_a_hostile_file_name_is_percent_encoded_in_a_real_scan(tmp_path: Path) -> None:
    name = "we ird#na%41me[x]&y,z;w.txt"
    _tree(tmp_path / "tree", name)
    outcome = run_scan(
        ScanRequest(path=str(tmp_path / "tree"), output_format=OutputFormat.SARIF), FakeClock()
    )
    doc = json.loads(outcome.text)
    (result,) = results_of(doc)
    uri = result["locations"][0]["physicalLocation"]["artifactLocation"]["uri"]  # type: ignore[index]
    assert uri == "we%20ird%23na%2541me%5Bx%5D%26y%2Cz%3Bw.txt"
    assert check_sarif(doc) == []


def test_suppressed_findings_are_listed_with_a_suppression_only_on_request(tmp_path: Path) -> None:
    _tree(tmp_path / "tree")
    baseline = tmp_path / "baseline.yaml"
    base = ScanRequest(path=str(tmp_path / "tree"), output_format=OutputFormat.SARIF)
    run_scan(dataclasses.replace(base, write_baseline=str(baseline)), FakeClock())
    hidden = run_scan(dataclasses.replace(base, baseline=str(baseline)), FakeClock())
    shown = run_scan(
        dataclasses.replace(base, baseline=str(baseline), show_suppressed=True), FakeClock()
    )
    assert hidden.exit_code is ExitCode.OK
    assert results_of(json.loads(hidden.text)) == []
    (result,) = results_of(json.loads(shown.text))
    assert result["suppressions"][0]["kind"] == "external"  # type: ignore[index]
    assert check_sarif(json.loads(shown.text)) == []


def test_configured_extra_rules_appear_in_the_rule_list(tmp_path: Path) -> None:
    rule = {
        "id": "custom-demo",
        "name": "Demo",
        "description": "A demo rule.",
        "regex": "demo_(?P<secret>[A-Za-z0-9]{24})",
        "keywords": ["demo_"],
        "severity": "medium",
        "confidence": "high",
        "shown_chars": 0,
        "min_secret_bits": 100,
        "fake": [{"parts": ["demo", "_"]}, {"charset": "base62", "length": 24}],
    }
    config = tmp_path / "config.yaml"
    config.write_bytes(
        dump_yaml({"version": 1, "extra_rules": [rule], "disable_rules": ["npm-token"]}).encode(
            "ascii"
        )
    )
    tree = tmp_path / "tree"
    tree.mkdir()
    (tree / "a.txt").write_text("x = demo_" + "A1b2C3d4E5f6G7h8I9j0K1l2" + "\n", encoding="utf-8")
    outcome = run_scan(
        ScanRequest(path=str(tree), output_format=OutputFormat.SARIF, config=str(config)),
        FakeClock(),
    )
    doc = json.loads(outcome.text)
    ids = [rule["id"] for rule in driver_rules(doc)]
    assert "custom-demo" in ids
    assert "npm-token" not in ids
    assert ids[-3:] == [info.id for info in DETECTOR_INFOS]
    (result,) = results_of(doc)
    assert result["ruleId"] == "custom-demo"
    index = result["ruleIndex"]
    assert isinstance(index, int)
    assert driver_rules(doc)[index]["id"] == "custom-demo"
    assert check_sarif(doc) == []


def test_a_custom_rule_with_hostile_text_is_escaped_not_refused(tmp_path: Path) -> None:
    """A configuration file can put any text in a rule's name and description. The report shows
    escape sequences for it (the single sanitiser) and is still written."""
    hostile_name = "Demo" + chr(0x1B) + "[31m" + chr(0x202E) + "evil"
    hostile_description = "line one" + chr(10) + "line" + chr(0x200B) + "two" + chr(92)
    rule = {
        "id": "custom-demo",
        "name": hostile_name,
        "description": hostile_description,
        "regex": "demo_(?P<secret>[A-Za-z0-9]{24})",
        "keywords": ["demo_"],
        "severity": "medium",
        "confidence": "high",
        "shown_chars": 0,
        "min_secret_bits": 100,
        "fake": [{"parts": ["demo", "_"]}, {"charset": "base62", "length": 24}],
    }
    config = tmp_path / "config.yaml"
    config.write_bytes(dump_yaml({"version": 1, "extra_rules": [rule]}).encode("ascii"))
    tree = tmp_path / "tree"
    tree.mkdir()
    (tree / "a.txt").write_text("x = demo_" + "A1b2C3d4E5f6G7h8I9j0K1l2" + "\n", encoding="utf-8")
    for output_format in (OutputFormat.SARIF, OutputFormat.JSON, OutputFormat.JSONL):
        request = ScanRequest(path=str(tree), output_format=output_format, config=str(config))
        outcome = run_scan(request, FakeClock())
        assert outcome.exit_code is ExitCode.FINDINGS
        for raw in (chr(0x1B), chr(0x202E), chr(0x200B)):
            assert raw not in outcome.text
    doc = json.loads(
        run_scan(
            ScanRequest(path=str(tree), output_format=OutputFormat.SARIF, config=str(config)),
            FakeClock(),
        ).text
    )
    custom = next(rule for rule in driver_rules(doc) if rule["id"] == "custom-demo")
    assert custom["name"] == sanitize(hostile_name)
    assert custom["fullDescription"] == {"text": sanitize(hostile_description)}
    assert check_sarif(doc) == []
