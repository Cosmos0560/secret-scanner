"""The JSONL renderer: event shape, stable field names, ASCII only, the limits of mini-siem's
generic JSON parser, summary line and hostile names (PLAN.md D11, docs/siem-mapping.md)."""

from __future__ import annotations

import hashlib
import json
from collections.abc import Callable
from dataclasses import replace
from pathlib import Path

import pytest

from secret_scanner.app.scan import ScanRequest, run_scan
from secret_scanner.cli import main as cli_main
from secret_scanner.core.errors import ExitCode
from secret_scanner.core.fakes import build_fake
from secret_scanner.core.models import (
    IssueKind,
    OutputFormat,
    ScanIssue,
    ScanStats,
    Severity,
    SuppressedBy,
    Target,
)
from secret_scanner.core.sanitize import sanitize
from secret_scanner.render import jsonl
from secret_scanner.render.jsonl import (
    EVENT_FINDING,
    EVENT_SUMMARY,
    FINDING_FIELDS,
    SCHEMA,
    SUMMARY_FIELDS,
    TOP_LEVEL_FIELDS,
    jsonl_events,
    render_jsonl,
)
from secret_scanner.services.loader import load_builtin_rules
from tests.helpers import FINGERPRINT, HASH8, FakeClock, make_finding, make_report

# What mini-siem's generic JSON parser does with a line, as recorded in docs/siem-mapping.md
# (src/mini_siem/parsers/jsonlog.py, read on 2026-11-09): these top-level keys are reinterpreted;
# every other key is flattened into an attribute, objects into dotted names up to a depth of 3.
MINI_SIEM_TIME_KEYS = ("timestamp", "@timestamp", "time", "ts", "datetime")
MINI_SIEM_ALIASES = {
    "source_ip": ("source_ip", "src_ip", "client_ip", "remote_addr", "remote_ip", "ip"),
    "user_name": ("user_name", "username", "user", "account"),
    "message": ("message", "msg", "log", "event"),
    "host": ("host", "hostname"),
    "user_agent": ("user_agent", "useragent", "ua", "http_user_agent"),
    "url_path": ("url_path", "url", "path", "uri", "request_uri"),
    "http_method": ("http_method", "method"),
    "http_status": ("http_status", "status", "status_code"),
    "process_name": ("process_name", "process", "program", "app"),
}
MINI_SIEM_MAX_ATTRS = 64
MINI_SIEM_MAX_ATTR_KEY_CHARS = 64
MINI_SIEM_MAX_ATTR_VALUE_CHARS = 1_024
MINI_SIEM_MAX_MESSAGE_CHARS = 4_096
MINI_SIEM_MAX_HOST_CHARS = 255
MINI_SIEM_MAX_LINE_BYTES = 65_536
MINI_SIEM_MAX_DEPTH = 3

RLO = chr(0x202E)  # right-to-left override
ZERO_WIDTH_SPACE = chr(0x200B)
ACCENTED = chr(0xE9)
CJK = chr(0x4E2D)
EMOJI = chr(0x1F600)
HOSTILE_NAME = "dir\x1b[31m\nname" + RLO + "evil" + ZERO_WIDTH_SPACE + "\r.txt\\x" + chr(0xDCFF)
HOSTILE_SHOWN = sanitize(HOSTILE_NAME)


def parse(text: str) -> list[dict[str, object]]:
    return [json.loads(line) for line in text.splitlines()]


def secret_of(event: dict[str, object]) -> dict[str, object]:
    inner = event["secret"]
    assert isinstance(inner, dict)
    return inner


def flatten(document: dict[str, object]) -> dict[str, str]:
    """mini-siem's attribute flattening (scalars to text, nulls dropped, objects to dotted keys)."""
    consumed = {"event_type", *MINI_SIEM_TIME_KEYS[:1]}
    attrs: dict[str, str] = {}

    def walk(obj: dict[str, object], prefix: str, depth: int) -> None:
        for key, value in obj.items():
            name = f"{prefix}{key}"
            if isinstance(value, dict) and depth < MINI_SIEM_MAX_DEPTH:
                walk(value, f"{name}.", depth + 1)
            elif isinstance(value, bool):
                attrs[name] = "true" if value else "false"
            elif isinstance(value, str | int | float):
                attrs[name] = str(value)

    rest = {k: v for k, v in document.items() if k not in consumed}
    for names in MINI_SIEM_ALIASES.values():
        for name in names:
            if name in rest:
                rest.pop(name)
                break
    walk(rest, "", 1)
    return attrs


def sample_report() -> object:
    return make_report(
        (
            make_finding(path="src/app.py", fingerprint="a" * 32),
            make_finding(
                rule_id="aws-access-key-id",
                path="conf/.env",
                line=1,
                column=5,
                severity=Severity.CRITICAL,
                fingerprint="b" * 32,
                commit="0123456789abcdef0123456789abcdef01234567",
            ),
        ),
        by_fingerprint=1,
    )


# -- shape ------------------------------------------------------------------------------------


def test_one_line_per_finding_then_one_summary_line() -> None:
    report = sample_report()
    text = render_jsonl(report, "ci-host")  # type: ignore[arg-type]
    events = parse(text)
    assert [event["event_type"] for event in events] == [
        EVENT_FINDING,
        EVENT_FINDING,
        EVENT_SUMMARY,
    ]
    assert text.endswith("\n")
    assert text.count("\n") == 3
    assert "\r" not in text


def test_the_top_level_keys_and_the_finding_keys_are_the_documented_ones_in_order() -> None:
    events = parse(render_jsonl(sample_report(), "h"))  # type: ignore[arg-type]
    for event in events:
        assert tuple(event) == TOP_LEVEL_FIELDS
    assert tuple(secret_of(events[0])) == FINDING_FIELDS
    assert tuple(secret_of(events[-1])) == SUMMARY_FIELDS


def test_a_finding_event_carries_the_redacted_form_and_location_but_no_snippet() -> None:
    report = make_report((make_finding(path="src/app.py", line=3, column=9, fingerprint="a" * 32),))
    event = parse(render_jsonl(report, "ci-host"))[0]
    secret = event["secret"]
    assert event["timestamp"] == "2026-01-01T00:00:00Z"
    assert event["host"] == "ci-host"
    assert event["event_type"] == "secret.finding"
    assert event["message"] == f"npm-token: npm_... [40 chars, sha256:{HASH8}] at src/app.py:3:9"
    assert secret == {
        "rule_id": "npm-token",
        "detector": "rule",
        "severity": "high",
        "confidence": "high",
        "file": "src/app.py",
        "file_sha256": hashlib.sha256(b"src/app.py").hexdigest(),
        "file_truncated": False,
        "line": 3,
        "column": 9,
        "commit": None,
        "commit_time": None,
        "redacted": f"npm_... [40 chars, sha256:{HASH8}]",
        "secret_length": 40,
        "secret_hash8": HASH8,
        "fingerprint": "a" * 32,
        "target": "fs",
        "tool_version": "0.1.0",
        "schema": SCHEMA,
        "suppressed_by": None,
    }


def test_a_git_finding_names_its_commit_in_the_fields_and_the_message() -> None:
    commit = "0123456789abcdef0123456789abcdef01234567"
    report = make_report((make_finding(commit=commit),), target=Target.GIT)
    event = parse(render_jsonl(report, "h"))[0]
    assert event["secret"]["commit"] == commit  # type: ignore[index]
    assert event["secret"]["commit_time"] == 1_700_000_000  # type: ignore[index]
    assert event["secret"]["target"] == "git"  # type: ignore[index]
    assert str(event["message"]).endswith(" in commit 0123456789ab")


def test_a_suppressed_finding_is_marked_in_the_field_and_the_message() -> None:
    report = make_report(
        (make_finding(suppressed_by=SuppressedBy.PATH), make_finding(line=9, fingerprint="c" * 32)),
        by_path=1,
    )
    first, second, summary = parse(render_jsonl(report, "h"))
    assert first["secret"]["suppressed_by"] == "path"  # type: ignore[index]
    assert str(first["message"]).endswith("(suppressed by path)")
    assert second["secret"]["suppressed_by"] is None  # type: ignore[index]
    assert summary["secret"]["findings"] == 1  # type: ignore[index]
    assert summary["secret"]["suppressed_by_path"] == 1  # type: ignore[index]


def test_the_output_is_deterministic() -> None:
    report = sample_report()
    assert render_jsonl(report, "h") == render_jsonl(report, "h")  # type: ignore[arg-type]


# -- the summary line -------------------------------------------------------------------------


def test_an_empty_report_is_one_summary_line() -> None:
    text = render_jsonl(make_report(), "h")
    (summary,) = parse(text)
    assert summary["event_type"] == EVENT_SUMMARY
    assert summary["message"] == "secret-scanner directory scan complete: 0 finding(s), 0 issue(s)"
    assert summary["secret"]["findings"] == 0  # type: ignore[index]
    assert summary["secret"]["complete"] is True  # type: ignore[index]


def test_the_summary_counts_by_severity_and_states_an_incomplete_run() -> None:
    report = make_report(
        (
            make_finding(severity=Severity.CRITICAL, fingerprint="1" * 32),
            make_finding(severity=Severity.CRITICAL, line=4, fingerprint="2" * 32),
            make_finding(severity=Severity.LOW, line=5, fingerprint="3" * 32),
            make_finding(
                severity=Severity.HIGH,
                line=6,
                fingerprint="4" * 32,
                suppressed_by=SuppressedBy.FINGERPRINT,
            ),
        ),
        issues=(ScanIssue(IssueKind.UNREADABLE, "a.txt", "permission denied"),),
        stats=ScanStats(files_seen=9, files_scanned=7, commits=5),
        target=Target.GIT,
        target_display="repo",
        stale=None,
        history_complete=False,
        truncated=True,
        by_fingerprint=1,
    )
    summary = parse(render_jsonl(report, "h"))[-1]
    assert summary["message"] == "secret-scanner history scan INCOMPLETE: 3 finding(s), 1 issue(s)"
    assert summary["secret"] == {
        "target": "git",
        "target_path": "repo",
        "target_path_truncated": False,
        "findings": 3,
        "findings_critical": 2,
        "findings_high": 0,
        "findings_medium": 0,
        "findings_low": 1,
        "findings_info": 0,
        "suppressed_by_fingerprint": 1,
        "suppressed_by_path": 0,
        "stale": None,
        "issues": 1,
        "complete": False,
        "truncated": True,
        "history_complete": False,
        "files_seen": 9,
        "files_scanned": 7,
        "commits": 5,
        "rules_sha256": "ab" * 32,
        "tool_version": "0.1.0",
        "schema": SCHEMA,
    }


# -- ASCII, hostile names and limits ------------------------------------------------------------


def test_the_output_is_ascii_only_and_free_of_control_characters() -> None:
    report = make_report(
        (make_finding(path=HOSTILE_SHOWN + ACCENTED + CJK + EMOJI),),
        target_display=HOSTILE_SHOWN + ACCENTED,
    )
    text = render_jsonl(report, "h" + ACCENTED)
    data = text.encode("ascii")  # raises on any non-ASCII byte
    assert all(byte >= 0x20 or byte == 0x0A for byte in data)
    event = parse(text)[0]
    assert event["secret"]["file"] == HOSTILE_SHOWN + ACCENTED + CJK + EMOJI  # type: ignore[index]
    assert event["host"] == "h" + ACCENTED


def test_a_name_that_skipped_the_sanitiser_is_refused() -> None:
    finding = make_finding()
    object.__setattr__(finding.location, "path", "bad\x1b[31mname")
    with pytest.raises(ValueError, match="location path"):
        render_jsonl(make_report((finding,)), "h")
    with pytest.raises(ValueError, match="host label"):
        render_jsonl(make_report(), "bad\nhost")


def test_a_long_path_is_cut_whole_escapes_only_and_the_hash_covers_the_full_path() -> None:
    full = sanitize(RLO * 600 + "tail")  # 600 six-character escapes
    assert len(full) > 3_000
    report = make_report((make_finding(path=full),), target_display=full)
    event = parse(render_jsonl(report, "h"))[0]
    secret = event["secret"]
    shown = secret["file"]  # type: ignore[index]
    assert len(shown) <= jsonl.MAX_FILE_CHARS
    assert secret["file_truncated"] is True  # type: ignore[index]
    assert full.startswith(shown)
    assert shown.endswith("\\u202e")  # no escape was cut in half
    assert (len(shown) // 6) * 6 == len(shown)
    assert secret["file_sha256"] == hashlib.sha256(full.encode("utf-8")).hexdigest()  # type: ignore[index]
    summary = parse(render_jsonl(report, "h"))[-1]
    assert summary["secret"]["target_path_truncated"] is True  # type: ignore[index]
    assert len(summary["secret"]["target_path"]) <= jsonl.MAX_FILE_CHARS  # type: ignore[index]


def test_every_value_and_the_line_stay_within_the_limits_of_mini_siem() -> None:
    commit = "f" * 64  # a SHA-256 repository
    report = make_report(
        (
            make_finding(path=sanitize(RLO * 700), commit=commit),
            make_finding(path="a" * 4_000, line=2, commit=commit, fingerprint="9" * 32),
        ),
        target=Target.GIT,
        target_display="r" * 4_000,
        history_complete=True,
    )
    text = render_jsonl(report, "h" * MINI_SIEM_MAX_HOST_CHARS)
    for line in text.splitlines():
        assert len(line.encode("ascii")) <= MINI_SIEM_MAX_LINE_BYTES
        document = json.loads(line)
        assert len(document["host"]) <= MINI_SIEM_MAX_HOST_CHARS
        assert len(document["message"]) <= MINI_SIEM_MAX_ATTR_VALUE_CHARS
        assert len(document["message"]) <= MINI_SIEM_MAX_MESSAGE_CHARS
        attrs = flatten(document)
        assert len(attrs) + 1 <= MINI_SIEM_MAX_ATTRS  # +1: declared_event_type
        for key, value in attrs.items():
            assert 0 < len(key) <= MINI_SIEM_MAX_ATTR_KEY_CHARS
            assert len(value) <= MINI_SIEM_MAX_ATTR_VALUE_CHARS, key


def test_no_top_level_key_is_one_that_mini_siem_would_reinterpret() -> None:
    reinterpreted = set(MINI_SIEM_TIME_KEYS)
    for names in MINI_SIEM_ALIASES.values():
        reinterpreted.update(names)
    reinterpreted.add("event_type")
    intended = {"timestamp", "host", "message", "event_type"}
    for key in TOP_LEVEL_FIELDS:
        assert key in intended or key not in reinterpreted, key
    # in particular never a top-level path, url, user, ip or status
    for forbidden in ("path", "url", "uri", "user", "ip", "status", "method", "process", "app"):
        assert forbidden not in TOP_LEVEL_FIELDS


def test_every_finding_field_flattens_to_a_plain_attribute() -> None:
    attrs = flatten(parse(render_jsonl(sample_report(), "h"))[0])  # type: ignore[arg-type]
    # nulls are dropped by mini-siem; everything else becomes secret.<field>
    assert set(attrs) == {f"secret.{name}" for name in FINDING_FIELDS} - {
        "secret.commit",
        "secret.commit_time",
        "secret.suppressed_by",
    }
    assert attrs["secret.file_truncated"] == "false"
    assert attrs["secret.line"] == "3"


def test_the_fingerprint_and_hash_are_the_only_secret_derived_values() -> None:
    event = parse(render_jsonl(make_report((make_finding(),)), "h"))[0]
    secret = event["secret"]
    assert secret["fingerprint"] == FINGERPRINT  # type: ignore[index]
    assert secret["secret_hash8"] == HASH8  # type: ignore[index]
    assert jsonl_events(make_report((make_finding(),)), "h")[0] == event


# -- through the real scan and the CLI ----------------------------------------------------------


def _planted_tree(root: Path) -> str:
    """A directory with one generated fake AWS key id; returns the fake."""
    rule = next(r for r in load_builtin_rules().rules if r.id == "aws-access-key-id")
    secret = build_fake(rule, "jsonl")
    root.mkdir()
    (root / "settings.txt").write_text(f"aws_key = {secret}\n", encoding="utf-8", newline="\n")
    return secret


def test_the_scan_command_writes_jsonl_to_stdout_without_the_secret(
    tmp_path: Path, capsys: pytest.CaptureFixture[str], assert_not_leaked: Callable[..., None]
) -> None:
    secret = _planted_tree(tmp_path / "tree")
    code = cli_main.main(
        ["scan", str(tmp_path / "tree"), "--format", "jsonl", "--host-label", "ci-host"]
    )
    captured = capsys.readouterr()
    assert code == 1
    assert_not_leaked(captured.out, secret, allowed_shown=4)
    assert_not_leaked(captured.err, secret, allowed_shown=4)
    finding, summary = parse(captured.out)
    assert finding["event_type"] == EVENT_FINDING
    assert finding["host"] == "ci-host"
    assert finding["secret"]["rule_id"] == "aws-access-key-id"  # type: ignore[index]
    assert finding["secret"]["file"] == "settings.txt"  # type: ignore[index]
    assert finding["secret"]["redacted"].startswith("AKIA... [20 chars, sha256:")  # type: ignore[index]
    assert summary["secret"]["findings"] == 1  # type: ignore[index]
    assert summary["secret"]["complete"] is True  # type: ignore[index]
    captured.out.encode("ascii")


def test_the_scan_command_writes_jsonl_to_a_file(
    tmp_path: Path, capsys: pytest.CaptureFixture[str], assert_not_leaked: Callable[..., None]
) -> None:
    secret = _planted_tree(tmp_path / "tree")
    out = tmp_path / "events.jsonl"
    code = cli_main.main(
        ["scan", str(tmp_path / "tree"), "--format", "jsonl", "--output", str(out)]
    )
    captured = capsys.readouterr()
    assert code == 1
    assert captured.out == ""
    written = out.read_bytes()
    assert written.endswith(b"\n")
    assert_not_leaked(written, secret, allowed_shown=4)
    assert len(parse(written.decode("ascii"))) == 2


def test_a_suppressed_finding_is_listed_only_with_show_suppressed(tmp_path: Path) -> None:
    _planted_tree(tmp_path / "tree")
    baseline = tmp_path / "baseline.yaml"
    run = ScanRequest(path=str(tmp_path / "tree"), output_format=OutputFormat.JSONL)
    first = run_scan(replace(run, write_baseline=str(baseline)), FakeClock())
    assert first.exit_code is ExitCode.FINDINGS
    hidden = run_scan(replace(run, baseline=str(baseline)), FakeClock())
    shown = run_scan(replace(run, baseline=str(baseline), show_suppressed=True), FakeClock())
    assert hidden.exit_code is ExitCode.OK
    assert [e["event_type"] for e in parse(hidden.text)] == [EVENT_SUMMARY]
    events = parse(shown.text)
    assert [e["event_type"] for e in events] == [EVENT_FINDING, EVENT_SUMMARY]
    assert events[0]["secret"]["suppressed_by"] == "fingerprint"  # type: ignore[index]
    assert events[1]["secret"]["findings"] == 0  # type: ignore[index]
    assert events[1]["secret"]["suppressed_by_fingerprint"] == 1  # type: ignore[index]
