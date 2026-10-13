"""Models: ordering of vocabularies, validation, and the structural proof that nothing reachable
from a Report can hold a secret (PLAN.md section 2)."""

from __future__ import annotations

import dataclasses
import re
import types
import typing
from typing import Any

import pytest

from secret_scanner.core import models
from secret_scanner.core.models import (
    Confidence,
    Detector,
    Finding,
    IssueKind,
    Location,
    Redacted,
    Report,
    ScanIssue,
    ScanStats,
    Severity,
    SuppressedBy,
    Target,
)


def test_severity_order_and_at_least() -> None:
    order = [Severity.INFO, Severity.LOW, Severity.MEDIUM, Severity.HIGH, Severity.CRITICAL]
    assert list(Severity) == order
    assert [severity.rank for severity in order] == [0, 1, 2, 3, 4]
    assert Severity.CRITICAL.at_least(Severity.LOW)
    assert Severity.LOW.at_least(Severity.LOW)
    assert not Severity.LOW.at_least(Severity.HIGH)


def test_confidence_order_and_at_least() -> None:
    assert list(Confidence) == [Confidence.LOW, Confidence.MEDIUM, Confidence.HIGH]
    assert Confidence.HIGH.at_least(Confidence.MEDIUM)
    assert not Confidence.LOW.at_least(Confidence.MEDIUM)


def test_vocabularies_use_their_documented_values() -> None:
    assert [d.value for d in Detector] == ["rule", "entropy", "private_key"]
    assert [t.value for t in Target] == ["fs", "git"]
    assert [s.value for s in SuppressedBy] == ["fingerprint", "path"]
    assert {kind.value for kind in IssueKind} == {
        "unreadable",
        "vanished",
        "unstable",
        "too_large",
        "line_too_long",
        "undecodable",
        "limit_reached",
        "time_budget",
        "missing_object",
        "shallow_history",
        "findings_cap",
    }


def test_redacted_validates_its_hash_and_length() -> None:
    assert Redacted(shown="", length=3, hash8="0123abcd", text="t").length == 3
    for bad_hash in ("0123abc", "0123ABCD", "0123abcg", ""):
        with pytest.raises(ValueError, match="hash8"):
            Redacted(shown="", length=1, hash8=bad_hash, text="t")
    with pytest.raises(ValueError, match="length"):
        Redacted(shown="", length=-1, hash8="0123abcd", text="t")


def test_location_validates_line_and_columns() -> None:
    location = Location(path_key="a/b", path="a/b", line=1, column=2, end_column=5)
    assert (location.commit, location.commit_time) == (None, None)
    for line, column, end in [(0, 1, 1), (1, 0, 1), (1, 5, 4)]:
        with pytest.raises(ValueError, match="1-based"):
            Location(path_key="p", path="p", line=line, column=column, end_column=end)


def test_models_are_frozen() -> None:
    stats = ScanStats()
    with pytest.raises(dataclasses.FrozenInstanceError):
        stats.files_seen = 1  # type: ignore[misc]  # the point of the test: assignment must fail


def _annotation_types(annotation: Any) -> list[Any]:
    """Flatten an annotation into the concrete types it mentions."""
    origin = typing.get_origin(annotation)
    if origin in (typing.Union, types.UnionType) or origin is not None:
        found: list[Any] = []
        for argument in typing.get_args(annotation):
            found.extend(_annotation_types(argument))
        return found
    return [annotation]


def _reachable_dataclasses(root: type) -> dict[str, type]:
    seen: dict[str, type] = {}
    pending = [root]
    while pending:
        current = pending.pop()
        if current.__name__ in seen:
            continue
        seen[current.__name__] = current
        hints = typing.get_type_hints(current)
        for field in dataclasses.fields(current):
            for found in _annotation_types(hints[field.name]):
                if isinstance(found, type) and dataclasses.is_dataclass(found):
                    pending.append(found)
    return seen


SECRET_LIKE_NAMES = re.compile(r"secret|value|password|token|plaintext|credential", re.IGNORECASE)
FORBIDDEN_TYPES = (bytes, bytearray, memoryview)


def secret_holding_fields(root: type) -> list[str]:
    """Every `Class.field` reachable from `root` that is named like a secret or typed as bytes."""
    problems: list[str] = []
    for name, cls in _reachable_dataclasses(root).items():
        hints = typing.get_type_hints(cls)
        for field in dataclasses.fields(cls):
            if SECRET_LIKE_NAMES.search(field.name):
                problems.append(f"{name}.{field.name}: named like a secret")
            for found in _annotation_types(hints[field.name]):
                if found in FORBIDDEN_TYPES:
                    problems.append(f"{name}.{field.name}: holds {found.__name__}")
    return problems


@dataclasses.dataclass
class _Leaky:
    secret: bytes
    note: str


@dataclasses.dataclass
class _Holder:
    inner: _Leaky
    items: tuple[_Leaky, ...]


def test_nothing_reachable_from_report_can_hold_a_secret() -> None:
    reachable = _reachable_dataclasses(Report)
    assert {"Report", "Finding", "Redacted", "Location", "ScanIssue", "ScanStats"} <= set(reachable)
    assert secret_holding_fields(Report) == []


def test_type_walk_detects_a_secret_holding_field() -> None:
    assert secret_holding_fields(_Holder) == [
        "_Leaky.secret: named like a secret",
        "_Leaky.secret: holds bytes",
    ]


def test_finding_and_report_construction() -> None:
    location = Location(path_key="p", path="p", line=1, column=1, end_column=2)
    redacted = Redacted(shown="", length=8, hash8="00000000", text="[8 chars, sha256:00000000]")
    finding = Finding(
        rule_id="r",
        detector=Detector.RULE,
        severity=Severity.HIGH,
        confidence=Confidence.HIGH,
        location=location,
        redacted=redacted,
        fingerprint="f" * 32,
    )
    assert finding.suppressed_by is None
    report = Report(
        target=Target.FS,
        target_display="x",
        findings=(finding,),
        suppressed_by_fingerprint=0,
        suppressed_by_path=0,
        stale=None,
        issues=(ScanIssue(IssueKind.TOO_LARGE, "big.bin", "over the file size limit"),),
        stats=ScanStats(),
        complete=False,
        truncated=False,
        rules_sha256="0" * 64,
        generated_at="2026-01-01T00:00:00Z",
        tool_version="0.1.0",
    )
    assert report.history_complete is None
    assert models.Suppressions().entries == ()


def test_display_text_must_be_escaped_at_construction() -> None:
    from secret_scanner.core.models import IssueKind, ScanIssue

    with pytest.raises(ValueError, match=r"Location\.path"):
        Location(path_key="p", path="bad\nname", line=1, column=1, end_column=2)
    with pytest.raises(ValueError, match="ScanIssue"):
        ScanIssue(kind=IssueKind.UNREADABLE, path="bad" + chr(0x1B), detail="d")
    with pytest.raises(ValueError, match="ScanIssue"):
        ScanIssue(kind=IssueKind.UNREADABLE, path=None, detail="bad" + chr(0x1B))
    assert ScanIssue(kind=IssueKind.UNREADABLE, path=None, detail="ok").path is None
    escaped = Location(path_key="a\nb", path="a\\nb", line=1, column=1, end_column=2)
    assert escaped.path == "a\\nb"


def test_report_target_display_must_be_escaped() -> None:
    kwargs = {
        "target": Target.FS,
        "findings": (),
        "suppressed_by_fingerprint": 0,
        "suppressed_by_path": 0,
        "stale": None,
        "issues": (),
        "stats": ScanStats(),
        "complete": True,
        "truncated": False,
        "rules_sha256": "0" * 64,
        "generated_at": "2026-01-01T00:00:00Z",
        "tool_version": "0.1.0",
    }
    assert Report(target_display="dir/ok", **kwargs).target_display == "dir/ok"  # type: ignore[arg-type]
    with pytest.raises(ValueError, match="target_display"):
        Report(target_display="bad\nname", **kwargs)  # type: ignore[arg-type]


def test_output_formats_are_the_documented_ones() -> None:
    from secret_scanner.core.models import OutputFormat

    assert [fmt.value for fmt in OutputFormat] == ["table", "json"]  # jsonl, sarif: Phase 5
