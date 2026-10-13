"""Baseline (suppression file) schema, matching and stale counting (PLAN.md D9). Pure.

A baseline suppresses a finding in one of two ways: its fingerprint is listed (and, when the entry
names a rule, the rule agrees), or its path matches one of the `paths` globs. A finding that
matches both is counted under the fingerprint. An entry is stale when no finding detected in the
run has its fingerprint; staleness is only judged by the caller for a complete run.

The document parsed here is plain data from the strict YAML loader: unknown keys, wrong types,
malformed fingerprints, duplicates and more than `MAX_BASELINE_ENTRIES` entries are refused with
`ConfigError`, never ignored.
"""

from __future__ import annotations

from collections.abc import Iterable, Mapping, Sequence
from dataclasses import dataclass, replace

from secret_scanner.core.errors import ConfigError, unknown_key_error
from secret_scanner.core.globs import any_match, compile_globs
from secret_scanner.core.limits import DEFAULT_LIMITS, MAX_PATH_CHARS, Limits
from secret_scanner.core.models import (
    Finding,
    SuppressedBy,
    SuppressionEntry,
    Suppressions,
)
from secret_scanner.core.rules import is_kebab_case

BASELINE_VERSION = 1
FINGERPRINT_CHARS = 32
MAX_REASON_CHARS = 512
DEFAULT_REASON = "TODO: review"
_HEX = frozenset("0123456789abcdef")
_ENTRY_KEYS = frozenset({"fingerprint", "rule", "path", "reason"})
_TOP_KEYS = frozenset({"version", "suppress", "paths"})


@dataclass(frozen=True, slots=True)
class SuppressionResult:
    """Findings split by the baseline. `suppressed` carries `suppressed_by`."""

    reported: tuple[Finding, ...]
    suppressed: tuple[Finding, ...]
    by_fingerprint: int
    by_path: int


def _text(value: object, where: str, *, maximum: int) -> str:
    if not isinstance(value, str):
        raise ConfigError(f"{where}: must be a string")
    if len(value) > maximum:
        raise ConfigError(f"{where}: longer than {maximum} characters")
    if any(ord(char) < 0x20 or ord(char) == 0x7F for char in value):
        raise ConfigError(f"{where}: contains a control character")
    return value


def _optional_text(entry: Mapping[str, object], key: str, where: str, maximum: int) -> str | None:
    value = entry.get(key)
    if value is None:
        return None
    return _text(value, f"{where}.{key}", maximum=maximum)


def _entry(item: object, where: str) -> SuppressionEntry:
    if not isinstance(item, dict):
        raise ConfigError(f"{where}: must be a mapping")
    if any(key not in _ENTRY_KEYS for key in item):
        raise unknown_key_error(where, _ENTRY_KEYS)
    if "fingerprint" not in item:
        raise ConfigError(f"{where}: missing key 'fingerprint'")
    fingerprint = item["fingerprint"]
    if (
        not isinstance(fingerprint, str)
        or len(fingerprint) != FINGERPRINT_CHARS
        or not set(fingerprint) <= _HEX
    ):
        raise ConfigError(f"{where}.fingerprint: must be {FINGERPRINT_CHARS} lower-case hex digits")
    rule = _optional_text(item, "rule", where, 64)
    if rule is not None and not is_kebab_case(rule):
        raise ConfigError(f"{where}.rule: must be a kebab-case rule id")
    return SuppressionEntry(
        fingerprint=fingerprint,
        rule=rule,
        path=_optional_text(item, "path", where, MAX_PATH_CHARS),
        reason=_optional_text(item, "reason", where, MAX_REASON_CHARS),
    )


def parse_baseline(data: object, limits: Limits = DEFAULT_LIMITS) -> Suppressions:
    """Validate a parsed baseline document and return it as `Suppressions`."""
    if not isinstance(data, dict):
        raise ConfigError("baseline: must be a mapping")
    if any(key not in _TOP_KEYS for key in data):
        raise unknown_key_error("baseline", _TOP_KEYS)
    version = data.get("version")
    if isinstance(version, bool) or version != BASELINE_VERSION:
        raise ConfigError(f"baseline: version must be {BASELINE_VERSION}")
    raw_entries = data.get("suppress", [])
    if raw_entries is None:
        raw_entries = []
    if not isinstance(raw_entries, list):
        raise ConfigError("baseline.suppress: must be a list")
    if len(raw_entries) > limits.max_baseline_entries:
        raise ConfigError(f"baseline.suppress: more than {limits.max_baseline_entries} entries")
    entries: list[SuppressionEntry] = []
    seen: set[str] = set()
    for index, item in enumerate(raw_entries):
        entry = _entry(item, f"baseline.suppress[{index}]")
        if entry.fingerprint in seen:
            raise ConfigError(f"baseline.suppress[{index}]: duplicate fingerprint")
        seen.add(entry.fingerprint)
        entries.append(entry)
    raw_paths = data.get("paths", [])
    if raw_paths is None:
        raw_paths = []
    if not isinstance(raw_paths, list):
        raise ConfigError("baseline.paths: must be a list")
    # Compiling validates every glob and the count bound; the source strings are what we keep.
    compile_globs(
        [_text(p, "baseline.paths[]", maximum=limits.max_glob_chars) for p in raw_paths],
        limits,
        what="baseline.paths",
    )
    return Suppressions(entries=tuple(entries), paths=tuple(str(p) for p in raw_paths))


def apply_suppressions(
    findings: Sequence[Finding], suppressions: Suppressions, limits: Limits = DEFAULT_LIMITS
) -> SuppressionResult:
    """Split `findings` into reported and suppressed ones (order preserved)."""
    by_print: dict[str, SuppressionEntry] = {e.fingerprint: e for e in suppressions.entries}
    globs = compile_globs(suppressions.paths, limits, what="baseline.paths")
    reported: list[Finding] = []
    suppressed: list[Finding] = []
    by_fingerprint = 0
    by_path = 0
    for finding in findings:
        entry = by_print.get(finding.fingerprint)
        if entry is not None and (entry.rule is None or entry.rule == finding.rule_id):
            suppressed.append(replace(finding, suppressed_by=SuppressedBy.FINGERPRINT))
            by_fingerprint += 1
        elif any_match(globs, finding.location.path_key):
            suppressed.append(replace(finding, suppressed_by=SuppressedBy.PATH))
            by_path += 1
        else:
            reported.append(finding)
    return SuppressionResult(tuple(reported), tuple(suppressed), by_fingerprint, by_path)


def count_stale(entries: Iterable[SuppressionEntry], detected: Iterable[Finding]) -> int:
    """Entries that no detected finding matches (same fingerprint and, when named, same rule)."""
    present: dict[str, set[str]] = {}
    for finding in detected:
        present.setdefault(finding.fingerprint, set()).add(finding.rule_id)
    stale = 0
    for entry in entries:
        rules = present.get(entry.fingerprint)
        if rules is None or (entry.rule is not None and entry.rule not in rules):
            stale += 1
    return stale


def baseline_document(
    findings: Iterable[Finding],
    *,
    paths: Sequence[str] = (),
    reason: str = DEFAULT_REASON,
    reasons: Mapping[str, str] | None = None,
) -> dict[str, object]:
    """Plain data for a baseline that suppresses `findings`: one entry per fingerprint, sorted by
    path, rule and fingerprint so the file is stable and reviewable. The path is the escaped
    display form (informational; matching is by fingerprint). `reasons` maps a fingerprint to the
    reason a person already wrote for it, so refreshing a baseline keeps reviewed text; other
    entries get `reason`."""
    known = reasons or {}
    unique: dict[str, Finding] = {}
    for finding in findings:
        unique.setdefault(finding.fingerprint, finding)
    ordered = sorted(unique.values(), key=lambda f: (f.location.path_key, f.rule_id, f.fingerprint))
    return {
        "version": BASELINE_VERSION,
        "suppress": [
            {
                "fingerprint": finding.fingerprint,
                "rule": finding.rule_id,
                "path": finding.location.path,
                "reason": known.get(finding.fingerprint) or reason,
            }
            for finding in ordered
        ],
        "paths": list(paths),
    }
