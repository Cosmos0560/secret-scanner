"""The `rules` listing: every rule's id, name, detector, severity, confidence, description and
pre-filter keywords, as a table or as one JSON document, schema `secret-rules/1` (PLAN.md D4).

The input is `RuleInfo`, which has no pattern and no fake specification, so nothing here can print
an example of a secret. Strings are checked with `require_display_safe` like every other renderer's.
"""

from __future__ import annotations

import json
from collections.abc import Sequence

from secret_scanner.core.ruleinfo import RuleInfo
from secret_scanner.core.sanitize import require_display_safe

SCHEMA = "secret-rules/1"
TOOL_NAME = "secret-scanner"
RULE_FIELDS = (
    "id",
    "name",
    "detector",
    "severity",
    "confidence",
    "description",
    "keywords",
)
_HEADERS = ("ID", "SEVERITY", "CONFIDENCE", "DETECTOR", "KEYWORDS")
NO_KEYWORDS = "(none: runs on every line)"


def _text(value: str, what: str) -> str:
    return require_display_safe(value, what)


def _rule(info: RuleInfo) -> dict[str, object]:
    return {
        "id": _text(info.id, "rule id"),
        "name": _text(info.name, "rule name"),
        "detector": info.detector.value,
        "severity": info.severity.value,
        "confidence": info.confidence.value,
        "description": _text(info.description, "rule description"),
        "keywords": [_text(keyword, "keyword") for keyword in info.keywords],
    }


def rules_document(
    infos: Sequence[RuleInfo], *, version: str, rules_sha256: str
) -> dict[str, object]:
    """The listing as plain data, in the key order of the schema."""
    return {
        "schema": SCHEMA,
        "tool": {"name": TOOL_NAME, "version": _text(version, "tool version")},
        "rules_sha256": _text(rules_sha256, "rules hash"),
        "rules": [_rule(info) for info in infos],
    }


def render_rules_json(infos: Sequence[RuleInfo], *, version: str, rules_sha256: str) -> str:
    """The listing as one ASCII-only JSON document followed by a newline."""
    document = rules_document(infos, version=version, rules_sha256=rules_sha256)
    return json.dumps(document, ensure_ascii=True, indent=2, allow_nan=False) + "\n"


def render_rules_table(infos: Sequence[RuleInfo], *, version: str, rules_sha256: str) -> str:
    """One row per rule with its description on the next line, then a note on what is not shown."""
    rows = [
        (
            _text(info.id, "rule id"),
            info.severity.value,
            info.confidence.value,
            info.detector.value,
            ", ".join(_text(keyword, "keyword") for keyword in info.keywords) or NO_KEYWORDS,
        )
        for info in infos
    ]
    widths = [max(len(_HEADERS[i]), *(len(row[i]) for row in rows)) for i in range(4)]
    lines = [
        f"secret-scanner {_text(version, 'tool version')} - {len(infos)} built-in rules",
        f"rules file sha256 {_text(rules_sha256, 'rules hash')}",
        "",
    ]

    def row_line(cells: tuple[str, ...]) -> str:
        padded = [cells[i].ljust(widths[i]) for i in range(4)]
        return "  ".join([*padded, cells[4]]).rstrip()

    lines.append(row_line(_HEADERS))
    for cells, info in zip(rows, infos, strict=True):
        lines.append(row_line(cells))
        lines.append("  " + _text(info.description, "rule description"))
    lines += [
        "",
        "Keywords are lower-case literals: a rule's pattern runs only on a line that holds one.",
        "No example or sample secret is listed.",
    ]
    return "\n".join(lines) + "\n"
