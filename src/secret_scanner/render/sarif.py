"""The SARIF 2.1.0 report (PLAN.md D12, docs/sarif.md).

One run. `tool.driver` carries the name, the version and one `reportingDescriptor` per rule that
can produce a result; every result points at its descriptor by `ruleId` and `ruleIndex`.

What a result holds, and what it does not:

* the location is the file's path relative to the scan root, percent-encoded one segment at a time
  from the exact path (so a hostile name stays inert and still names the real file), a line and
  columns counted in Unicode code points (`columnKind: unicodeCodePoints`);
* the message and `properties.redacted` hold the redacted form of PLAN.md D7 and nothing else;
* `partialFingerprints` holds the fingerprint of D8 and nothing else derived from the secret;
* there is no `snippet`, no `region.snippet`, no `contextRegion` and no `message.markdown`: a source
  line can hold a second, undetected secret, and the viewer shows the line from the repository.

Suppressed findings appear only when the report lists them (`--show-suppressed`), each with a
`suppressions` entry. The output is ASCII only (`ensure_ascii`), two-space indented, with a fixed
key order.
"""

from __future__ import annotations

import json
from collections.abc import Mapping, Sequence

from secret_scanner.core.models import Finding, Report, ScanIssue, Severity
from secret_scanner.core.ruleinfo import RuleInfo
from secret_scanner.core.sanitize import require_display_safe

SARIF_VERSION = "2.1.0"
SCHEMA_URI = (
    "https://docs.oasis-open.org/sarif/sarif/v2.1.0/errata01/os/schemas/sarif-schema-2.1.0.json"
)
TOOL_NAME = "secret-scanner"
INFORMATION_URI = "https://github.com/Cosmos0560/secret-scanner"
FINGERPRINT_KEY = "secretScanner/v1"
SOURCE_ROOT_ID = "%SRCROOT%"
COMMIT_CHARS = 12

# PLAN.md D12. `critical` and `high` are errors, `medium` a warning, `low` and `info` notes.
LEVELS: Mapping[Severity, str] = {
    Severity.CRITICAL: "error",
    Severity.HIGH: "error",
    Severity.MEDIUM: "warning",
    Severity.LOW: "note",
    Severity.INFO: "note",
}
# The number GitHub code scanning turns into its severity buckets; `info` has none.
SECURITY_SEVERITY: Mapping[Severity, str] = {
    Severity.CRITICAL: "9.5",
    Severity.HIGH: "8.0",
    Severity.MEDIUM: "5.5",
    Severity.LOW: "2.0",
}
PRECISION = {"high": "high", "medium": "medium", "low": "low"}
HELP_TEXT = (
    "Treat this credential as exposed. Revoke or rotate it at the service that issued it, "
    "remove it from the code and keep it in a secret manager or an environment the repository "
    "does not contain. A secret that was committed stays in the git history until the history "
    "is rewritten, and in every clone. This tool does not check whether a secret is still valid."
)
JUSTIFICATIONS = {
    "fingerprint": "Suppressed by an entry of the baseline file (matched by fingerprint).",
    "path": "Suppressed by a path pattern of the baseline file.",
}

_UNRESERVED = frozenset(b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-._~")


def _text(value: str, what: str) -> str:
    return require_display_safe(value, what)


def _encode_segment(segment: str) -> str:
    data = segment.encode("utf-8", errors="surrogateescape")
    return "".join(chr(byte) if byte in _UNRESERVED else f"%{byte:02X}" for byte in data)


def artifact_uri(path_key: str) -> str:
    """The URI reference for a path relative to the scan root: each `/`-separated segment encoded
    byte by byte (UTF-8, invalid bytes as they were), every byte outside the RFC 3986 unreserved
    set as `%XX`. Nothing a file name holds can add URI syntax: no `:`, `?`, `#`, `%`, `..`
    trick or control character survives unencoded."""
    return "/".join(_encode_segment(segment) for segment in path_key.split("/"))


def _descriptor(info: RuleInfo) -> dict[str, object]:
    properties: dict[str, object] = {
        "tags": ["security", "secret"],
        "precision": PRECISION[info.confidence.value],
    }
    score = SECURITY_SEVERITY.get(info.severity)
    if score is not None:
        properties["security-severity"] = score
    return {
        "id": _text(info.id, "rule id"),
        "name": _text(info.name, "rule name"),
        "shortDescription": {"text": _text(info.name, "rule name")},
        "fullDescription": {"text": _text(info.description, "rule description")},
        "help": {"text": HELP_TEXT},
        "defaultConfiguration": {"level": LEVELS[info.severity]},
        "properties": properties,
    }


def _message(finding: Finding, info: RuleInfo) -> str:
    text = f"{_text(info.name, 'rule name')}: {_text(finding.redacted.text, 'redacted value')}"
    if finding.location.commit is not None:
        text += " in commit " + _text(finding.location.commit, "commit")[:COMMIT_CHARS]
    return text


def _result(finding: Finding, index: int, info: RuleInfo) -> dict[str, object]:
    location = finding.location
    region = {
        "startLine": location.line,
        "startColumn": location.column,
        "endColumn": location.end_column,
    }
    properties: dict[str, object] = {
        "confidence": finding.confidence.value,
        "severity": finding.severity.value,
        "redacted": _text(finding.redacted.text, "redacted value"),
    }
    if location.commit is not None:
        properties["commit"] = _text(location.commit, "commit")
    result: dict[str, object] = {
        "ruleId": _text(finding.rule_id, "rule id"),
        "ruleIndex": index,
        "level": LEVELS[finding.severity],
        "message": {"text": _message(finding, info)},
        "locations": [
            {
                "physicalLocation": {
                    "artifactLocation": {
                        "uri": artifact_uri(location.path_key),
                        "uriBaseId": SOURCE_ROOT_ID,
                    },
                    "region": region,
                }
            }
        ],
        "partialFingerprints": {FINGERPRINT_KEY: _text(finding.fingerprint, "fingerprint")},
        "properties": properties,
    }
    if finding.suppressed_by is not None:
        result["suppressions"] = [
            {"kind": "external", "justification": JUSTIFICATIONS[finding.suppressed_by.value]}
        ]
    return result


def _notification(issue: ScanIssue) -> dict[str, object]:
    where = "" if issue.path is None else _text(issue.path, "issue path") + ": "
    return {
        "level": "warning",
        "message": {"text": where + _text(issue.detail, "issue detail")},
        "descriptor": {"id": issue.kind.value},
    }


def sarif_document(report: Report, infos: Sequence[RuleInfo]) -> dict[str, object]:
    """The report as plain data. `infos` must describe every rule a result can name."""
    index_of = {info.id: position for position, info in enumerate(infos)}
    if len(index_of) != len(infos):
        raise ValueError("the rule list holds a rule id twice")
    results = []
    for finding in report.findings:
        position = index_of.get(finding.rule_id)
        if position is None:
            raise ValueError("a result names a rule that is not in the rule list")
        results.append(_result(finding, position, infos[position]))
    version = _text(report.tool_version, "tool version")
    run: dict[str, object] = {
        "tool": {
            "driver": {
                "name": TOOL_NAME,
                "version": version,
                "semanticVersion": version,
                "informationUri": INFORMATION_URI,
                "rules": [_descriptor(info) for info in infos],
            }
        },
        "columnKind": "unicodeCodePoints",
        "invocations": [
            {
                "executionSuccessful": report.complete,
                "toolExecutionNotifications": [_notification(i) for i in report.issues],
            }
        ],
        "results": results,
        "properties": {
            "target": report.target.value,
            "complete": report.complete,
            "truncated": report.truncated,
            "historyComplete": report.history_complete,
            "rulesSha256": _text(report.rules_sha256, "rules hash"),
            "suppressedByFingerprint": report.suppressed_by_fingerprint,
            "suppressedByPath": report.suppressed_by_path,
            "stale": report.stale,
            "generatedAt": _text(report.generated_at, "timestamp"),
        },
    }
    return {"$schema": SCHEMA_URI, "version": SARIF_VERSION, "runs": [run]}


def render_sarif(report: Report, infos: Sequence[RuleInfo]) -> str:
    """The report as one SARIF 2.1.0 document, ASCII only, followed by a newline."""
    document = sarif_document(report, infos)
    return json.dumps(document, ensure_ascii=True, indent=2, allow_nan=False) + "\n"
