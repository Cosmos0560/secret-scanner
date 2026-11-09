"""A structural checker for the SARIF 2.1.0 subset this tool writes.

The official SARIF JSON schema is not available here: no PyPI package ships it (checked 2026-11-09,
see docs/sarif.md), and nothing may be fetched from anywhere else. So the checks below are
written by hand from the SARIF 2.1.0 specification (OASIS, errata 01) and cover what the
renderer emits: required properties, value sets, types, cross references and the form of every
URI. A document that passes is *not* proven valid against the official schema; that is a known gap.
"""

from __future__ import annotations

import re
from collections.abc import Iterator

LEVELS = frozenset({"none", "note", "warning", "error"})
SUPPRESSION_KINDS = frozenset({"inSource", "external"})
# A relative URI reference of percent-encoded segments: unreserved characters and %XX only.
URI_REFERENCE = re.compile(
    r"^(?:[A-Za-z0-9._~-]|%[0-9A-F]{2})+(?:/(?:[A-Za-z0-9._~-]|%[0-9A-F]{2})+)*$"
)
FORBIDDEN_KEYS = frozenset(
    {"snippet", "contextRegion", "contextSnippet", "markdown", "codeFlows", "stacks", "fixes"}
)
REGION_KEYS = ("startLine", "startColumn", "endColumn")


def walk_keys(node: object) -> Iterator[str]:
    """Every object key anywhere in a JSON-shaped value."""
    if isinstance(node, dict):
        for key, value in node.items():
            yield key
            yield from walk_keys(value)
    elif isinstance(node, list):
        for item in node:
            yield from walk_keys(item)


def _is_int(value: object) -> bool:
    return isinstance(value, int) and not isinstance(value, bool)


def _message(node: object, where: str, problems: list[str]) -> None:
    if not isinstance(node, dict) or not isinstance(node.get("text"), str) or not node["text"]:
        problems.append(f"{where}: message needs a non-empty text")


def _check_rule(rule: object, position: int, problems: list[str]) -> None:
    where = f"rules[{position}]"
    if not isinstance(rule, dict):
        problems.append(f"{where}: not an object")
        return
    if not isinstance(rule.get("id"), str) or not rule["id"]:
        problems.append(f"{where}: id is required")
    for key in ("shortDescription", "fullDescription", "help"):
        text = rule.get(key)
        if not isinstance(text, dict) or not isinstance(text.get("text"), str):
            problems.append(f"{where}: {key}.text is required")
    configuration = rule.get("defaultConfiguration")
    if not isinstance(configuration, dict) or configuration.get("level") not in LEVELS:
        problems.append(f"{where}: defaultConfiguration.level is not a SARIF level")
    properties = rule.get("properties")
    if not isinstance(properties, dict):
        problems.append(f"{where}: properties is required")
        return
    if properties.get("tags") != ["security", "secret"]:
        problems.append(f"{where}: tags")
    if properties.get("precision") not in {"very-high", "high", "medium", "low"}:
        problems.append(f"{where}: precision")
    score = properties.get("security-severity")
    if score is not None:
        try:
            valid = isinstance(score, str) and 0.0 <= float(score) <= 10.0
        except ValueError:
            valid = False
        if not valid:
            problems.append(f"{where}: security-severity must be a string from 0.0 to 10.0")


def _check_location(location: object, where: str, problems: list[str]) -> None:
    physical = location.get("physicalLocation") if isinstance(location, dict) else None
    if not isinstance(physical, dict):
        problems.append(f"{where}: physicalLocation is required")
        return
    artifact = physical.get("artifactLocation")
    uri = artifact.get("uri") if isinstance(artifact, dict) else None
    if not isinstance(uri, str) or URI_REFERENCE.match(uri) is None:
        problems.append(f"{where}: artifactLocation.uri is not a percent-encoded relative path")
    elif any(segment in {".", ".."} for segment in uri.split("/")):
        problems.append(f"{where}: artifactLocation.uri has a dot segment")
    if isinstance(artifact, dict) and artifact.get("uriBaseId") != "%SRCROOT%":
        problems.append(f"{where}: uriBaseId")
    region = physical.get("region")
    if not isinstance(region, dict) or tuple(region) != REGION_KEYS:
        problems.append(f"{where}: region holds exactly {', '.join(REGION_KEYS)}")
        return
    if not all(_is_int(region[key]) for key in REGION_KEYS):
        problems.append(f"{where}: region values are integers")
    elif region["startLine"] < 1 or region["startColumn"] < 1:
        problems.append(f"{where}: region is 1-based")
    elif region["endColumn"] < region["startColumn"]:
        problems.append(f"{where}: endColumn precedes startColumn")


def _check_result(result: object, position: int, rules: list[object], problems: list[str]) -> None:
    where = f"results[{position}]"
    if not isinstance(result, dict):
        problems.append(f"{where}: not an object")
        return
    index = result.get("ruleIndex")
    if isinstance(index, bool) or not isinstance(index, int) or not 0 <= index < len(rules):
        problems.append(f"{where}: ruleIndex does not point into tool.driver.rules")
    else:
        rule = rules[index]
        if not isinstance(rule, dict) or rule.get("id") != result.get("ruleId"):
            problems.append(f"{where}: ruleId differs from the rule at ruleIndex")
    if result.get("level") not in LEVELS:
        problems.append(f"{where}: level is not a SARIF level")
    _message(result.get("message"), where, problems)
    locations = result.get("locations")
    if not isinstance(locations, list) or len(locations) != 1:
        problems.append(f"{where}: exactly one location")
    else:
        _check_location(locations[0], where, problems)
    fingerprints = result.get("partialFingerprints")
    if (
        not isinstance(fingerprints, dict)
        or not fingerprints
        or not all(isinstance(k, str) and isinstance(v, str) for k, v in fingerprints.items())
    ):
        problems.append(f"{where}: partialFingerprints maps strings to strings")
    suppressions = result.get("suppressions", [])
    if not isinstance(suppressions, list) or not all(
        isinstance(s, dict) and s.get("kind") in SUPPRESSION_KINDS for s in suppressions
    ):
        problems.append(f"{where}: suppressions need a kind of inSource or external")


def _check_invocation(invocation: object, problems: list[str]) -> None:
    if not isinstance(invocation, dict) or not isinstance(
        invocation.get("executionSuccessful"), bool
    ):
        problems.append("invocations[0]: executionSuccessful is a required boolean")
        return
    notifications = invocation.get("toolExecutionNotifications", [])
    if not isinstance(notifications, list):
        problems.append("invocations[0]: toolExecutionNotifications is a list")
        return
    for position, notification in enumerate(notifications):
        where = f"notifications[{position}]"
        if not isinstance(notification, dict):
            problems.append(f"{where}: not an object")
            continue
        _message(notification.get("message"), where, problems)
        if notification.get("level") not in LEVELS:
            problems.append(f"{where}: level")


def check_sarif(document: object) -> list[str]:
    """The problems found in `document`; an empty list means it passed every structural check."""
    problems: list[str] = []
    if not isinstance(document, dict):
        return ["the document is not an object"]
    if document.get("version") != "2.1.0":
        problems.append("version must be 2.1.0")
    if not isinstance(document.get("$schema"), str):
        problems.append("$schema must be a string")
    runs = document.get("runs")
    if not isinstance(runs, list) or len(runs) != 1 or not isinstance(runs[0], dict):
        return [*problems, "exactly one run is required"]
    run = runs[0]
    driver = run.get("tool", {}).get("driver") if isinstance(run.get("tool"), dict) else None
    if not isinstance(driver, dict) or not isinstance(driver.get("name"), str):
        return [*problems, "tool.driver.name is required"]
    for key in ("version", "semanticVersion", "informationUri"):
        if not isinstance(driver.get(key), str):
            problems.append(f"tool.driver.{key} is a string")
    rules = driver.get("rules")
    if not isinstance(rules, list):
        return [*problems, "tool.driver.rules is a list"]
    for position, rule in enumerate(rules):
        _check_rule(rule, position, problems)
    ids = [rule.get("id") for rule in rules if isinstance(rule, dict)]
    if len(ids) != len(set(ids)):
        problems.append("rule ids are unique")
    if run.get("columnKind") != "unicodeCodePoints":
        problems.append("columnKind must be unicodeCodePoints")
    invocations = run.get("invocations")
    if not isinstance(invocations, list) or len(invocations) != 1:
        problems.append("exactly one invocation")
    else:
        _check_invocation(invocations[0], problems)
    results = run.get("results")
    if not isinstance(results, list):
        return [*problems, "results is a list"]
    for position, result in enumerate(results):
        _check_result(result, position, rules, problems)
    forbidden = FORBIDDEN_KEYS.intersection(walk_keys(document))
    if forbidden:
        problems.append(f"forbidden keys: {', '.join(sorted(forbidden))}")
    return problems
