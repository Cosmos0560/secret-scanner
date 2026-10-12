"""Strict YAML loading and the built-in rules (PLAN.md D19). The only importer of `yaml` and
`importlib`.

All YAML of the tool (built-in rules, configuration, baseline) goes through `parse_yaml`: a
`SafeLoader` subclass that also refuses duplicate keys, merge keys, anchors, aliases (so no
alias-expansion bomb) and every explicit tag, with a size cap before parsing. Schemas are checked
afterwards by the pure modules of `core/`, which refuse unknown keys and wrong types, including
the YAML 1.1 surprises (an unquoted `yes` is a bool, `0755` an integer).

Error messages carry a fixed reason and a position, never content.
"""

from __future__ import annotations

import hashlib
from collections.abc import Hashable
from dataclasses import dataclass
from importlib import resources
from typing import Any

import yaml
from yaml.error import MarkedYAMLError
from yaml.nodes import MappingNode

from secret_scanner.core.errors import ConfigError
from secret_scanner.core.limits import DEFAULT_LIMITS, Limits
from secret_scanner.core.models import Rule
from secret_scanner.core.rules import parse_rules_document

BUILTIN_RULES_PACKAGE = "secret_scanner"
BUILTIN_RULES_PATH = ("rules", "builtin.yaml")
_MERGE_TAG = "tag:yaml.org,2002:merge"


class _RefusedError(MarkedYAMLError):
    """A construct the strict loader does not allow. `problem` is a fixed sentence."""


class _StrictLoader(yaml.SafeLoader):
    def compose_node(self, parent: Any, index: Any) -> Any:
        event: Any = self.peek_event()  # type: ignore[no-untyped-call]  # stubs leave it untyped
        mark: Any = event.start_mark
        if isinstance(event, yaml.AliasEvent):
            raise _RefusedError(None, None, "aliases are not allowed", mark)
        if event.anchor is not None:
            raise _RefusedError(None, None, "anchors are not allowed", mark)
        if getattr(event, "tag", None) is not None:
            raise _RefusedError(None, None, "explicit tags are not allowed", mark)
        return super().compose_node(parent, index)

    def construct_mapping(self, node: MappingNode, deep: bool = False) -> dict[Hashable, Any]:
        seen: set[Hashable] = set()
        for key_node, _ in node.value:
            if key_node.tag == _MERGE_TAG:
                raise _RefusedError(None, None, "merge keys are not allowed", key_node.start_mark)
            key = self.construct_object(key_node, deep=True)
            if isinstance(key, Hashable):
                if key in seen:
                    raise _RefusedError(None, None, "duplicate key", key_node.start_mark)
                seen.add(key)
        return super().construct_mapping(node, deep=deep)


def _describe(what: str, error: BaseException) -> str:
    reason = type(error).__name__
    mark = None
    if isinstance(error, _RefusedError):
        reason = error.problem or "refused construct"
        mark = error.problem_mark
    elif isinstance(error, MarkedYAMLError):
        mark = error.problem_mark
    where = "" if mark is None else f" at line {mark.line + 1}, column {mark.column + 1}"
    return f"{what}: invalid YAML ({reason}){where}"


def parse_yaml(data: bytes, *, max_bytes: int, what: str = "YAML file") -> object:
    """Parse one YAML document from bytes. Returns plain data (dict, list, str, int, float, bool,
    None); raises `ConfigError` for anything the strict loader refuses."""
    if len(data) > max_bytes:
        raise ConfigError(f"{what}: larger than the limit of {max_bytes} bytes")
    try:
        text = data.decode("utf-8-sig")
    except UnicodeDecodeError:
        raise ConfigError(f"{what}: not valid UTF-8") from None
    loader: _StrictLoader | None = None
    try:
        loader = _StrictLoader(text)  # the reader validates characters here, not at parse time
        return loader.get_single_data()
    except yaml.YAMLError as error:
        raise ConfigError(_describe(what, error)) from None
    except RecursionError:
        raise ConfigError(f"{what}: nested too deeply") from None
    finally:
        if loader is not None:
            loader.dispose()


@dataclass(frozen=True, slots=True)
class RuleSet:
    """Validated rules and the SHA-256 of the file they came from (the "rules version")."""

    rules: tuple[Rule, ...]
    sha256: str


def load_rules_from_bytes(
    data: bytes,
    *,
    limits: Limits = DEFAULT_LIMITS,
    id_prefix: str | None = None,
    what: str = "rules file",
) -> RuleSet:
    """Parse and validate a rules document (`version: 1`, `rules: [...]`)."""
    document = parse_yaml(data, max_bytes=limits.max_rules_file_bytes, what=what)
    rules = parse_rules_document(document, limits, id_prefix=id_prefix)
    return RuleSet(rules=rules, sha256=hashlib.sha256(data).hexdigest())


def load_builtin_rules(limits: Limits = DEFAULT_LIMITS) -> RuleSet:
    """The built-in rules, read from the package data."""
    resource = resources.files(BUILTIN_RULES_PACKAGE).joinpath(*BUILTIN_RULES_PATH)
    return load_rules_from_bytes(resource.read_bytes(), limits=limits, what="built-in rules")
