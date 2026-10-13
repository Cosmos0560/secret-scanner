"""Configuration and baseline files -> models (PLAN.md D9, D19).

Both are read only from paths given on the command line (never discovered inside a scanned
tree), parsed by the strict loader, and validated here: unknown keys, wrong types and values
outside their bounds are refused with `ConfigError`, never ignored. Limits in a configuration can
only be lowered. CLI flags override configuration values; that merge is the application's job.
"""

from __future__ import annotations

from collections.abc import Collection
from dataclasses import dataclass, field
from typing import TypeVar

from secret_scanner.core.detect.entropy import EntropyConfig
from secret_scanner.core.errors import ConfigError, unknown_key_error
from secret_scanner.core.globs import compile_globs
from secret_scanner.core.limits import DEFAULT_LIMITS, Limits
from secret_scanner.core.models import Confidence, Rule, Severity, Suppressions
from secret_scanner.core.rules import CUSTOM_ID_PREFIX, parse_rule_list
from secret_scanner.core.suppress import parse_baseline
from secret_scanner.services.loader import dump_yaml, parse_yaml

_E = TypeVar("_E", Confidence, Severity)

CONFIG_VERSION = 1
_TOP_KEYS = frozenset(
    {
        "version",
        "exclude",
        "min_confidence",
        "fail_on",
        "entropy",
        "disable_rules",
        "extra_rules",
        "limits",
    }
)
_ENTROPY_KEYS = frozenset({"enabled", "base64_threshold", "hex_threshold", "min_length"})
BASELINE_HEADER = (
    "# secret-scanner baseline (version 1).\n"
    "# Each entry suppresses one finding by its fingerprint. Review every entry and replace\n"
    "# the reason. A baseline that arrives with the change it excuses deserves the same review\n"
    "# as code: it can hide that change's own secret.\n"
)


@dataclass(frozen=True, slots=True)
class ScanConfig:
    """A validated configuration. `None` means "not set here" (the default applies)."""

    exclude: tuple[str, ...] = ()
    min_confidence: Confidence | None = None
    fail_on: Severity | None = None
    entropy: EntropyConfig = field(default_factory=EntropyConfig)
    disable_rules: tuple[str, ...] = ()
    extra_rules: tuple[Rule, ...] = ()
    limits: Limits = DEFAULT_LIMITS


def _enum_value(value: object, where: str, kind: type[_E]) -> _E:
    allowed = [member.value for member in kind]
    if not isinstance(value, str) or value not in allowed:
        raise ConfigError(f"{where}: must be one of {', '.join(allowed)}")
    return kind(value)


def _string_list(value: object, where: str, *, maximum: int) -> tuple[str, ...]:
    if value is None:
        return ()
    if not isinstance(value, list):
        raise ConfigError(f"{where}: must be a list")
    if len(value) > maximum:
        raise ConfigError(f"{where}: more than {maximum} entries")
    for item in value:
        if not isinstance(item, str):
            raise ConfigError(f"{where}: every entry must be a string")
    return tuple(value)


def _entropy(value: object) -> EntropyConfig:
    if value is None:
        return EntropyConfig()
    if not isinstance(value, dict):
        raise ConfigError("config.entropy: must be a mapping")
    if any(key not in _ENTROPY_KEYS for key in value):
        raise unknown_key_error("config.entropy", _ENTROPY_KEYS)
    defaults = EntropyConfig()
    enabled = value.get("enabled", defaults.enabled)
    if not isinstance(enabled, bool):
        raise ConfigError("config.entropy.enabled: must be true or false")
    numbers: dict[str, float] = {}
    for key in ("base64_threshold", "hex_threshold"):
        number = value.get(key, getattr(defaults, key))
        if isinstance(number, bool) or not isinstance(number, int | float):
            raise ConfigError(f"config.entropy.{key}: must be a number")
        numbers[key] = float(number)
    length = value.get("min_length", defaults.min_length)
    if isinstance(length, bool) or not isinstance(length, int):
        raise ConfigError("config.entropy.min_length: must be an integer")
    return EntropyConfig(
        enabled=enabled,
        base64_threshold=numbers["base64_threshold"],
        hex_threshold=numbers["hex_threshold"],
        min_length=length,
    )


def parse_config(
    document: object,
    *,
    builtin_rule_ids: Collection[str],
    base_limits: Limits = DEFAULT_LIMITS,
) -> ScanConfig:
    """Validate a parsed configuration document."""
    if not isinstance(document, dict):
        raise ConfigError("config: must be a mapping")
    if any(key not in _TOP_KEYS for key in document):
        raise unknown_key_error("config", _TOP_KEYS)
    version = document.get("version")
    if isinstance(version, bool) or version != CONFIG_VERSION:
        raise ConfigError(f"config: version must be {CONFIG_VERSION}")

    limits_section = document.get("limits")
    limits = base_limits
    if limits_section is not None:
        if not isinstance(limits_section, dict):
            raise ConfigError("config.limits: must be a mapping")
        limits = base_limits.with_overrides({str(k): v for k, v in limits_section.items()})

    exclude = _string_list(document.get("exclude"), "config.exclude", maximum=limits.max_globs)
    compile_globs(exclude, limits, what="config.exclude")  # validates every pattern

    min_confidence = document.get("min_confidence")
    fail_on = document.get("fail_on")

    extra_raw = document.get("extra_rules")
    extra_rules: tuple[Rule, ...] = ()
    if extra_raw is not None:
        extra_rules = parse_rule_list(
            extra_raw, "config.extra_rules", limits, id_prefix=CUSTOM_ID_PREFIX
        )

    disabled = _string_list(document.get("disable_rules"), "config.disable_rules", maximum=256)
    known = set(builtin_rule_ids) | {rule.id for rule in extra_rules}
    for index, rule_id in enumerate(disabled):
        if rule_id not in known:
            raise ConfigError(f"config.disable_rules[{index}]: unknown rule id")
    if len(set(disabled)) != len(disabled):
        raise ConfigError("config.disable_rules: duplicate rule id")

    return ScanConfig(
        exclude=exclude,
        min_confidence=(
            None
            if min_confidence is None
            else _enum_value(min_confidence, "config.min_confidence", Confidence)
        ),
        fail_on=None if fail_on is None else _enum_value(fail_on, "config.fail_on", Severity),
        entropy=_entropy(document.get("entropy")),
        disable_rules=disabled,
        extra_rules=extra_rules,
        limits=limits,
    )


def load_config(
    data: bytes, *, builtin_rule_ids: Collection[str], base_limits: Limits = DEFAULT_LIMITS
) -> ScanConfig:
    """Parse and validate configuration bytes."""
    document = parse_yaml(data, max_bytes=base_limits.max_config_bytes, what="configuration file")
    return parse_config(document, builtin_rule_ids=builtin_rule_ids, base_limits=base_limits)


def load_baseline(data: bytes, limits: Limits = DEFAULT_LIMITS) -> Suppressions:
    """Parse and validate baseline bytes."""
    document = parse_yaml(data, max_bytes=limits.max_baseline_bytes, what="baseline file")
    return parse_baseline(document, limits)


def serialize_baseline(document: dict[str, object]) -> bytes:
    """The text of a baseline file for a document from `baseline_document`."""
    return (BASELINE_HEADER + dump_yaml(document)).encode("ascii")
