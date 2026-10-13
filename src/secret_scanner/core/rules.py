"""Rule schema validation (PLAN.md D4, D19): parsed YAML data in, `Rule` objects out.

Pure: the strict YAML loader (`services/loader.py`) turns text into plain data, this module checks
it. Everything is refused rather than ignored: unknown keys, wrong types (including the YAML 1.1
surprises, where an unquoted `yes` is a bool and `0755` an integer), regexes outside the guard's
grammar, keywords that are not lower-case literals, a `shown_chars` that is not a fixed public
prefix, a `min_secret_bits` below 64 or above what the pattern can guarantee, and a fake spec that
does not match its own rule.

Messages name the rule position and field, never the value: a user rule could hold anything.
"""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from typing import TypeVar

from secret_scanner.core.errors import ConfigError, unknown_key_error
from secret_scanner.core.fakes import CHARSETS, MAX_SEGMENT_CHARS, build_fake
from secret_scanner.core.limits import DEFAULT_LIMITS, Limits
from secret_scanner.core.models import (
    Checksum,
    Confidence,
    Detector,
    FakeSegment,
    Rule,
    Severity,
)
from secret_scanner.core.redact import check_shown_chars
from secret_scanner.core.regex_guard import PatternRefusedError, compile_pattern

RULES_FILE_VERSION = 1
MIN_SECRET_BITS = 64
MAX_ID_CHARS = 64
MAX_TEXT_CHARS = 512
MAX_LITERAL_CHARS = 64
MAX_CONTEXT_KEYWORDS = 4
MAX_FAKE_SEGMENTS = 16
MAX_FAKE_PARTS = 8
MAX_ENTROPY_BITS_PER_CHAR = 8.0

ENTROPY_BASE64_ID = "entropy-base64"
ENTROPY_HEX_ID = "entropy-hex"
PRIVATE_KEY_ID = "private-key"
RESERVED_IDS = frozenset({ENTROPY_BASE64_ID, ENTROPY_HEX_ID, PRIVATE_KEY_ID})
CUSTOM_ID_PREFIX = "custom-"

_RULE_KEYS = frozenset(
    {
        "id",
        "name",
        "description",
        "regex",
        "keywords",
        "severity",
        "confidence",
        "shown_chars",
        "min_secret_bits",
        "min_entropy",
        "checksum",
        "context",
        "fake",
    }
)
_REQUIRED_RULE_KEYS = frozenset(
    {
        "id",
        "name",
        "description",
        "regex",
        "keywords",
        "severity",
        "confidence",
        "shown_chars",
        "min_secret_bits",
        "fake",
    }
)


def _mapping(
    value: object, where: str, allowed: frozenset[str], required: frozenset[str]
) -> dict[str, object]:
    if not isinstance(value, Mapping):
        raise ConfigError(f"{where}: must be a mapping")
    keys = [key for key in value if isinstance(key, str)]
    if len(keys) != len(value):
        raise ConfigError(f"{where}: keys must be strings")
    if set(keys) - allowed:
        raise unknown_key_error(where, allowed)
    missing = sorted(required - set(keys))
    if missing:
        raise ConfigError(f"{where}: missing key {missing[0]!r}")
    return dict(value)


def _text(value: object, where: str, *, max_chars: int = MAX_TEXT_CHARS) -> str:
    if not isinstance(value, str):
        raise ConfigError(f"{where}: must be a string (quote values that YAML reads as numbers)")
    if not value or len(value) > max_chars:
        raise ConfigError(f"{where}: must be 1 to {max_chars} characters")
    return value


def _integer(value: object, where: str, minimum: int, maximum: int) -> int:
    if isinstance(value, bool) or not isinstance(value, int):
        raise ConfigError(f"{where}: must be an integer")
    if not minimum <= value <= maximum:
        raise ConfigError(f"{where}: must be between {minimum} and {maximum}")
    return value


def is_kebab_case(value: str) -> bool:
    """`a`, `aws-access-key-id`: lower-case ASCII letters and digits in hyphen-separated parts."""
    if not value or len(value) > MAX_ID_CHARS or value[0].isdigit():
        return False
    return all(
        part and part.isascii() and part.isalnum() and part == part.lower()
        for part in value.split("-")
    )


def _literals(value: object, where: str, *, maximum: int) -> tuple[str, ...]:
    if not isinstance(value, list) or not 1 <= len(value) <= maximum:
        raise ConfigError(f"{where}: must be a list of 1 to {maximum} literals")
    result: list[str] = []
    for index, item in enumerate(value):
        text = _text(item, f"{where}[{index}]", max_chars=MAX_LITERAL_CHARS)
        if not text.isascii() or not text.isprintable() or text != text.lower():
            raise ConfigError(f"{where}[{index}]: must be a lower-case printable ASCII literal")
        result.append(text)
    if len(set(result)) != len(result):
        raise ConfigError(f"{where}: duplicate literal")
    return tuple(result)


_E = TypeVar("_E", Severity, Confidence, Checksum)


def _enum(value: object, where: str, kind: type[_E]) -> _E:
    if not isinstance(value, str):
        raise ConfigError(f"{where}: must be a string")
    try:
        return kind(value)
    except ValueError:
        allowed = ", ".join(member.value for member in kind)
        raise ConfigError(f"{where}: must be one of {allowed}") from None


def _fake_segments(value: object, where: str, limits: Limits) -> tuple[FakeSegment, ...]:
    if not isinstance(value, list) or not 1 <= len(value) <= MAX_FAKE_SEGMENTS:
        raise ConfigError(f"{where}: must be a list of 1 to {MAX_FAKE_SEGMENTS} segments")
    segments: list[FakeSegment] = []
    total = 0
    for index, item in enumerate(value):
        place = f"{where}[{index}]"
        if isinstance(item, Mapping) and "parts" in item:
            data = _mapping(item, place, frozenset({"parts"}), frozenset({"parts"}))
            parts = data["parts"]
            if not isinstance(parts, list) or not 1 <= len(parts) <= MAX_FAKE_PARTS:
                raise ConfigError(f"{place}.parts: must be a list of 1 to {MAX_FAKE_PARTS} strings")
            checked = tuple(
                _printable(_text(part, f"{place}.parts[{n}]", max_chars=MAX_LITERAL_CHARS), place)
                for n, part in enumerate(parts)
            )
            segment = FakeSegment(parts=checked)
            total += sum(len(part) for part in checked)
        else:
            keys = frozenset({"charset", "length"})
            data = _mapping(item, place, keys, keys)
            charset = _text(data["charset"], f"{place}.charset", max_chars=MAX_LITERAL_CHARS)
            if charset not in CHARSETS:
                raise ConfigError(f"{place}.charset: unknown charset")
            length = _integer(data["length"], f"{place}.length", 1, MAX_SEGMENT_CHARS)
            segment = FakeSegment(charset=charset, length=length)
            total += length
        segments.append(segment)
    if total > limits.max_match_chars:
        raise ConfigError(f"{where}: the fake is longer than the match width limit")
    return tuple(segments)


def _printable(text: str, where: str) -> str:
    if not text.isascii() or not text.isprintable():
        raise ConfigError(f"{where}: fake parts are printable ASCII")
    return text


def parse_rule(
    data: object, where: str, limits: Limits = DEFAULT_LIMITS, *, id_prefix: str | None = None
) -> Rule:
    """Validate one rule mapping. `id_prefix` is required of the id (user rules: `custom-`)."""
    fields = _mapping(data, where, _RULE_KEYS, _REQUIRED_RULE_KEYS)
    rule_id = _text(fields["id"], f"{where}.id", max_chars=MAX_ID_CHARS)
    if not is_kebab_case(rule_id):
        raise ConfigError(f"{where}.id: must be kebab-case (lower-case letters, digits, hyphens)")
    if rule_id in RESERVED_IDS:
        raise ConfigError(f"{where}.id: reserved for a built-in detector")
    if id_prefix is not None and not rule_id.startswith(id_prefix):
        raise ConfigError(f"{where}.id: must start with {id_prefix!r}")
    name = _text(fields["name"], f"{where}.name")
    description = _text(fields["description"], f"{where}.description")
    source = _text(fields["regex"], f"{where}.regex", max_chars=limits.max_pattern_chars)
    try:
        pattern = compile_pattern(source, with_secret_group=True, limits=limits)
    except PatternRefusedError as error:
        raise ConfigError(f"{where}.regex: {error}") from error
    keywords = _literals(
        fields["keywords"], f"{where}.keywords", maximum=limits.max_keywords_per_rule
    )
    severity = _enum(fields["severity"], f"{where}.severity", Severity)
    confidence = _enum(fields["confidence"], f"{where}.confidence", Confidence)
    shown_chars = _integer(fields["shown_chars"], f"{where}.shown_chars", 0, 12)
    try:
        check_shown_chars(shown_chars, pattern.secret_min_width)
    except ConfigError as error:
        raise ConfigError(f"{where}.shown_chars: {error}") from error
    if shown_chars > pattern.secret_public_chars:
        raise ConfigError(
            f"{where}.shown_chars: only the first {pattern.secret_public_chars} characters of "
            "the secret are a fixed public prefix"
        )
    min_bits = _integer(
        fields["min_secret_bits"], f"{where}.min_secret_bits", MIN_SECRET_BITS, 4096
    )
    if pattern.secret_bits < min_bits:
        raise ConfigError(
            f"{where}.min_secret_bits: the regex only guarantees {int(pattern.secret_bits)} bits"
        )
    min_entropy = _min_entropy(fields.get("min_entropy"), f"{where}.min_entropy")
    raw_checksum = fields.get("checksum")
    checksum = None if raw_checksum is None else _enum(raw_checksum, f"{where}.checksum", Checksum)
    context = (
        ()
        if "context" not in fields
        else _literals(fields["context"], f"{where}.context", maximum=MAX_CONTEXT_KEYWORDS)
    )
    fake = _fake_segments(fields["fake"], f"{where}.fake", limits)
    rule = Rule(
        id=rule_id,
        name=name,
        description=description,
        detector=Detector.RULE,
        pattern=pattern,
        keywords=keywords,
        severity=severity,
        confidence=confidence,
        shown_chars=shown_chars,
        min_secret_bits=min_bits,
        min_entropy=min_entropy,
        checksum=checksum,
        context=context,
        fake=fake,
    )
    try:
        sample = build_fake(rule, "load-check").encode("ascii")
    except ValueError:
        raise ConfigError(f"{where}.fake: too short for the checksum of this rule") from None
    if pattern.search(sample) is None:
        raise ConfigError(f"{where}.fake: the fake does not match the rule's own regex")
    return rule


def _min_entropy(value: object, where: str) -> float | None:
    if value is None:
        return None
    if isinstance(value, bool) or not isinstance(value, int | float):
        raise ConfigError(f"{where}: must be a number")
    if not 0 <= value <= MAX_ENTROPY_BITS_PER_CHAR:
        raise ConfigError(f"{where}: must be between 0 and {MAX_ENTROPY_BITS_PER_CHAR:g}")
    return float(value)


def parse_rule_list(
    items: object, where: str, limits: Limits = DEFAULT_LIMITS, *, id_prefix: str | None = None
) -> tuple[Rule, ...]:
    """Validate a list of rule mappings: count bound and unique ids."""
    if not isinstance(items, list):
        raise ConfigError(f"{where}: must be a list")
    if not items or len(items) > limits.max_rules:
        raise ConfigError(f"{where}: must hold 1 to {limits.max_rules} rules")
    rules = [
        parse_rule(item, f"{where}[{index}]", limits, id_prefix=id_prefix)
        for index, item in enumerate(items)
    ]
    seen: set[str] = set()
    for rule in rules:
        if rule.id in seen:
            raise ConfigError(f"{where}: duplicate rule id {rule.id!r}")
        seen.add(rule.id)
    return tuple(rules)


def parse_rules_document(
    data: object, limits: Limits = DEFAULT_LIMITS, *, id_prefix: str | None = None
) -> tuple[Rule, ...]:
    """Validate a whole rules file: `version: 1` and a `rules` list."""
    document = _mapping(
        data, "rules file", frozenset({"version", "rules"}), frozenset({"version", "rules"})
    )
    version = document["version"]
    if isinstance(version, bool) or version != RULES_FILE_VERSION:
        raise ConfigError(f"rules file: version must be {RULES_FILE_VERSION}")
    return parse_rule_list(document["rules"], "rules", limits, id_prefix=id_prefix)


def rule_ids(rules: Sequence[Rule]) -> tuple[str, ...]:
    return tuple(rule.id for rule in rules)
