"""What may be said about a rule without saying anything about a secret (PLAN.md D4, D12).

`RuleInfo` is the public description of a rule: id, name, description, severity, confidence and the
pre-filter keywords. It is the only view of a rule that the `rules` command and the SARIF rule list
use. It has no pattern, no fake specification and nothing else that could be used to build a
secret-shaped value (invariant 1 of CLAUDE.md section 5).

The regex rules come from the rules file. The private key and entropy detectors are code, not
data, so their descriptions live here; a test compares them with the detectors' own constants.
"""

from __future__ import annotations

from collections.abc import Iterable
from dataclasses import dataclass

from secret_scanner.core.models import Confidence, Detector, Rule, Severity
from secret_scanner.core.rules import ENTROPY_BASE64_ID, ENTROPY_HEX_ID, PRIVATE_KEY_ID

PRIVATE_KEY_KEYWORD = "private key"


@dataclass(frozen=True, slots=True)
class RuleInfo:
    """The public description of one rule or detector."""

    id: str
    name: str
    description: str
    detector: Detector
    severity: Severity
    confidence: Confidence
    keywords: tuple[str, ...]


DETECTOR_INFOS: tuple[RuleInfo, ...] = (
    RuleInfo(
        id=PRIVATE_KEY_ID,
        name="Private key block",
        description=(
            "A PEM or PGP private key block with at least 64 base64 characters of body. "
            "Severity is critical, and medium for an encrypted key; confidence is high for a "
            "complete block and medium for a truncated one."
        ),
        detector=Detector.PRIVATE_KEY,
        severity=Severity.CRITICAL,
        confidence=Confidence.HIGH,
        keywords=(PRIVATE_KEY_KEYWORD,),
    ),
    RuleInfo(
        id=ENTROPY_BASE64_ID,
        name="High-entropy base64 string",
        description=(
            "A run of base64 or base64url characters with a Shannon entropy of at least 4.5 bits "
            "per character. Confidence is medium when the line assigns it to a name such as "
            "secret, token, password or api_key, and low otherwise (reported only with "
            "--min-confidence low)."
        ),
        detector=Detector.ENTROPY,
        severity=Severity.MEDIUM,
        confidence=Confidence.LOW,
        keywords=(),
    ),
    RuleInfo(
        id=ENTROPY_HEX_ID,
        name="High-entropy hex string",
        description=(
            "A run of at least 32 hex digits with a Shannon entropy of at least 3.0 bits per "
            "character, reported only on a line that assigns it to a name such as secret, token, "
            "password or api_key (hashes and digests are everywhere)."
        ),
        detector=Detector.ENTROPY,
        severity=Severity.MEDIUM,
        confidence=Confidence.MEDIUM,
        keywords=(),
    ),
)


def info_for_rule(rule: Rule) -> RuleInfo:
    """The public description of a regex rule (built-in or from a configuration file)."""
    return RuleInfo(
        id=rule.id,
        name=rule.name,
        description=rule.description,
        detector=rule.detector,
        severity=rule.severity,
        confidence=rule.confidence,
        keywords=rule.keywords,
    )


def rule_infos(rules: Iterable[Rule]) -> tuple[RuleInfo, ...]:
    """Every rule that can produce a finding in a run with `rules`: the regex rules in order, then
    the private key and entropy detectors."""
    return (*(info_for_rule(rule) for rule in rules), *DETECTOR_INFOS)
