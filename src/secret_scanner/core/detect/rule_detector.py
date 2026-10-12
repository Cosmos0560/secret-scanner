"""Regex rule detector (PLAN.md D4): keyword pre-filter, the guarded regex, placeholder rejection
by entropy, and offline checksums.

Two levels of pre-filter keep the regexes off most input: a rule whose keywords occur nowhere in
the file is not run on any line of it, and on the lines of a file it runs only where a keyword is
present on that line. A rule's context words (all of them, on the same line) are a requirement of
the rule itself and are checked whether or not the pre-filter is on.
"""

from __future__ import annotations

from collections.abc import Iterator, Sequence
from dataclasses import dataclass

from secret_scanner.core.checksums import github_token_checksum_valid
from secret_scanner.core.detect import prefilter
from secret_scanner.core.detect.entropy import shannon_entropy
from secret_scanner.core.detect.match import Match
from secret_scanner.core.lines import ColumnCursor
from secret_scanner.core.models import Checksum, Confidence, Rule


@dataclass(frozen=True, slots=True)
class _Prepared:
    rule: Rule
    keywords: tuple[bytes, ...]
    context: tuple[bytes, ...]


class RuleDetector:
    """Runs a fixed set of rules. `use_prefilter=False` disables both keyword levels (tests prove
    the result is identical, only slower)."""

    def __init__(self, rules: Sequence[Rule], *, use_prefilter: bool = True) -> None:
        self.rules = tuple(rules)
        self.use_prefilter = use_prefilter
        self._prepared = tuple(
            _Prepared(
                rule,
                tuple(word.encode("ascii") for word in rule.keywords),
                tuple(word.encode("ascii") for word in rule.context),
            )
            for rule in self.rules
        )

    def active_for(self, lowered_file: bytes) -> tuple[_Prepared, ...]:
        """The rules worth running on a file whose lower-cased content is `lowered_file`."""
        if not self.use_prefilter:
            return self._prepared
        return tuple(
            prepared
            for prepared in self._prepared
            if prefilter.contains_any(lowered_file, prepared.keywords)
            and prefilter.contains_all(lowered_file, prepared.context)
        )

    def scan_line(
        self, line: bytes, lowered_line: bytes, number: int, active: Sequence[_Prepared]
    ) -> Iterator[tuple[int, int, Match]]:
        """Yield `(start, end, match)` byte spans of the secrets found in one line."""
        columns = ColumnCursor(line)
        for prepared in active:
            if self.use_prefilter and not prefilter.contains_any(lowered_line, prepared.keywords):
                continue
            # The context words are part of what the rule means, not an optimisation: they are
            # required with the pre-filter on or off.
            if not prefilter.contains_all(lowered_line, prepared.context):
                continue
            rule = prepared.rule
            for found in rule.pattern.finditer(line):
                secret = line[found.secret_start : found.secret_end]
                if rule.min_entropy is not None and shannon_entropy(secret) < rule.min_entropy:
                    continue
                confidence = rule.confidence
                if rule.checksum is Checksum.GITHUB_CRC32 and not github_token_checksum_valid(
                    secret
                ):
                    confidence = Confidence.LOW
                yield (
                    found.secret_start,
                    found.secret_end,
                    Match(
                        rule_id=rule.id,
                        detector=rule.detector,
                        severity=rule.severity,
                        confidence=confidence,
                        line=number,
                        col_start=columns.column(found.secret_start),
                        col_end=columns.column(found.secret_end),
                        secret=secret,
                        shown_chars=rule.shown_chars,
                    ),
                )
