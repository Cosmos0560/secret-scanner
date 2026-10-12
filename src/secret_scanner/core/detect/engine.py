"""The detection engine: one pass over the lines of a buffer, all detectors, overlap resolution.

For every line, in order: the private key scanner (which protects the spans of a key), the rule
detector (keyword pre-filter first), and the entropy detector. Then:

* a hit that overlaps a protected span (a private key's header, body or footer) is dropped;
* an entropy hit that overlaps a rule hit is dropped: the rule wins (PLAN.md D5);
* two rule hits that overlap keep the better one: higher confidence, then higher severity, then
  the longer span, then the rule id (so the outcome is deterministic).

`scan` takes the raw bytes of a file or blob. It never raises for content: binary and
undecodable input are reported in the result, over-long lines are cut and listed, and the number
of matches per buffer is bounded by `max_findings_per_file`.
"""

from __future__ import annotations

from bisect import bisect_left, insort
from collections.abc import Sequence
from dataclasses import dataclass

from secret_scanner.core.detect import prefilter
from secret_scanner.core.detect.entropy import EntropyConfig, EntropyDetector
from secret_scanner.core.detect.match import Match
from secret_scanner.core.detect.private_key import (
    HEADER_KEYWORD,
    PrivateKeyScanner,
    compile_header_pattern,
)
from secret_scanner.core.detect.rule_detector import RuleDetector
from secret_scanner.core.limits import DEFAULT_LIMITS, Limits
from secret_scanner.core.lines import TextKind, prepare, split_lines
from secret_scanner.core.models import Rule

Hit = tuple[int, int, Match]  # (start byte, end byte, match) within one line


@dataclass(frozen=True, slots=True)
class BufferResult:
    """What one buffer yielded. `matches` hold secrets and must go through `core/findings.py`."""

    matches: tuple[Match, ...]
    kind: TextKind
    long_lines: tuple[int, ...]  # line numbers cut at the line limit (an issue for the caller)
    capped: bool  # more matches than `max_findings_per_file`; the rest were dropped
    lines: int


def _overlaps(a_start: int, a_end: int, b_start: int, b_end: int) -> bool:
    return a_start < b_end and b_start < a_end


def _priority(hit: Hit) -> tuple[int, int, int, str]:
    start, end, match = hit
    return (-match.confidence.rank, -match.severity.rank, -(end - start), match.rule_id)


def resolve_line(
    rule_hits: Sequence[Hit], entropy_hits: Sequence[Hit], protected: Sequence[tuple[int, int]]
) -> list[Match]:
    """Combine the hits of one line into the matches to keep, ordered by position."""

    def free(hit: Hit) -> bool:
        return not any(_overlaps(hit[0], hit[1], lo, hi) for lo, hi in protected)

    # Accepted rule hits, kept sorted by start and non-overlapping, so a new span only has to be
    # compared with its two neighbours: a line with thousands of hits stays linearithmic.
    starts: list[int] = []
    accepted: dict[int, Hit] = {}

    def clashes(start: int, end: int) -> bool:
        index = bisect_left(starts, start)
        if index > 0 and accepted[starts[index - 1]][1] > start:
            return True
        return index < len(starts) and starts[index] < end

    for hit in sorted(filter(free, rule_hits), key=_priority):
        if not clashes(hit[0], hit[1]):
            insort(starts, hit[0])
            accepted[hit[0]] = hit
    kept = list(accepted.values())
    # Entropy hits never overlap each other (maximal runs), only a rule hit can displace them.
    kept.extend(hit for hit in filter(free, entropy_hits) if not clashes(hit[0], hit[1]))
    kept.sort(key=lambda hit: (hit[0], hit[1]))
    return [hit[2] for hit in kept]


class Engine:
    """Runs the rules, the private key detector and (optionally) the entropy detector."""

    def __init__(
        self,
        rules: Sequence[Rule],
        *,
        entropy: EntropyConfig | None = None,
        limits: Limits = DEFAULT_LIMITS,
        use_prefilter: bool = True,
    ) -> None:
        self.limits = limits
        self._rules = RuleDetector(rules, use_prefilter=use_prefilter)
        config = EntropyConfig() if entropy is None else entropy
        self._entropy = EntropyDetector(config, limits) if config.enabled else None
        self._key_header = compile_header_pattern(limits)

    @property
    def entropy_enabled(self) -> bool:
        return self._entropy is not None

    def scan(self, data: bytes, *, use_entropy: bool = True) -> BufferResult:
        """Scan the raw bytes of one file or blob. `use_entropy=False` is for the paths the
        entropy detector skips by default (`entropy.path_excluded`)."""
        prepared = prepare(data)
        if prepared.kind is not TextKind.TEXT:
            return BufferResult((), prepared.kind, (), False, 0)
        text = prepared.text
        lowered_file = prefilter.lowered(text)
        active = self._rules.active_for(lowered_file)
        entropy = self._entropy if use_entropy else None
        key_possible = HEADER_KEYWORD in lowered_file
        keys = PrivateKeyScanner(self.limits, header=self._key_header)
        collected: list[Match] = []
        long_lines: list[int] = []
        cap = self.limits.max_findings_per_file
        total_lines = 0
        capped = False
        for line in split_lines(text, self.limits.max_line_bytes):
            total_lines = line.number
            if line.truncated:
                long_lines.append(line.number)
            content = line.content
            lowered_line = content.lower() if (active or key_possible) else b""
            protected = keys.feed(line.number, content, lowered_line) if key_possible else []
            rule_hits = (
                list(self._rules.scan_line(content, lowered_line, line.number, active))
                if active
                else []
            )
            entropy_hits = list(entropy.scan_line(content, line.number)) if entropy else []
            collected.extend(resolve_line(rule_hits, entropy_hits, protected))
            collected.extend(keys.matches)
            keys.matches.clear()
            if len(collected) > cap:
                capped = True
                break
        keys.finish()
        collected.extend(keys.matches)
        collected.sort(key=lambda match: (match.line, match.col_start))
        if len(collected) > cap:
            capped = True
            collected = collected[:cap]
        return BufferResult(tuple(collected), TextKind.TEXT, tuple(long_lines), capped, total_lines)
