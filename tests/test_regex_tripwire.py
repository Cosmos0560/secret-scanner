"""The ReDoS tripwire (PLAN.md D3): the single documented wall-clock assertion of the suite.

The guarantee against catastrophic backtracking comes from the grammar and the static cost budget,
which `test_regex_guard.py` proves without timing anything. This test only catches a regression
(a rule or a guard change that lets a slow shape through): it runs every built-in rule, and the
entropy and private key detectors, over adversarial lines of `MAX_LINE_BYTES` and fails if one
takes longer than a deliberately generous ceiling. Real runs take milliseconds.
"""

from __future__ import annotations

import time

import pytest

from secret_scanner.core.detect.engine import Engine
from secret_scanner.core.fakes import build_fake, fake_private_key
from secret_scanner.core.limits import DEFAULT_LIMITS
from secret_scanner.services.loader import load_builtin_rules

pytestmark = pytest.mark.slow

CEILING_SECONDS = 20.0  # per scan: two orders of magnitude above what a healthy rule needs
LINE = DEFAULT_LIMITS.max_line_bytes
RULES = list(load_builtin_rules().rules)


def _fit(unit: bytes) -> bytes:
    """`unit` repeated to exactly one maximum-length line."""
    return (unit * (LINE // len(unit) + 1))[:LINE]


def _adversarial_lines(fake: bytes) -> dict[str, bytes]:
    near_miss = fake[:-1]
    return {
        "run of the rule's own charset": _fit(fake[-1:]),
        "repeated prefix and body, one short": _fit(near_miss),
        "alternating near misses": _fit(near_miss + b"!"),
        "repeated whole fakes with no separator": _fit(fake),
        "keyword then a long run": fake[:8] + _fit(fake[-6:-1])[: LINE - 8],
        "a long run then a real secret at the end": _fit(fake[-1:])[: LINE - len(fake) - 1]
        + b" "
        + fake,
        "all printable ascii": _fit(bytes(range(0x20, 0x7F))),
    }


def _timed(function: object, *args: object) -> float:
    started = time.perf_counter()
    function(*args)  # type: ignore[operator]
    return time.perf_counter() - started


@pytest.mark.parametrize("rule", RULES, ids=[rule.id for rule in RULES])
def test_rule_stays_fast_on_adversarial_lines(rule) -> None:  # type: ignore[no-untyped-def]
    fake = build_fake(rule, "tripwire").encode("ascii")
    for name, line in _adversarial_lines(fake).items():
        assert len(line) <= LINE
        elapsed = _timed(lambda data: list(rule.pattern.finditer(data)), line)
        assert elapsed < CEILING_SECONDS, f"{rule.id}: {name} took {elapsed:.1f}s"


def test_the_whole_engine_stays_fast_on_adversarial_lines() -> None:
    engine = Engine(RULES)
    fake_bytes = [build_fake(rule, "engine-tripwire").encode("ascii") for rule in RULES]
    for fake in fake_bytes:
        for name, line in _adversarial_lines(fake).items():
            elapsed = _timed(engine.scan, line + b"\n")
            assert elapsed < CEILING_SECONDS, f"engine: {name} took {elapsed:.1f}s"


def test_engine_stays_fast_on_a_file_of_header_lines_and_long_key_bodies() -> None:
    engine = Engine(RULES)
    header = fake_private_key("tripwire").split("\n")[0].encode()
    many_headers = (header + b"\n") * (LINE // (len(header) + 1))
    one_long_body = header + b"\n" + _fit(b"A") + b"\n"
    many_lines = header + b"\n" + (b"A" * 64 + b"\n") * 20_000
    for name, data in {
        "many headers": many_headers,
        "one long body line": one_long_body,
        "twenty thousand body lines": many_lines,
    }.items():
        elapsed = _timed(engine.scan, data)
        assert elapsed < CEILING_SECONDS, f"{name} took {elapsed:.1f}s"


def test_a_secret_at_the_end_of_a_maximum_length_line_is_still_found() -> None:
    engine = Engine(RULES)
    for rule in RULES:
        fake = build_fake(rule, "tail").encode("ascii")
        line = b"x " * ((LINE - len(fake) - 40) // 2) + b" aws secret " + fake
        assert len(line) <= LINE
        found = [m.rule_id for m in engine.scan(line + b"\n").matches]
        assert rule.id in found, rule.id
