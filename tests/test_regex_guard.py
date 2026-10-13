"""The regex guard (PLAN.md D3): the grammar, the named refusals, the width and cost accounting,
and a timing-independent proof that accepted patterns stay inside the static budget.

Nothing here measures time. The proof is structural: the guard's own width is compared with the
width CPython's parser computes for the same pattern, the cost is a function of that width and the
alternation paths, and a seeded generator checks both on a few thousand patterns.
"""

from __future__ import annotations

import importlib
import random
import re
from dataclasses import replace

import pytest

from secret_scanner.core.errors import ConfigError, ExitCode
from secret_scanner.core.limits import DEFAULT_LIMITS, Limits
from secret_scanner.core.regex_guard import (
    GuardedPattern,
    GuardReason,
    PatternRefusedError,
    compile_pattern,
)

BS = chr(92)
cpython_parser = importlib.import_module("re._parser")


def _refusal(source: str, *, secret: bool = False) -> PatternRefusedError:
    with pytest.raises(PatternRefusedError) as caught:
        compile_pattern(source, with_secret_group=secret)
    return caught.value


# -- the refusal table: every reason, with planted patterns ----------------------------------

REFUSED: list[tuple[str, GuardReason]] = [
    ("a" * 513, GuardReason.TOO_LONG),
    ("café", GuardReason.NOT_ASCII),
    ("a\tb", GuardReason.NOT_ASCII),
    ("a\nb", GuardReason.NOT_ASCII),
    (BS + "x80", GuardReason.NOT_ASCII),
    ("a.b", GuardReason.UNESCAPED_DOT),
    ("^a", GuardReason.ANCHOR),
    ("a$", GuardReason.ANCHOR),
    (BS + "Aa", GuardReason.ANCHOR),
    ("a" + BS + "Z", GuardReason.ANCHOR),
    (BS + "Ba", GuardReason.ANCHOR),
    ("a+", GuardReason.UNBOUNDED_QUANTIFIER),
    ("a*", GuardReason.UNBOUNDED_QUANTIFIER),
    ("a{2,}", GuardReason.UNBOUNDED_QUANTIFIER),
    ("[a-z]+", GuardReason.UNBOUNDED_QUANTIFIER),
    ("*a", GuardReason.UNBOUNDED_QUANTIFIER),
    ("{2}a", GuardReason.BAD_QUANTIFIER),
    ("?a", GuardReason.BAD_QUANTIFIER),
    ("a{,3}", GuardReason.BAD_QUANTIFIER),
    ("a{x}", GuardReason.BAD_QUANTIFIER),
    ("a{3", GuardReason.BAD_QUANTIFIER),
    ("a{1,x}", GuardReason.BAD_QUANTIFIER),
    ("a{0}", GuardReason.BAD_QUANTIFIER),
    ("a{3,2}", GuardReason.BAD_QUANTIFIER),
    (BS + "b?", GuardReason.BAD_QUANTIFIER),
    ("(?=a)?", GuardReason.BAD_QUANTIFIER),
    ("(?:" + BS + "ba){2}", GuardReason.BAD_QUANTIFIER),
    ("a??", GuardReason.LAZY_QUANTIFIER),
    ("a{1,2}?", GuardReason.LAZY_QUANTIFIER),
    ("a?+", GuardReason.LAZY_QUANTIFIER),
    ("a{1,2}+", GuardReason.LAZY_QUANTIFIER),
    ("a{2}{3}", GuardReason.NESTED_QUANTIFIER),
    ("a?{2}", GuardReason.NESTED_QUANTIFIER),
    ("a?*", GuardReason.NESTED_QUANTIFIER),
    ("(?:a{2}){3}", GuardReason.NESTED_QUANTIFIER),
    ("(?:[a-z]{1,10}){1,10}", GuardReason.NESTED_QUANTIFIER),
    ("(?:a?)?", GuardReason.NESTED_QUANTIFIER),
    ("(?:a|ab){1,5}", GuardReason.ALTERNATION_IN_QUANTIFIED_GROUP),
    ("(?:a|b)?", GuardReason.ALTERNATION_IN_QUANTIFIED_GROUP),
    ("(?:a)" + BS + "1", GuardReason.BACKREFERENCE),
    ("(?P=secret)", GuardReason.BACKREFERENCE),
    ("[" + BS + "1]", GuardReason.BACKREFERENCE),
    ("(?(1)a|b)", GuardReason.CONDITIONAL),
    ("a(?i)b", GuardReason.INLINE_FLAG),
    ("(?s)a", GuardReason.INLINE_FLAG),
    ("(?i:a)", GuardReason.INLINE_FLAG),
    ("(?im)a", GuardReason.INLINE_FLAG),
    ("(a)", GuardReason.UNSUPPORTED_GROUP),
    ("(?<name>a)", GuardReason.UNSUPPORTED_GROUP),
    ("(?P<other>a)", GuardReason.UNSUPPORTED_GROUP),
    ("(?#comment)a", GuardReason.UNSUPPORTED_GROUP),
    ("(?>a)", GuardReason.UNSUPPORTED_GROUP),
    ("(", GuardReason.UNSUPPORTED_GROUP),
    (BS + "p", GuardReason.UNSUPPORTED_ESCAPE),
    (BS + "X", GuardReason.UNSUPPORTED_ESCAPE),
    (BS + "u0041", GuardReason.UNSUPPORTED_ESCAPE),
    (BS + "N", GuardReason.UNSUPPORTED_ESCAPE),
    (BS + "0", GuardReason.UNSUPPORTED_ESCAPE),
    (BS + "xZZ", GuardReason.UNSUPPORTED_ESCAPE),
    ("[" + BS + "b]", GuardReason.UNSUPPORTED_ESCAPE),
    ("[]", GuardReason.BAD_CLASS),
    ("[a", GuardReason.BAD_CLASS),
    ("[z-a]", GuardReason.BAD_CLASS),
    ("[[:alpha:]]", GuardReason.BAD_CLASS),
    ("[a--b]", GuardReason.BAD_CLASS),
    ("[a&&b]", GuardReason.BAD_CLASS),
    ("[a-" + BS + "d]", GuardReason.BAD_CLASS),
    ("[^" + BS + "d" + BS + "D]", GuardReason.BAD_CLASS),
    ("[a" + BS, GuardReason.BAD_CLASS),
    ("(?<=a{1,3})b", GuardReason.LOOKAROUND_FORM),
    ("(?=)a", GuardReason.LOOKAROUND_FORM),
    ("(?!ab)a", GuardReason.LOOKAROUND_FORM),
    ("(?<![a-z]{2})a", GuardReason.LOOKAROUND_FORM),
    ("(?=.)a", GuardReason.LOOKAROUND_FORM),
    ("(?<=" + BS + "b)a", GuardReason.LOOKAROUND_FORM),
    ("a)", GuardReason.UNBALANCED),
    ("(?:a", GuardReason.UNBALANCED),
    ("a}", GuardReason.UNBALANCED),
    ("a]", GuardReason.UNBALANCED),
    ("a" + BS, GuardReason.UNBALANCED),
    ("(?:" * 7 + "a" + ")" * 7, GuardReason.TOO_DEEP),
    ("", GuardReason.EMPTY_MATCH),
    ("a?", GuardReason.EMPTY_MATCH),
    ("(?:)", GuardReason.EMPTY_MATCH),
    ("a||b", GuardReason.EMPTY_MATCH),
    ("(?:a|)", GuardReason.EMPTY_MATCH),
    (BS + "b", GuardReason.EMPTY_MATCH),
    ("(?=a)", GuardReason.EMPTY_MATCH),
    ("a{1,2000}", GuardReason.TOO_WIDE),
    ("[a-z]{1,600}x[a-z]{1,600}", GuardReason.TOO_WIDE),
    ("|".join(["[a-z]{1,300}-[0-9]{1,300}"] * 14), GuardReason.TOO_COSTLY),
    ("[a-z]{1,9}[a-z]{1,9}", GuardReason.ADJACENT_VARIABLE),
    ("[a-z]{1,9}a[a-z]{1,9}", GuardReason.ADJACENT_VARIABLE),
    ("[a-z]{1,9}-?[a-z]{1,9}", GuardReason.ADJACENT_VARIABLE),
    ("[a-z]{1,9}[0-9]{0,9}[a-z]{1,9}", GuardReason.ADJACENT_VARIABLE),
    ("(?:ab|c[a-z]{1,3})[a-z]{1,3}", GuardReason.ADJACENT_VARIABLE),
    ("[a-z]{1,5}(?:[0-9]|[a-z])[a-z]{1,5}", GuardReason.ADJACENT_VARIABLE),
    ("x[a-z]{0,5}[a-z]?", GuardReason.ADJACENT_VARIABLE),
    ("[" + BS + "d-z]", GuardReason.NOT_COMPILABLE),
]


@pytest.mark.parametrize(("source", "reason"), REFUSED)
def test_pattern_is_refused_with_its_named_reason(source: str, reason: GuardReason) -> None:
    assert _refusal(source).reason is reason


def test_every_reason_has_a_planted_pattern() -> None:
    covered = {reason for _, reason in REFUSED} | {GuardReason.SECRET_GROUP}
    assert covered == set(GuardReason)


# -- the hostile table of PLAN.md D3, verbatim ------------------------------------------------

HOSTILE_D3 = [
    "(a+)+$",
    "(a|a)*",
    "(.*a){20}",
    r"\d+\d+",
    r"(a)\1",
    "a{1,100000}",
    "(?:[a-z]{1,10}){1,10}",
    "[a-z]*",
    "[A-Za-z0-9]+",
    "(?<=a{1,3})b",
    "x" * 600,
    "(?:a|a)*",
    "(?:a|aa)+",
    "((a)*)*b",
    "(x+x+)+y",
    "(?:[a-z]+)*",
    "a{1,}",
    "(?:.|a){1,50}",
]


@pytest.mark.parametrize("source", HOSTILE_D3)
def test_every_hostile_pattern_is_rejected_at_load_time(source: str) -> None:
    refusal = _refusal(source)
    assert isinstance(refusal.reason, GuardReason)
    assert isinstance(refusal, ConfigError)  # exit code 2, never a crash
    assert refusal.exit_code is ExitCode.USAGE


def test_refusal_message_names_reason_and_does_not_echo_the_pattern() -> None:
    refusal = _refusal("a+" + "Q" * 40)
    assert "unbounded-quantifier" in str(refusal)
    assert "QQQQ" not in str(refusal)


# -- the secret group -------------------------------------------------------------------------


def test_rule_patterns_need_exactly_one_secret_group() -> None:
    assert _refusal("abc", secret=True).reason is GuardReason.SECRET_GROUP
    assert _refusal("(?P<secret>a)(?P<secret>b)", secret=True).reason is GuardReason.SECRET_GROUP
    assert _refusal("(?P<secret>a(?P<secret>b))", secret=True).reason is GuardReason.SECRET_GROUP
    assert _refusal("(?P<secret>a){2}", secret=True).reason is GuardReason.SECRET_GROUP
    grouped = _refusal("(?:x(?P<secret>a)){2}", secret=True)
    assert grouped.reason is GuardReason.SECRET_GROUP
    assert _refusal("(?:x(?P<secret>a))?", secret=True).reason is GuardReason.SECRET_GROUP
    assert compile_pattern("x(?P<secret>[a-z]{4})", with_secret_group=True).width_max == 5


def test_internal_patterns_may_not_have_a_secret_group() -> None:
    assert _refusal("(?P<secret>a)").reason is GuardReason.SECRET_GROUP


# -- accepted patterns: widths, paths, cost, bits ---------------------------------------------

ACCEPTED: list[tuple[str, tuple[int, int], int]] = [
    ("abc", (3, 3), 1),
    (BS + "d{3}-" + BS + "d{4}", (8, 8), 1),
    ("(?i)akia[a-z2-7]{16}", (20, 20), 1),
    ("(?:AKIA|ASIA)[A-Z2-7]{16}", (20, 20), 2),
    ("(?:AKIA|ASIA|ABIA|ACCA)[A-Z2-7]{16}", (20, 20), 4),
    (BS + "bfoo" + BS + "b", (3, 3), 1),
    ("a{1,3}-b{1,3}", (3, 7), 1),
    ("[a-z]{1,9}1[0-9]{1,9}", (3, 19), 1),
    ("(?:ab){2}", (4, 4), 1),
    ("(?:ab)?c", (1, 3), 1),
    ("(?<![A-Za-z0-9])x{3}(?![A-Za-z0-9])", (3, 3), 1),
    ("[^" + BS + 'x00-"]{2}', (2, 2), 1),
    ("[A-Za-z0-9+/=_-]{20,256}", (20, 256), 1),
    (BS + "." + BS + "-" + BS + "t" + BS + "x41", (4, 4), 1),
    ("a|b|c", (1, 1), 3),
    ("(?<!" + BS + "w)x{3}(?!" + BS + "w)", (3, 3), 1),
    ("hooks" + BS + ".slack" + BS + ".com/services/", (25, 25), 1),
]


@pytest.mark.parametrize(("source", "width", "paths"), ACCEPTED)
def test_accepted_pattern_accounting(source: str, width: tuple[int, int], paths: int) -> None:
    pattern = compile_pattern(source)
    assert (pattern.width_min, pattern.width_max) == width
    assert pattern.paths == paths
    assert pattern.cost == width[1] * paths
    assert pattern.cost <= DEFAULT_LIMITS.max_pattern_cost
    assert pattern.source == source
    assert repr(source) in repr(pattern)


def test_top_level_alternatives_are_counted() -> None:
    assert compile_pattern("a|b|c").alternatives == 3
    assert compile_pattern("(?:a|b)(?:c|d)").alternatives == 1
    assert compile_pattern("(?:a|b)(?:c|d)").paths == 4


def test_secret_bits_and_public_prefix_are_computed_from_the_group() -> None:
    pattern = compile_pattern("x(?P<secret>gh[pousr]_[A-Za-z0-9]{36})", with_secret_group=True)
    assert pattern.secret_min_width == 40
    assert pattern.secret_public_chars == 4  # g, h, [pousr], _
    assert 36 * 5.9 < pattern.secret_bits < 36 * 5.96 + 3
    fixed = compile_pattern("(?P<secret>abcd)", with_secret_group=True)
    assert fixed.secret_bits == 0
    assert fixed.secret_public_chars == 4
    alt = compile_pattern("(?P<secret>(?:AKIA|ASIA)[A-Z2-7]{16})", with_secret_group=True)
    assert alt.secret_public_chars == 4
    assert alt.secret_bits == pytest.approx(80.0)
    variable = compile_pattern("(?P<secret>ab[0-9]{2,5})", with_secret_group=True)
    assert variable.secret_public_chars == 2
    assert variable.secret_bits == pytest.approx(2 * 3.3219, abs=0.01)
    optional = compile_pattern("(?P<secret>[a-z]{4}-?[0-9]{4})", with_secret_group=True)
    assert optional.secret_bits == pytest.approx(4 * 4.7004 + 4 * 3.3219, abs=0.01)
    assert (
        compile_pattern("(?P<secret>(?:ab){2}[0-9]{5})", with_secret_group=True).secret_public_chars
        == 4
    )
    assert (
        compile_pattern("(?P<secret>\\bab[0-9]{9})", with_secret_group=True).secret_public_chars
        == 2
    )


def test_limits_can_be_lowered_and_are_respected() -> None:
    tight = replace(DEFAULT_LIMITS, max_pattern_chars=16, max_match_chars=10, max_pattern_cost=12)
    assert compile_pattern("abcdefgh", limits=tight).width_max == 8
    with pytest.raises(PatternRefusedError) as too_long:
        compile_pattern("abcdefghijklmnopq", limits=tight)
    assert too_long.value.reason is GuardReason.TOO_LONG
    with pytest.raises(PatternRefusedError) as too_wide:
        compile_pattern("abcdefghijk", limits=tight)
    assert too_wide.value.reason is GuardReason.TOO_WIDE
    with pytest.raises(PatternRefusedError) as too_costly:
        compile_pattern("abcdefg|hijklmn", limits=tight)
    assert too_costly.value.reason is GuardReason.TOO_COSTLY


def test_a_pattern_at_the_cost_ceiling_is_accepted_and_one_above_is_not() -> None:
    cost_limit = replace(DEFAULT_LIMITS, max_pattern_cost=14)
    assert compile_pattern("abcdefg|hijklmn", limits=cost_limit).cost == 14
    below = replace(DEFAULT_LIMITS, max_pattern_cost=13)
    assert _refusal_with("abcdefg|hijklmn", below).reason is GuardReason.TOO_COSTLY


def _refusal_with(source: str, limits: Limits) -> PatternRefusedError:
    with pytest.raises(PatternRefusedError) as caught:
        compile_pattern(source, limits=limits)
    return caught.value


# -- delimiters -------------------------------------------------------------------------------


def test_variable_items_separated_by_a_required_delimiter_are_accepted() -> None:
    for source in [
        "[0-9]{10,13}-[0-9]{10,13}-[0-9]{10,13}",
        "T[A-Za-z0-9]{8,12}/B[A-Za-z0-9]{8,12}/[A-Za-z0-9]{24}",
        "[a-z]{1,9}[0-9]{1,9}",  # disjoint classes: the second cannot start inside the first
        "[a-z]{1,9}(?:-|_)[a-z]{1,9}",
        "[a-z]{1,9}(?:ab|cd)[A-Z]{1,9}",
        "(?:[a-z]{1,9}|[0-9]{3})-[a-z]{1,9}",
    ]:
        assert compile_pattern(source).cost <= DEFAULT_LIMITS.max_pattern_cost, source


def test_fixed_count_repeats_can_delimit() -> None:
    assert compile_pattern("[a-z]{1,9}-{2}[a-z]{1,9}").width_max == 20
    assert compile_pattern("[a-z]{1,9}(?:--){2}[a-z]{1,9}").width_max == 22


# -- the proof that the accounting is sound ---------------------------------------------------


def _cpython_width(source: str) -> tuple[int, int]:
    low, high = cpython_parser.parse(source.encode("ascii")).getwidth()
    return int(low), int(high)


@pytest.mark.parametrize("source", [source for source, _, _ in ACCEPTED])
def test_width_agrees_with_cpythons_own_parser(source: str) -> None:
    pattern = compile_pattern(source)
    assert (pattern.width_min, pattern.width_max) == _cpython_width(source)


def _random_pattern(rng: random.Random) -> str:
    atoms = ["a", "b", "7", "-", "_", "[a-c]", "[0-9]", "[A-Za-z0-9]", BS + "d", BS + "w", "[^a]"]
    parts: list[str] = []
    for _ in range(rng.randint(1, 6)):
        kind = rng.random()
        atom = rng.choice(atoms)
        if kind < 0.4:
            parts.append(atom)
        elif kind < 0.7:
            parts.append(f"{atom}{{{rng.randint(1, 4)}}}")
        elif kind < 0.9:
            low = rng.randint(0, 3)
            parts.append(f"{atom}{{{low},{low + rng.randint(1, 6)}}}")
        elif kind < 0.95:
            parts.append(f"(?:{rng.choice(atoms)}|{rng.choice(atoms)})")
        else:
            parts.append(f"(?:{rng.choice(atoms)}{rng.choice(atoms)}){{{rng.randint(1, 3)}}}")
    pattern = "".join(parts)
    if rng.random() < 0.15:
        pattern = f"{pattern}|{rng.choice(atoms)}{{{rng.randint(1, 5)}}}"
    return pattern


@pytest.mark.parametrize(
    ("count", "min_accepted", "min_refused"),
    [
        # The default gate draws the first 300 patterns of the seeded sequence; the full gate and CI
        # draw all 1500 (measured: 276 / 24 and 1375 / 125 accepted / refused).
        pytest.param(300, 200, 10, id="300"),
        pytest.param(1500, 250, 50, id="1500", marks=pytest.mark.slow),
    ],
)
def test_generated_accepted_patterns_are_inside_the_budget_and_widths_are_sound(
    count: int, min_accepted: int, min_refused: int
) -> None:
    rng = random.Random(20261012)
    accepted = 0
    refused = 0
    for _ in range(count):
        source = _random_pattern(rng)
        try:
            pattern = compile_pattern(source)
        except PatternRefusedError:
            refused += 1
            continue
        accepted += 1
        assert pattern.cost == pattern.width_max * pattern.paths
        assert pattern.cost <= DEFAULT_LIMITS.max_pattern_cost
        assert pattern.width_max <= DEFAULT_LIMITS.max_match_chars
        assert len(source) <= DEFAULT_LIMITS.max_pattern_chars
        assert (pattern.width_min, pattern.width_max) == _cpython_width(source)
        probe = re.compile(source.encode("ascii"))
        for _sample in range(10):
            text = bytes(rng.choice(b"ab7-_cA09z") for _ in range(rng.randint(0, 40)))
            for found in probe.finditer(text):
                assert pattern.width_min <= found.end() - found.start() <= pattern.width_max
    assert accepted > min_accepted
    assert refused > min_refused  # the generator does produce hostile shapes


def test_only_compile_pattern_makes_a_guarded_pattern() -> None:
    with pytest.raises(TypeError):
        GuardedPattern(
            object(),
            source="a",
            compiled=re.compile(b"a"),
            has_secret=False,
            width=(1, 1),
            alternatives=1,
            paths=1,
            secret_bits=0.0,
            secret_min_width=1,
            secret_public_chars=0,
            ignore_case=False,
        )


# -- matching ---------------------------------------------------------------------------------


def test_finditer_reports_match_and_secret_spans() -> None:
    pattern = compile_pattern("key=(?P<secret>[a-z]{4})", with_secret_group=True)
    spans = [
        (m.start, m.end, m.secret_start, m.secret_end) for m in pattern.finditer(b"..key=abcd.")
    ]
    assert spans == [(2, 10, 6, 10)]
    plain = compile_pattern("[0-9]{2}")
    assert [(m.start, m.end, m.secret_start, m.secret_end) for m in plain.finditer(b"a12b34")] == [
        (1, 3, 1, 3),
        (4, 6, 4, 6),
    ]
    assert plain.search(b"zz") is None
    first = plain.search(b"a12b34")
    assert first is not None
    assert first.start == 1


def test_matching_is_ascii_only_on_bytes() -> None:
    word = compile_pattern(BS + "w{3}")
    assert word.search("ééé".encode()) is None  # UTF-8 bytes are not \w
    assert word.search(b"ab_") is not None
    insensitive = compile_pattern("(?i)akia")
    assert insensitive.ignore_case
    assert insensitive.search(b"xx AkIa xx") is not None
    assert compile_pattern("akia").search(b"AKIA") is None


def test_ignore_case_extends_negated_classes_correctly() -> None:
    pattern = compile_pattern("(?i)[^a]{2}")
    assert pattern.search(b"AA") is None
    assert pattern.search(b"Ab") is None
    assert pattern.search(b"bc") is not None
    assert pattern.search(b"\xff\xfe") is not None
