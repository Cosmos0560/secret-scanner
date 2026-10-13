"""The segment-wise glob matcher (PLAN.md D9, D13): semantics, refusals, pathological input."""

from __future__ import annotations

import pytest

from secret_scanner.core.errors import ConfigError
from secret_scanner.core.globs import any_match, compile_glob, compile_globs
from secret_scanner.core.limits import DEFAULT_LIMITS

MATCHES = [
    # (pattern, path, expected)
    ("a.txt", "a.txt", True),
    ("a.txt", "b/a.txt", False),  # anchored: a bare name matches only at the root
    ("**/a.txt", "a.txt", True),  # `**` also matches zero segments
    ("**/a.txt", "x/y/a.txt", True),
    ("*.pem", "key.pem", True),
    ("*.pem", "dir/key.pem", False),  # `*` does not cross a separator
    ("**/*.pem", "dir/sub/key.pem", True),
    ("**/*.pem", ".hidden.pem", True),  # dot files are ordinary names
    ("tests/fixtures/**", "tests/fixtures", True),
    ("tests/fixtures/**", "tests/fixtures/a/b.txt", True),
    ("tests/fixtures/**", "tests/other/b.txt", False),
    ("tests/fixtures", "tests/fixtures/a.txt", False),  # no implicit directory match
    ("src/**/gen.py", "src/gen.py", True),
    ("src/**/gen.py", "src/a/b/gen.py", True),
    ("src/**/gen.py", "src/a/b/gen.pyc", False),
    ("**", "anything/at/all", True),
    ("**", "x", True),
    ("**/**", "x/y", True),
    ("a?c", "abc", True),
    ("a?c", "ac", False),
    ("a?c", "abbc", False),
    ("[abc].txt", "b.txt", True),
    ("[abc].txt", "d.txt", False),
    ("[a-c].txt", "b.txt", True),
    ("[a-c].txt", "e.txt", False),
    ("[!a-c].txt", "e.txt", True),
    ("[!a-c].txt", "b.txt", False),
    ("[^a-c].txt", "e.txt", True),
    ("[]a].txt", "].txt", True),  # a leading ] is a literal member
    ("[a-].txt", "-.txt", True),  # a trailing - is a literal member
    ("[*].txt", "*.txt", True),  # the only way to write a literal star
    ("[*].txt", "a.txt", False),
    ("a*b*c", "aXXbYYc", True),
    ("a*b*c", "abc", True),
    ("a*b*c", "acb", False),
    ("*", "", True),  # an empty name (never produced by a walk) still matches a lone star
    ("a**b", "axxb", True),  # `**` inside a segment is an ordinary star
    ("A.txt", "a.txt", False),  # case-sensitive on every platform
    ("é*", "été", True),
]


@pytest.mark.parametrize(("pattern", "path", "expected"), MATCHES)
def test_semantics_table(pattern: str, path: str, expected: bool) -> None:
    assert compile_glob(pattern).matches(path) is expected


REFUSED = [
    ("", "is empty"),
    ("/abs/path", "must be relative"),
    ("a//b", "empty segment"),
    ("a/", "empty segment"),
    ("a/./b", "'.' segment"),
    ("a/../b", "'..' segment"),
    ("a\\b", "backslash"),
    ("a\x00b", "control character"),
    ("a\nb", "control character"),
    ("a\x7fb", "control character"),
    ("[abc", "not closed"),
    ("[", "not closed"),
    ("[!", "not closed"),
    ("[z-a].txt", "runs backwards"),
    ("a/[b/c]", "not closed"),  # a separator cannot sit inside a set
    ("x" * 513, "longer than 512"),
]


@pytest.mark.parametrize(("pattern", "reason"), REFUSED)
def test_malformed_patterns_are_refused_with_a_reason(pattern: str, reason: str) -> None:
    with pytest.raises(ConfigError, match=reason):
        compile_glob(pattern)


def test_the_error_never_carries_an_unsanitised_pattern() -> None:
    with pytest.raises(ConfigError) as caught:
        compile_glob("\x1b[31m" + "x" * 200 + "\n")
    assert "\x1b" not in str(caught.value)
    assert "\n" not in str(caught.value)


def test_a_non_string_pattern_is_refused() -> None:
    with pytest.raises(ConfigError, match="must be a string"):
        compile_glob(7)  # type: ignore[arg-type]


def test_a_pattern_exactly_at_the_length_limit_is_accepted() -> None:
    assert compile_glob("x" * 512).matches("x" * 512)


def test_globs_count_is_bounded() -> None:
    assert len(compile_globs(["a"] * 256)) == 256
    with pytest.raises(ConfigError, match="more than 256 globs"):
        compile_globs(["a"] * 257, what="exclude")


def test_limits_can_lower_the_bounds() -> None:
    limits = DEFAULT_LIMITS.with_overrides({"max_glob_chars": 5, "max_globs": 2})
    with pytest.raises(ConfigError, match="longer than 5"):
        compile_glob("abcdef", limits)
    with pytest.raises(ConfigError, match="more than 2"):
        compile_globs(["a", "b", "c"], limits)


def test_any_match() -> None:
    globs = compile_globs(["a/**", "*.key"])
    assert any_match(globs, "a/b")
    assert any_match(globs, "x.key")
    assert not any_match(globs, "b/x.key")
    assert not any_match((), "anything")


def test_pathological_patterns_stay_polynomial() -> None:
    # Classic exponential cases for backtracking matchers; the answer must simply come back.
    text = "a" * 4000
    assert not compile_glob("*a*a*a*a*a*a*a*a*a*a*b").matches(text)
    assert compile_glob("*a*a*a*a*a*a*a*a*a*a*").matches(text)
    deep = "/".join(["d"] * 400)
    assert not compile_glob("**/**/**/**/**/**/**/x").matches(deep)
    assert compile_glob("**/**/**/**/**/**/**/d").matches(deep)


def test_a_path_with_many_segments_and_a_leading_globstar() -> None:
    assert compile_glob("**/z").matches("/".join(["a"] * 500 + ["z"]))
    assert not compile_glob("z/**").matches("/".join(["a"] * 500 + ["z"]))


def test_a_refused_entry_is_named_by_position_and_never_echoed() -> None:
    with pytest.raises(ConfigError) as caught:
        compile_globs(["ok", "token_" + "A1b2C3" * 5 + "/../x"], what="config.exclude")
    assert str(caught.value) == "config.exclude[1]: glob has a '..' segment"
