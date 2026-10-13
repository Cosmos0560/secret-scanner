"""Exit codes, precedence and the exception hierarchy (PLAN.md D10)."""

from __future__ import annotations

import itertools
import re

import pytest

from secret_scanner.core import errors
from secret_scanner.core.errors import ExitCode, combine_exit_codes
from tests.helpers import PROJECT_ROOT


def _section(text: str, heading: str) -> str:
    start = text.index(heading)
    end = text.find("\n### ", start + 1)
    return text[start : end if end != -1 else len(text)]


def test_exit_code_values() -> None:
    assert {code.name: int(code) for code in ExitCode} == {
        "OK": 0,
        "FINDINGS": 1,
        "USAGE": 2,
        "GIT": 3,
        "INCOMPLETE": 4,
    }


def test_precedence_is_two_three_four_one_zero() -> None:
    assert [int(code) for code in errors.EXIT_PRECEDENCE] == [2, 3, 4, 1, 0]
    assert set(errors.EXIT_PRECEDENCE) == set(ExitCode)


@pytest.mark.parametrize(
    ("codes", "expected"),
    [
        ([], ExitCode.OK),
        ([ExitCode.OK], ExitCode.OK),
        ([ExitCode.FINDINGS], ExitCode.FINDINGS),
        ([ExitCode.FINDINGS, ExitCode.INCOMPLETE], ExitCode.INCOMPLETE),
        ([ExitCode.INCOMPLETE, ExitCode.GIT], ExitCode.GIT),
        ([ExitCode.GIT, ExitCode.USAGE], ExitCode.USAGE),
        (
            [ExitCode.OK, ExitCode.FINDINGS, ExitCode.INCOMPLETE, ExitCode.GIT, ExitCode.USAGE],
            ExitCode.USAGE,
        ),
    ],
)
def test_combine_exit_codes(codes: list[ExitCode], expected: ExitCode) -> None:
    assert combine_exit_codes(codes) == expected


def test_precedence_is_total_over_every_pair() -> None:
    order = {code: index for index, code in enumerate(errors.EXIT_PRECEDENCE)}
    for first, second in itertools.permutations(ExitCode, 2):
        winner = first if order[first] < order[second] else second
        assert combine_exit_codes([first, second]) == winner


def test_each_error_class_maps_to_one_exit_code() -> None:
    assert errors.UsageError.exit_code is ExitCode.USAGE
    assert errors.ConfigError.exit_code is ExitCode.USAGE
    assert errors.ScanIOError.exit_code is ExitCode.USAGE
    assert errors.GitError.exit_code is ExitCode.GIT
    assert errors.IncompleteRunError.exit_code is ExitCode.INCOMPLETE
    assert issubclass(errors.UsageError, errors.SecretScannerError)


def test_error_messages_are_sanitised_and_bounded() -> None:
    hostile = "bad name " + chr(0x1B) + "[31m" + chr(0x202E) + "\n" + "x" * 2000
    error = errors.UsageError(hostile)
    message = str(error)
    assert chr(0x1B) not in message
    assert chr(0x202E) not in message
    assert "\n" not in message
    assert len(message) <= errors.MAX_ERROR_MESSAGE_CHARS


def test_plan_md_exit_codes_and_precedence_match_the_code() -> None:
    plan = (PROJECT_ROOT / "PLAN.md").read_text(encoding="utf-8")
    d10 = " ".join(_section(plan, "### D10").split())
    precedence = re.search(r"Precedence: ((?:\d > )+\d)", d10)
    assert precedence is not None
    assert precedence.group(1) == " > ".join(str(int(code)) for code in errors.EXIT_PRECEDENCE)
    documented = dict(re.findall(r"`(\d)` ([a-z]+)", d10))
    assert set(documented) == {str(int(code)) for code in ExitCode}
    assert documented["0"] == "clean"
    assert documented["1"] == "findings"
    assert documented["2"] == "usage"
    assert documented["3"] == "git"
    assert documented["4"] == "incomplete"


def test_unknown_key_errors_list_the_allowed_keys_and_never_echo_the_key() -> None:
    from secret_scanner.core.errors import ConfigError, unknown_key_error

    error = unknown_key_error("config", ["version", "exclude"])
    assert isinstance(error, ConfigError)
    assert str(error) == "config: unknown key (allowed: exclude, version)"
