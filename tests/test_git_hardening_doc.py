"""docs/git-hardening.md against the runner: every pinned setting, environment variable, command
and bound the page lists is the one the code uses, and the other way round."""

from __future__ import annotations

import os

import pytest

from secret_scanner.core import limits as limits_module
from secret_scanner.core.gitparse import MIN_GIT_VERSION, describe_version
from secret_scanner.gitio import runner as runner_module
from secret_scanner.gitio.runner import (
    FIXED_ENVIRONMENT,
    GLOBAL_OPTIONS,
    PINNED_CONFIG,
    GitCommand,
)
from tests.helpers import PROJECT_ROOT

DOC = (PROJECT_ROOT / "docs" / "git-hardening.md").read_text(encoding="utf-8")


def section(title: str) -> str:
    start = DOC.index(f"## {title}")
    end = DOC.find("\n## ", start + 1)
    return DOC[start : end if end >= 0 else len(DOC)]


def rows(title: str) -> list[list[str]]:
    """The body rows of the first table of a section, cells with backticks and spaces stripped."""
    table = [line for line in section(title).splitlines() if line.startswith("|")]
    body = table[2:]  # header and separator
    return [[cell.strip().strip("`") for cell in line.strip("|").split("|")] for line in body]


def test_the_minimum_version() -> None:
    assert f"Minimum **{describe_version(MIN_GIT_VERSION)}**" in DOC


def test_environment_table_is_the_fixed_environment() -> None:
    documented = {row[0]: row[1] for row in rows("The environment")}
    code = dict(FIXED_ENVIRONMENT)
    assert set(documented) == set(code)
    for name, value in code.items():
        expected = "the null device" if value == os.devnull else value
        assert documented[name] == expected, name


def test_pinned_configuration_table_is_the_pinned_configuration() -> None:
    documented = {row[0]: row[1] for row in rows("Pinned configuration")}
    assert list(documented) == [key for key, _ in PINNED_CONFIG]  # same keys, same order
    for key, value in PINNED_CONFIG:
        expected = "(empty)" if value == "" else value
        assert documented[key] == expected, key


def test_global_options_are_named() -> None:
    text = section("Global options")
    for option in GLOBAL_OPTIONS:
        assert f"`{option}`" in text


def test_command_table_is_the_command_set() -> None:
    documented = {row[0]: row[1] for row in rows("The command set")}
    assert set(documented) == {
        "version",
        "rev-parse",
        "log",
        "cat-file --batch-check",
        "cat-file --batch",
        "ls-files",
    }
    assert {command.value for command in GitCommand} == set(documented)
    fixed = runner_module._FIXED_ARGUMENTS
    for command in (GitCommand.LOG, GitCommand.LS_FILES, GitCommand.CAT_FILE_BATCH):
        assert documented[command.value].split(" (")[0] == " ".join(fixed[command]), command


def test_bounds_table_names_real_constants() -> None:
    for row in rows("Bounds"):
        for constant in row[1].replace("`", "").split(","):
            name = constant.strip()
            assert hasattr(limits_module, name), name


@pytest.mark.parametrize("name", ["--filters", "--textconv", "--follow-symlinks"])
def test_the_page_says_blobs_are_never_converted(name: str) -> None:
    assert name in section("The command set")
    for command in (GitCommand.CAT_FILE_CHECK, GitCommand.CAT_FILE_BATCH):
        assert name not in runner_module._FIXED_ARGUMENTS[command]


def test_every_test_named_in_the_threat_model_exists() -> None:
    """The threat model's controls are claims; each test it names must be a real test function
    (a rename or removal fails here instead of leaving a claim without evidence)."""
    import re

    model = (PROJECT_ROOT / "docs" / "threat-model.md").read_text(encoding="utf-8")
    sources = {
        path.name: path.read_text(encoding="utf-8")
        for path in (PROJECT_ROOT / "tests").glob("test_*.py")
    }
    names = set(re.findall(r"`((?:tests/[a-z_]+\.py::)?test_[a-z0-9_]+)`", model))
    assert names, "the threat model names no tests"
    for name in names:
        file, _, function = name.rpartition("::")
        if file:
            assert f"def {function}(" in sources[os.path.basename(file)], name
        else:
            assert any(f"def {function}(" in text for text in sources.values()), name
