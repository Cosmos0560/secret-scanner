"""Release metadata: what `pyproject.toml` says about the project is what the owner decided, and
the version has one source that the metadata, the command line and the changelog agree with.

Files are read as data (`tomllib`, text); nothing is built or installed here.
"""

from __future__ import annotations

import datetime
import importlib.metadata
import re
import tomllib
from typing import Any

import pytest

from secret_scanner import __version__
from secret_scanner.cli import main as cli_main
from tests.helpers import PROJECT_ROOT

PYPROJECT = PROJECT_ROOT / "pyproject.toml"
STATUS_PREFIX = "Development Status :: "


@pytest.fixture(name="project", scope="module")
def _project() -> dict[str, Any]:
    document = tomllib.loads(PYPROJECT.read_text(encoding="utf-8"))
    project = document["project"]
    assert isinstance(project, dict)
    return project


def test_the_development_status_is_beta(project: dict[str, Any]) -> None:
    """Owner decision of 2026-11-10 (PLAN.md v0.14): a first public release, measured on one
    machine, is Beta; exactly one status classifier is declared."""
    statuses = [c for c in project["classifiers"] if c.startswith(STATUS_PREFIX)]
    assert statuses == ["Development Status :: 4 - Beta"]


def test_the_metadata_names_no_address_and_one_runtime_dependency(project: dict[str, Any]) -> None:
    """CLAUDE.md section 1 (no email address, name only) and PLAN.md D20 (PyYAML only)."""
    assert all(set(author) == {"name"} for author in project["authors"])
    assert "maintainers" not in project
    assert [d.split(">=")[0] for d in project["dependencies"]] == ["PyYAML"]


# -- one version, everywhere (Phase 6) ------------------------------------------------------------

VERSION_SOURCE = PROJECT_ROOT / "src" / "secret_scanner" / "__init__.py"
CHANGELOG = PROJECT_ROOT / "CHANGELOG.md"
VERSION_LINE = re.compile(r'^__version__ = "([^"\n]+)"$', re.MULTILINE)
RELEASE_HEADING = re.compile(r"^## (\S+) - (\d{4})-(\d\d)-(\d\d)$", re.MULTILINE)


def test_the_version_has_one_source_and_pyproject_reads_it() -> None:
    document = tomllib.loads(PYPROJECT.read_text(encoding="utf-8"))
    project = document["project"]
    assert "version" not in project, "no second copy of the version in pyproject.toml"
    assert project["dynamic"] == ["version"]
    source = PROJECT_ROOT / document["tool"]["hatch"]["version"]["path"]
    assert source == VERSION_SOURCE
    assert VERSION_LINE.findall(VERSION_SOURCE.read_text(encoding="utf-8")) == [__version__]


def test_the_version_is_a_release_version() -> None:
    assert re.fullmatch(r"[1-9]\d*\.\d+\.\d+", __version__), "no pre-release or development suffix"


def test_the_installed_metadata_agrees_with_the_version() -> None:
    """The metadata of the installed distribution is written when it is installed. After a change
    of the version, install again: `python -m pip install -e ".[dev]"`."""
    installed = importlib.metadata.version("secret-scanner")
    assert installed == __version__, "the installed metadata is stale: install the project again"
    metadata = importlib.metadata.metadata("secret-scanner")
    assert metadata["Name"] == "secret-scanner"
    assert "Development Status :: 4 - Beta" in metadata.get_all("Classifier", [])


def test_the_command_line_reports_the_version(capsys: pytest.CaptureFixture[str]) -> None:
    assert cli_main.main(["--version"]) == 0
    assert capsys.readouterr().out == f"secret-scanner {__version__}\n"


def test_the_newest_changelog_section_is_the_version_with_a_date() -> None:
    text = CHANGELOG.read_text(encoding="utf-8")
    headings = [line for line in text.splitlines() if line.startswith("## ")]
    assert headings, "CHANGELOG.md has no version section"
    newest = RELEASE_HEADING.fullmatch(headings[0])
    assert newest is not None, "the newest section must be `## <version> - YYYY-MM-DD`"
    assert newest.group(1) == __version__
    year, month, day = (int(newest.group(index)) for index in (2, 3, 4))
    assert datetime.date(year, month, day) >= datetime.date(2026, 11, 10)
    assert all(RELEASE_HEADING.fullmatch(heading) for heading in headings)


def test_the_documents_named_in_the_changelog_exist() -> None:
    text = CHANGELOG.read_text(encoding="utf-8")
    named = set(re.findall(r"`((?:docs|tests|scripts|src)/[\w./-]+|[A-Z]+\.md)`", text))
    assert len(named) >= 10
    missing = sorted(name for name in named if not (PROJECT_ROOT / name).is_file())
    assert missing == []
