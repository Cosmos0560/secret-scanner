"""Release metadata: what `pyproject.toml` says about the project is what the owner decided.

The file is read as data (`tomllib`); nothing is built or installed here.
"""

from __future__ import annotations

import tomllib
from typing import Any

import pytest

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
