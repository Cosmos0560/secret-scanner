"""CI policy: the workflow is parsed and checked against PLAN.md section 4 (Phase 1, CI).

CI itself cannot be run from here; this test pins the settings that matter, so a later edit that
weakens permissions, drops a platform, or unpins an action fails the gate.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

import pytest
import yaml

from tests.helpers import PROJECT_ROOT

WORKFLOW = PROJECT_ROOT / ".github" / "workflows" / "ci.yml"


@pytest.fixture(name="workflow")
def _workflow() -> dict[Any, Any]:
    loaded = yaml.safe_load(WORKFLOW.read_text(encoding="utf-8"))
    assert isinstance(loaded, dict)
    return loaded


def _job(workflow: dict[Any, Any]) -> dict[str, Any]:
    jobs = workflow["jobs"]
    assert list(jobs) == ["gate"]
    job = jobs["gate"]
    assert isinstance(job, dict)
    return job


def test_triggers_are_push_to_main_and_pull_requests(workflow: dict[Any, Any]) -> None:
    # YAML 1.1 reads the key `on` as the boolean True.
    triggers: dict[str, Any] = workflow[True] if True in workflow else workflow["on"]
    assert set(triggers) == {"push", "pull_request"}
    assert triggers["push"]["branches"] == ["main"]


def test_permissions_are_read_only_at_workflow_and_job_level(workflow: dict[Any, Any]) -> None:
    assert workflow["permissions"] == {"contents": "read"}
    assert "permissions" not in _job(workflow) or _job(workflow)["permissions"] == {
        "contents": "read"
    }


def test_concurrency_cancels_superseded_runs(workflow: dict[Any, Any]) -> None:
    concurrency = workflow["concurrency"]
    assert concurrency["cancel-in-progress"] is True
    assert "github.ref" in concurrency["group"]


def test_matrix_covers_both_operating_systems_and_three_pythons(
    workflow: dict[Any, Any],
) -> None:
    strategy = _job(workflow)["strategy"]
    assert strategy["fail-fast"] is False
    matrix = strategy["matrix"]
    assert matrix["os"] == ["ubuntu-24.04", "windows-latest"]
    assert [str(version) for version in matrix["python-version"]] == ["3.11", "3.12", "3.13"]
    assert not matrix.get("include")
    assert not matrix.get("exclude")


def test_job_has_a_timeout(workflow: dict[Any, Any]) -> None:
    assert _job(workflow)["timeout-minutes"] == 15


def test_actions_are_the_approved_versions_with_safe_options(workflow: dict[Any, Any]) -> None:
    steps = _job(workflow)["steps"]
    uses = {step["uses"]: step for step in steps if "uses" in step}
    assert set(uses) == {"actions/checkout@v5", "actions/setup-python@v6"}
    checkout = uses["actions/checkout@v5"]["with"]
    assert checkout["fetch-depth"] == 0
    assert checkout["persist-credentials"] is False
    setup = uses["actions/setup-python@v6"]["with"]
    assert setup["python-version"] == "${{ matrix.python-version }}"


def test_steps_install_the_dev_extra_and_run_the_full_gate_unfiltered(
    workflow: dict[Any, Any],
) -> None:
    commands = [step["run"] for step in _job(workflow)["steps"] if "run" in step]
    assert commands == [
        'python -m pip install -e ".[dev]"',
        "python scripts/gate.py --full",
    ]
    gate_command = commands[-1]
    assert not any(token in gate_command for token in ("|", ">", "||", "; "))


def test_job_runs_on_the_matrix_os(workflow: dict[Any, Any]) -> None:
    assert _job(workflow)["runs-on"] == "${{ matrix.os }}"


def test_no_secrets_or_write_scopes_anywhere_in_the_workflow() -> None:
    text = WORKFLOW.read_text(encoding="utf-8")
    assert "secrets." not in text
    assert "write" not in text
    assert "pull_request_target" not in text
    assert Path(WORKFLOW).name == "ci.yml"
