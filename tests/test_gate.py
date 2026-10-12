"""The gate runner: step list, summary, exit status, log file and a real streamed step."""

from __future__ import annotations

import io
import re
import sys
from pathlib import Path

import pytest

from scripts import gate
from scripts.gate import Step, StepResult


class _Clock:
    def __init__(self) -> None:
        self.now = 0.0

    def __call__(self) -> float:
        self.now += 1.5
        return self.now


def _runner(failing: set[str]) -> gate.Runner:
    def run(step: Step, cwd: Path, emit: gate.Emit) -> int:
        emit(f"output of {step.name}")
        return 1 if step.name in failing else 0

    return run


def test_steps_are_the_six_gate_steps_in_order() -> None:
    steps = gate.build_steps("py", full=False)
    assert [step.name for step in steps] == [
        "ruff check",
        "ruff format --check",
        "mypy --platform linux",
        "mypy --platform win32",
        "check_architecture",
        "pytest (fast)",
    ]
    assert steps[2].argv[-2:] == ("--platform", "linux")
    assert steps[3].argv[-2:] == ("--platform", "win32")
    assert steps[4].argv == ("py", "scripts/check_architecture.py")
    assert all(step.argv[0] == "py" for step in steps)


def test_fast_gate_excludes_slow_tests_and_full_gate_does_not() -> None:
    fast = gate.build_steps("py", full=False)[-1].argv
    full = gate.build_steps("py", full=True)[-1].argv
    assert fast[-2:] == ("-m", "not slow")
    assert "not slow" not in full
    for argv in (fast, full):
        assert "--cov-branch" in argv
        assert f"--cov-fail-under={gate.COVERAGE_FLOOR}" in argv
        assert "-rs" in argv
    assert gate.build_steps("py", full=True)[-1].name == "pytest (full)"


def test_coverage_floor_matches_pyproject() -> None:
    text = (gate.ROOT / "pyproject.toml").read_text(encoding="utf-8")
    assert f"fail_under = {gate.COVERAGE_FLOOR}" in text


def test_all_green_exits_zero_and_prints_a_summary() -> None:
    out = io.StringIO()
    code = gate.main([], runner=_runner(set()), clock=_Clock(), python="py", out=out)
    text = out.getvalue()
    assert code == 0
    assert "== gate summary ==" in text
    assert "PASSED" in text
    assert text.count("PASS ") == 6


def test_one_failure_runs_every_step_and_exits_one() -> None:
    out = io.StringIO()
    code = gate.main(
        [], runner=_runner({"mypy --platform win32"}), clock=_Clock(), python="py", out=out
    )
    text = out.getvalue()
    assert code == 1
    assert re.search(r"FAIL \(exit 1\)\s+mypy --platform win32", text)
    assert "FAILED (1 of 6 steps)" in text
    assert "output of pytest (fast)" in text  # later steps still ran


def test_log_file_receives_the_full_output(tmp_path: Path) -> None:
    log = tmp_path / "gate.log"
    out = io.StringIO()
    code = gate.main(
        ["--log", str(log)], runner=_runner({"ruff check"}), clock=_Clock(), python="py", out=out
    )
    assert code == 1
    assert log.read_text(encoding="utf-8").splitlines() == out.getvalue().splitlines()


def test_summary_formats_durations_and_total() -> None:
    results = [
        StepResult(Step("a", ("x",)), 0, 1.25),
        StepResult(Step("long name", ("x",)), 3, 2.0),
    ]
    lines = gate.format_summary(results)
    assert lines[0] == "== gate summary =="
    assert "1.2s" in lines[1] or "1.3s" in lines[1]
    assert lines[2].startswith("FAIL (exit 3)")
    assert lines[-1] == "total 3.2s: FAILED (1 of 2 steps)" or lines[-1].endswith(
        "FAILED (1 of 2 steps)"
    )
    assert gate.format_summary([])[-1] == "total 0.0s: PASSED"


def test_run_step_streams_output_and_returns_the_exit_status(tmp_path: Path) -> None:
    lines: list[str] = []
    step = Step("probe", (sys.executable, "-c", "print('one'); print('two')"))
    assert gate.run_step(step, tmp_path, lines.append) == 0
    assert lines == ["one", "two"]
    failing = Step("fail", (sys.executable, "-c", "import sys; print('x'); sys.exit(7)"))
    assert gate.run_step(failing, tmp_path, lines.append) == 7


def test_cp1252_console_is_hardened() -> None:
    raw = io.BytesIO()
    stream = io.TextIOWrapper(raw, encoding="cp1252", errors="strict", newline="\n")

    def noisy(step: Step, cwd: Path, emit: gate.Emit) -> int:
        emit("unicode " + chr(0x2713) + " arrow")
        return 0

    code = gate.main([], runner=noisy, clock=_Clock(), python="py", out=stream)
    stream.flush()
    assert code == 0
    assert (chr(92) + "u2713").encode() in raw.getvalue()


def test_unknown_option_is_a_usage_error() -> None:
    with pytest.raises(SystemExit) as exit_info:
        gate.main(["--nope"], runner=_runner(set()), out=io.StringIO())
    assert exit_info.value.code == 2
