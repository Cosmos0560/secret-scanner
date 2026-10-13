#!/usr/bin/env python
"""The project gate (CLAUDE.md section 3). Runs six steps, prints a summary, and exits non-zero
if any step failed:

    ruff check, ruff format --check, mypy --platform linux, mypy --platform win32,
    scripts/check_architecture.py, pytest with branch coverage (floor 85%).

`--full` includes the tests marked `slow` (as CI does). `--log FILE` writes the complete output to
FILE as well, without changing the exit status; never pipe or redirect the gate itself, because a
filter hides failures and masks the exit status. `--durations N` also lists the N slowest tests,
which is how the default gate's time is audited (nothing is filtered or skipped by it).
"""

from __future__ import annotations

import argparse
import os
import subprocess
import sys
import time
from collections.abc import Callable, Sequence
from contextlib import ExitStack
from dataclasses import dataclass
from pathlib import Path
from typing import IO, TextIO, cast

ROOT = Path(__file__).resolve().parent.parent
COVERAGE_FLOOR = 85
NEWLINES = chr(13) + chr(10)  # trailing CR and LF are stripped from each streamed line


@dataclass(frozen=True, slots=True)
class Step:
    name: str
    argv: tuple[str, ...]


@dataclass(frozen=True, slots=True)
class StepResult:
    step: Step
    returncode: int
    seconds: float

    @property
    def passed(self) -> bool:
        return self.returncode == 0


Emit = Callable[[str], None]
Runner = Callable[[Step, Path, Emit], int]


def build_steps(python: str, *, full: bool, durations: int = 0) -> list[Step]:
    """The six gate steps, in order. `python` is the interpreter that runs every tool.
    `durations` (more than 0) makes pytest list that many slowest tests; it changes no check."""
    pytest_argv = [
        python,
        "-m",
        "pytest",
        "-q",
        "-rs",
        "--cov",
        "--cov-branch",
        f"--cov-fail-under={COVERAGE_FLOOR}",
        "--cov-report=term-missing:skip-covered",
    ]
    if not full:
        pytest_argv += ["-m", "not slow"]
    if durations > 0:
        pytest_argv += [f"--durations={durations}"]
    return [
        Step("ruff check", (python, "-m", "ruff", "check", ".")),
        Step("ruff format --check", (python, "-m", "ruff", "format", "--check", ".")),
        Step("mypy --platform linux", (python, "-m", "mypy", "--platform", "linux")),
        Step("mypy --platform win32", (python, "-m", "mypy", "--platform", "win32")),
        Step("check_architecture", (python, "scripts/check_architecture.py")),
        Step("pytest" + (" (full)" if full else " (fast)"), tuple(pytest_argv)),
    ]


def run_step(step: Step, cwd: Path, emit: Emit) -> int:
    """Run one step, streaming its combined output line by line to `emit`."""
    env = dict(os.environ)
    env["PYTHONUTF8"] = "1"
    with subprocess.Popen(
        step.argv,
        cwd=cwd,
        env=env,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        text=True,
        encoding="utf-8",
        errors="replace",
    ) as process:
        for line in cast(IO[str], process.stdout):  # PIPE was requested, so it is not None
            emit(line.rstrip(NEWLINES))
        return process.wait()


def run_gate(
    steps: Sequence[Step],
    *,
    cwd: Path,
    runner: Runner,
    emit: Emit,
    clock: Callable[[], float],
) -> list[StepResult]:
    results: list[StepResult] = []
    for step in steps:
        emit(f"== {step.name} ==")
        started = clock()
        returncode = runner(step, cwd, emit)
        results.append(StepResult(step, returncode, clock() - started))
    return results


def format_summary(results: Sequence[StepResult]) -> list[str]:
    width = max((len(result.step.name) for result in results), default=0)
    lines = ["== gate summary =="]
    for result in results:
        status = "PASS" if result.passed else f"FAIL (exit {result.returncode})"
        lines.append(f"{status:<14} {result.step.name:<{width}}  {result.seconds:6.1f}s")
    failed = [result for result in results if not result.passed]
    total = sum(result.seconds for result in results)
    verdict = "PASSED" if not failed else f"FAILED ({len(failed)} of {len(results)} steps)"
    lines.append(f"total {total:.1f}s: {verdict}")
    return lines


def main(
    argv: Sequence[str] | None = None,
    *,
    runner: Runner = run_step,
    clock: Callable[[], float] = time.monotonic,
    python: str | None = None,
    out: TextIO | None = None,
    root: Path = ROOT,
) -> int:
    parser = argparse.ArgumentParser(prog="gate", description="Run the project gate.")
    parser.add_argument("--full", action="store_true", help="include tests marked slow")
    parser.add_argument("--log", metavar="FILE", help="also write the full output to FILE")
    parser.add_argument(
        "--durations",
        type=int,
        default=0,
        metavar="N",
        help="list the N slowest tests (pytest --durations); changes no check",
    )
    args = parser.parse_args(argv)

    stream = out if out is not None else sys.stdout
    reconfigure = getattr(stream, "reconfigure", None)
    if callable(reconfigure):
        reconfigure(errors="backslashreplace")
    with ExitStack() as stack:
        log: IO[str] | None = None
        if args.log:
            log = stack.enter_context(Path(args.log).open("w", encoding="utf-8", newline=""))

        def emit(line: str) -> None:
            print(line, file=stream, flush=True)
            if log is not None:
                print(line, file=log)

        steps = build_steps(python or sys.executable, full=args.full, durations=args.durations)
        results = run_gate(steps, cwd=root, runner=runner, emit=emit, clock=clock)
        for line in format_summary(results):
            emit(line)
    return 0 if all(result.passed for result in results) else 1


if __name__ == "__main__":  # pragma: no cover - the entry point is exercised by the gate itself
    sys.exit(main())
