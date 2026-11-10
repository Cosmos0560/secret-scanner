"""The `scan` use case: one directory tree in, one report out (PLAN.md section 1.2, D9 to D11, D13).

The order of work and the shared steps are in `app/common.py`. This module adds the directory
specifics: the walk, and `--gitignore`, which asks git (through the runner, D2) for its own list
of tracked and not-ignored files and uses it as a filter for the tool's own walker.

The module returns text and exit code; printing is the CLI's job.
"""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass

from secret_scanner.app.common import (
    ScanOutcome,
    check_outputs,
    finish_run,
    open_runner,
    prepare_run,
    target_label,
    validate_paths,
)
from secret_scanner.core.clock import Clock
from secret_scanner.core.limits import Limits
from secret_scanner.core.models import Confidence, OutputFormat, Severity, Target
from secret_scanner.fs import walk
from secret_scanner.gitio.runner import Spawn
from secret_scanner.services.fs_scanner import ScanSettings, scan_tree

__all__ = ["ScanOutcome", "ScanRequest", "run_scan"]


@dataclass(frozen=True, slots=True)
class ScanRequest:
    """What the user asked for. Options left as `None` take the configuration file's value, then
    the default."""

    path: str
    output_format: OutputFormat = OutputFormat.TABLE
    output: str | None = None
    force: bool = False
    config: str | None = None
    baseline: str | None = None
    write_baseline: str | None = None
    show_suppressed: bool = False
    min_confidence: Confidence | None = None
    fail_on: Severity | None = None
    default_excludes: bool = True
    host_label: str | None = None
    gitignore: bool = False
    allow_other_owner: bool = False
    git: str | None = None


def _git_listed_paths(
    request: ScanRequest,
    limits: Limits,
    clock: Clock,
    spawn: Spawn | None,
    environment: Mapping[str, str] | None,
) -> frozenset[str]:
    """The `/` paths git lists for the directory (tracked, plus untracked and not ignored)."""
    walk.check_scan_root(request.path)
    runner = open_runner(
        git=request.git,
        root=request.path,
        limits=limits,
        clock=clock,
        spawn=spawn,
        environment=environment,
    )
    listed = runner.list_files(request.path, allow_other_owner=request.allow_other_owner)
    return frozenset(path.decode("utf-8", errors="surrogateescape") for path in listed)


def run_scan(
    request: ScanRequest,
    clock: Clock,
    *,
    reader: walk.Reader | None = None,
    spawn: Spawn | None = None,
    environment: Mapping[str, str] | None = None,
    shown_as: str | None = None,
) -> ScanOutcome:
    """Run the scan described by `request`. Raises `SecretScannerError` subclasses for refusals
    (exit code 2, or 3 when git fails); every problem found while scanning is a recorded issue
    instead (exit code 4). `shown_as` replaces the path in the report's header; only the demo
    uses it, so that its random temporary directory is never printed."""
    validate_paths(request, {"--git": request.git})
    context = prepare_run(request)
    check_outputs(request)
    only_paths = None
    if request.gitignore:
        only_paths = _git_listed_paths(request, context.limits, clock, spawn, environment)
    settings = ScanSettings(
        rules=context.rules,
        entropy=context.config.entropy,
        limits=context.limits,
        exclude_globs=context.config.exclude,
        default_excludes=request.default_excludes,
        only_paths=only_paths,
    )
    result = scan_tree(request.path, settings, clock, reader)
    return finish_run(
        request,
        context,
        result,
        target=Target.FS,
        target_display=target_label(request.path, shown_as),
        clock=clock,
    )
