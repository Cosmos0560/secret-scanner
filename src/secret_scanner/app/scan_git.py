"""The `scan-git` use case: the history of one repository in, one report out (PLAN.md D1, D2, D10).

Order of work, before git reads a single object of the repository:

1. user input is validated: paths (`core/pathrules.py`), revisions (`core/gitparse.py`), outputs;
2. the repository directory is examined with `lstat` and bounded reads only (`fs/walk.py`): a
   `.git` that is a link or a file, objects borrowed from another store (`alternates`) and a
   grafts file are refused, because git would follow them silently;
3. git is found without trusting the current directory or the scanned tree, started with a
   from-scratch environment and pinned configuration (`gitio/runner.py`), and its version checked;
4. the repository is discovered with a ceiling at the parent of the given path, and its git
   directory must be the one found in step 2;
5. revisions are resolved to full object ids; the history is walked and scanned.

A shallow repository is incomplete (exit 4) unless `--allow-shallow`. The module returns text and
an exit code; printing is the CLI's job.
"""

from __future__ import annotations

import os
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
from secret_scanner.core.errors import GitError, UsageError
from secret_scanner.core.gitparse import split_range, validate_revision
from secret_scanner.core.models import (
    Confidence,
    IssueKind,
    OutputFormat,
    ScanIssue,
    Severity,
    Target,
)
from secret_scanner.fs import walk
from secret_scanner.gitio.runner import Spawn
from secret_scanner.services.fs_scanner import ScanSettings
from secret_scanner.services.git_scanner import HistorySpec, scan_history

__all__ = ["GitScanRequest", "run_scan_git"]


@dataclass(frozen=True, slots=True)
class GitScanRequest:
    """What the user asked for (`secret-scanner scan-git REPO ...`)."""

    path: str
    revision: str | None = None  # --rev
    revision_range: str | None = None  # --range A..B
    allow_shallow: bool = False
    allow_other_owner: bool = False
    git: str | None = None
    output_format: OutputFormat = OutputFormat.TABLE
    output: str | None = None
    force: bool = False
    config: str | None = None
    baseline: str | None = None
    write_baseline: str | None = None
    show_suppressed: bool = False
    min_confidence: Confidence | None = None
    fail_on: Severity | None = None
    host_label: str | None = None


def _validate_revisions(request: GitScanRequest) -> None:
    if request.revision is not None and request.revision_range is not None:
        raise UsageError("--rev and --range cannot be combined")
    if request.revision is not None:
        validate_revision(request.revision)
    if request.revision_range is not None:
        split_range(request.revision_range)


def _refuse_layout(layout: walk.RepositoryLayout) -> None:
    """Turn what the directory looks like into a refusal (exit code 3) or return."""
    if layout.kind is walk.GitDirKind.MISSING:
        raise GitError(
            "not a git repository: give the top directory of a work tree (the one that holds "
            ".git) or a bare repository"
        )
    if layout.kind is walk.GitDirKind.LINK:
        raise GitError("the repository's .git is a link or reparse point; it is not followed")
    if layout.kind is walk.GitDirKind.LINK_FILE:
        raise GitError(
            "the repository's .git is a file (a worktree or submodule checkout), which would "
            "send git to another directory; scan the main repository instead"
        )
    if layout.alternates:
        raise GitError(
            "the repository borrows objects from another store (objects/info/alternates); "
            "objects outside the repository are not read. Make it self-contained first "
            "(git repack -a -d)"
        )
    if layout.grafts:
        raise GitError(
            "the repository has an info/grafts file, which rewrites commit parents behind git's "
            "back; convert it (git replace --convert-graft-file) or remove it"
        )


def _ceiling(layout: walk.RepositoryLayout) -> str | None:
    """The directory above which discovery must not look: the parent of the repository root."""
    git_dir = layout.git_dir or ""
    root = os.path.dirname(git_dir) if layout.kind is walk.GitDirKind.STANDARD else git_dir
    parent = os.path.dirname(root)
    return parent if parent and parent != root else None


def run_scan_git(
    request: GitScanRequest,
    clock: Clock,
    *,
    spawn: Spawn | None = None,
    environment: Mapping[str, str] | None = None,
    shown_as: str | None = None,
) -> ScanOutcome:
    """Run the history scan described by `request`. Raises `SecretScannerError` subclasses:
    exit code 2 for usage, 3 when git is missing, too old, refused or fails, 4 when a limit stops
    the run before anything could be reported. `shown_as` replaces the path in the report's
    header; only the demo uses it, so that its random temporary directory is never printed."""
    validate_paths(request, {"--git": request.git})
    _validate_revisions(request)
    context = prepare_run(request)
    check_outputs(request)
    walk.check_scan_root(request.path)
    layout = walk.inspect_repository(request.path)
    _refuse_layout(layout)

    runner = open_runner(
        git=request.git,
        root=request.path,
        limits=context.limits,
        clock=clock,
        spawn=spawn,
        environment=environment,
    )
    git_dir = runner.discover(
        request.path, ceiling=_ceiling(layout), allow_other_owner=request.allow_other_owner
    )
    if layout.git_dir is None or not walk.same_directory(git_dir, layout.git_dir):
        raise GitError(
            "the repository's git directory is not the .git inside the given path; "
            "it is not followed"
        )
    shallow = runner.is_shallow(git_dir)

    if request.revision_range is not None:
        older, newer = split_range(request.revision_range)
        spec = HistorySpec(
            include=(runner.resolve_commit(git_dir, newer),),
            exclude=(runner.resolve_commit(git_dir, older),),
            all_refs=False,
        )
    elif request.revision is not None:
        spec = HistorySpec(
            include=(runner.resolve_commit(git_dir, request.revision),), all_refs=False
        )
    else:
        spec = HistorySpec(all_refs=True)

    settings = ScanSettings(
        rules=context.rules,
        entropy=context.config.entropy,
        limits=context.limits,
        exclude_globs=context.config.exclude,
    )
    result = scan_history(runner, git_dir, spec, settings, clock)

    extra: list[ScanIssue] = []
    notices: list[str] = []
    if shallow:
        if request.allow_shallow:
            notices.append(
                "warning: the repository is shallow; history before the cut-off was not scanned"
            )
        else:
            extra.append(
                ScanIssue(
                    IssueKind.SHALLOW_HISTORY,
                    None,
                    "shallow repository: history before the cut-off is not available "
                    "(use --allow-shallow to accept this)",
                )
            )
    complete_history = (not shallow) and result.complete and not extra
    return finish_run(
        request,
        context,
        result,
        target=Target.GIT,
        target_display=target_label(request.path, shown_as),
        clock=clock,
        extra_issues=extra,
        history_complete=complete_history,
        notices=notices,
    )
