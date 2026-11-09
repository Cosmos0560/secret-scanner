"""What `scan` and `scan-git` share (PLAN.md section 1.2, D9 to D11).

Order of work, chosen so that nothing is wasted and nothing unsafe is done:

1. every path given by the user is validated (`core/pathrules.py`);
2. configuration and baseline are read, only from the paths given (invariant 10);
3. outputs are checked *before* scanning: not inside the scanned tree, not a link, not an
   existing file without `--force`, not a file the run reads (invariants 3 and 9);
4. the target is scanned; findings are filtered by confidence, then split by the baseline;
5. the report is rendered, and the report and the new baseline are written atomically;
6. the exit code is decided by D10's precedence: incomplete (4) beats findings (1) beats clean.

Nothing here prints: the outcome carries text and notices, and the CLI prints them.
"""

from __future__ import annotations

import os
import sys
from collections.abc import Collection, Mapping, Sequence
from dataclasses import dataclass, replace
from typing import Protocol

from secret_scanner import __version__
from secret_scanner.core.clock import Clock, isoformat_utc
from secret_scanner.core.errors import (
    ConfigError,
    ExitCode,
    GitError,
    UsageError,
    combine_exit_codes,
)
from secret_scanner.core.findings import finding_sort_key
from secret_scanner.core.limits import DEFAULT_LIMITS, Limits
from secret_scanner.core.models import (
    Confidence,
    Finding,
    OutputFormat,
    Report,
    Rule,
    ScanIssue,
    Severity,
    SuppressedBy,
    Suppressions,
    Target,
)
from secret_scanner.core.pathrules import native_flavour, validate_user_path
from secret_scanner.core.ruleinfo import rule_infos
from secret_scanner.core.sanitize import sanitize_path
from secret_scanner.core.suppress import apply_suppressions, baseline_document, count_stale
from secret_scanner.fs import safe_files
from secret_scanner.gitio.runner import GitRunner, Spawn, spawn_process
from secret_scanner.host.hostinfo import resolve_host_label
from secret_scanner.render.json_out import render_json
from secret_scanner.render.jsonl import render_jsonl
from secret_scanner.render.sarif import render_sarif
from secret_scanner.render.table import render_table
from secret_scanner.services.config import (
    ScanConfig,
    load_baseline,
    load_config,
    serialize_baseline,
)
from secret_scanner.services.fs_scanner import ScanResult
from secret_scanner.services.loader import RuleSet, load_builtin_rules

DEFAULT_MIN_CONFIDENCE = Confidence.MEDIUM
DEFAULT_FAIL_ON = Severity.LOW
SHOWN_PATH_CHARS = 1_024
NOTICE_PATH_CHARS = 120


class CommonRequest(Protocol):
    """The request fields every command has."""

    @property
    def path(self) -> str: ...

    @property
    def output_format(self) -> OutputFormat: ...

    @property
    def output(self) -> str | None: ...

    @property
    def force(self) -> bool: ...

    @property
    def config(self) -> str | None: ...

    @property
    def baseline(self) -> str | None: ...

    @property
    def write_baseline(self) -> str | None: ...

    @property
    def show_suppressed(self) -> bool: ...

    @property
    def min_confidence(self) -> Confidence | None: ...

    @property
    def fail_on(self) -> Severity | None: ...

    @property
    def host_label(self) -> str | None: ...


@dataclass(frozen=True, slots=True)
class ScanOutcome:
    """The result of a run. `text` is the rendered report (what `--output` received, or what
    belongs on stdout); `notices` are one-line messages for stderr, already escaped."""

    exit_code: ExitCode
    report: Report
    text: str
    notices: tuple[str, ...] = ()


@dataclass(frozen=True, slots=True)
class RunContext:
    """Everything read before the target is touched."""

    builtin: RuleSet
    config: ScanConfig
    limits: Limits
    suppressions: Suppressions
    host: str
    rules: tuple[Rule, ...]


def display_path(path: str, max_chars: int) -> str:
    """A path the user gave, escaped for display, with `/` separators (PLAN.md v0.9)."""
    return sanitize_path(path, windows=sys.platform == "win32", max_chars=max_chars)


def shown(path: str) -> str:
    return display_path(path, NOTICE_PATH_CHARS)


def validate_paths(request: CommonRequest, extra: Mapping[str, str | None] | None = None) -> None:
    flavour = native_flavour(sys.platform)
    given: dict[str, str | None] = {
        "path": request.path,
        "--output": request.output,
        "--config": request.config,
        "--baseline": request.baseline,
        "--write-baseline": request.write_baseline,
    }
    given.update(extra or {})
    for value in given.values():
        if value is not None:
            validate_user_path(value, flavour)


def _load_config(request: CommonRequest, builtin_ids: Collection[str]) -> ScanConfig:
    if request.config is None:
        return ScanConfig()
    data = safe_files.read_own_file(
        request.config, DEFAULT_LIMITS.max_config_bytes, "configuration file"
    )
    return load_config(data, builtin_rule_ids=builtin_ids)


def _load_baseline(request: CommonRequest, limits: Limits) -> Suppressions:
    if request.baseline is None:
        return Suppressions()
    data = safe_files.read_own_file(request.baseline, limits.max_baseline_bytes, "baseline file")
    return load_baseline(data, limits)


def _effective_rules(builtin: RuleSet, config: ScanConfig, limits: Limits) -> tuple[Rule, ...]:
    disabled = set(config.disable_rules)
    rules = tuple(rule for rule in builtin.rules if rule.id not in disabled) + config.extra_rules
    if len(rules) > limits.max_rules:
        raise ConfigError(f"more than {limits.max_rules} rules are active")
    return rules


def prepare_run(request: CommonRequest) -> RunContext:
    """Load the rules, configuration and baseline named by the request."""
    host = resolve_host_label(request.host_label)
    builtin = load_builtin_rules()
    config = _load_config(request, {rule.id for rule in builtin.rules})
    limits = config.limits
    return RunContext(
        builtin=builtin,
        config=config,
        limits=limits,
        suppressions=_load_baseline(request, limits),
        host=host,
        rules=_effective_rules(builtin, config, limits),
    )


def check_outputs(request: CommonRequest) -> None:
    """Refuse every output that must not be written, before any scanning is done."""
    outputs = (("--output", request.output), ("--write-baseline", request.write_baseline))
    inputs = (("--config", request.config), ("--baseline", request.baseline))
    for label, target in outputs:
        if target is None:
            continue
        if safe_files.is_inside(request.path, target):
            raise UsageError(f"{label}: the file must not be inside the scanned tree")
        for input_label, source in inputs:
            # Replacing the baseline with a refreshed one is what --write-baseline is for; a
            # report written over a configuration or baseline would destroy it.
            same_allowed = label == "--write-baseline" and input_label == "--baseline"
            if source is not None and not same_allowed and safe_files.is_same_path(target, source):
                raise UsageError(f"{label}: would overwrite the file given as {input_label}")
        safe_files.check_output_target(target, force=request.force)
    if (
        request.output is not None
        and request.write_baseline is not None
        and safe_files.is_same_path(request.output, request.write_baseline)
    ):
        raise UsageError("--output and --write-baseline name the same file")


def _render(report: Report, output_format: OutputFormat, host: str, rules: Sequence[Rule]) -> str:
    if output_format is OutputFormat.JSON:
        return render_json(report, host)
    if output_format is OutputFormat.JSONL:
        return render_jsonl(report, host)
    if output_format is OutputFormat.SARIF:
        return render_sarif(report, rule_infos(rules))
    return render_table(report)


def _by_fingerprint(finding: Finding) -> bool:
    return finding.suppressed_by is SuppressedBy.FINGERPRINT


def finish_run(
    request: CommonRequest,
    context: RunContext,
    result: ScanResult,
    *,
    target: Target,
    target_display: str,
    clock: Clock,
    extra_issues: Sequence[ScanIssue] = (),
    history_complete: bool | None = None,
    notices: Sequence[str] = (),
) -> ScanOutcome:
    """Filter, suppress, render and write; decide the exit code (D9, D10, D11)."""
    if extra_issues:
        result = replace(result, issues=(*result.issues, *extra_issues))
    suppressions = context.suppressions
    min_confidence = (
        request.min_confidence or context.config.min_confidence or DEFAULT_MIN_CONFIDENCE
    )
    fail_on = request.fail_on or context.config.fail_on or DEFAULT_FAIL_ON
    eligible = [f for f in result.findings if f.confidence.at_least(min_confidence)]
    split = apply_suppressions(eligible, suppressions, context.limits)
    listed: list[Finding] = list(split.reported)
    if request.show_suppressed:
        listed += split.suppressed
    complete = result.complete
    report = Report(
        target=target,
        target_display=target_display,
        findings=tuple(sorted(listed, key=finding_sort_key)),
        suppressed_by_fingerprint=split.by_fingerprint,
        suppressed_by_path=split.by_path,
        # Staleness is judged against everything detected, whatever the confidence filter hid,
        # and only when the whole input was scanned (an unread part could hold the finding).
        stale=count_stale(suppressions.entries, result.findings) if complete else None,
        issues=result.issues,
        stats=result.stats,
        complete=complete,
        truncated=result.truncated,
        rules_sha256=context.builtin.sha256,
        generated_at=isoformat_utc(clock.now_utc()),
        tool_version=__version__,
        history_complete=history_complete,
    )
    text = _render(report, request.output_format, context.host, context.rules)

    messages: list[str] = []
    if request.write_baseline is not None:
        current = [*split.reported, *(f for f in split.suppressed if _by_fingerprint(f))]
        reasons = {e.fingerprint: e.reason for e in suppressions.entries if e.reason is not None}
        document = baseline_document(current, paths=suppressions.paths, reasons=reasons)
        data = serialize_baseline(document)
        safe_files.write_new_file(request.write_baseline, data, force=request.force)
        count = len({finding.fingerprint for finding in current})
        notice = f"baseline with {count} entries written to {shown(request.write_baseline)}"
        if not complete:
            notice += " (the run was incomplete: findings in unscanned parts are not in it)"
        messages.append(notice)
    if request.output is not None:
        safe_files.write_new_file(request.output, text.encode("utf-8"), force=request.force)
        messages.append(f"report written to {shown(request.output)}")
    messages.extend(notices)
    if not complete:
        messages.append(
            f"warning: the scan is incomplete ({len(report.issues)} issue(s)); "
            "this is not a clean result"
        )

    codes = []
    if not complete:
        codes.append(ExitCode.INCOMPLETE)
    if any(f.severity.at_least(fail_on) for f in split.reported):
        codes.append(ExitCode.FINDINGS)
    return ScanOutcome(combine_exit_codes(codes), report, text, tuple(messages))


def _environment_value(environment: Mapping[str, str], name: str) -> str:
    for key, value in environment.items():
        if key.upper() == name:
            return value
    return ""


def open_runner(
    *,
    git: str | None,
    root: str,
    limits: Limits,
    clock: Clock,
    spawn: Spawn | None = None,
    environment: Mapping[str, str] | None = None,
) -> GitRunner:
    """Find git (never in the current directory, a relative PATH entry, the temporary directory
    or the scanned tree; on Windows only `git.exe`), start a runner on its absolute path and check
    its version (D2). Raises `GitError` (exit code 3)."""
    env = os.environ if environment is None else environment
    windows = sys.platform == "win32"
    if git is not None:
        binary = safe_files.check_program(git, windows=windows, avoid=[root])
    else:
        trees, directories = safe_files.search_hazards()
        found = safe_files.find_program(
            "git",
            _environment_value(env, "PATH"),
            windows=windows,
            avoid=[root, *trees],
            avoid_directories=directories,
        )
        if found is None:
            raise GitError("git was not found on PATH (or --git PATH was not given)")
        binary = found
    runner = GitRunner(
        binary,
        limits=limits,
        clock=clock,
        deadline=clock.monotonic() + limits.max_run_seconds,
        parent_environment=env,
        platform=sys.platform,
        spawn=spawn_process if spawn is None else spawn,
    )
    runner.version()
    return runner
