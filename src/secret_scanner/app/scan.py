"""The `scan` use case: one directory tree in, one report out (PLAN.md section 1.2, D9 to D11).

Order of work, chosen so that nothing is wasted and nothing unsafe is done:

1. every path given by the user is validated (`core/pathrules.py`);
2. configuration and baseline are read, only from the paths given (invariant 10);
3. outputs are checked *before* scanning: not inside the scanned tree, not a link, not an
   existing file without `--force`, not a file the run reads (invariants 3 and 9);
4. the tree is scanned; findings are filtered by confidence, then split by the baseline;
5. the report is rendered, and the report and the new baseline are written atomically;
6. the exit code is decided by D10's precedence: incomplete (4) beats findings (1) beats clean.

The module returns text and exit code; printing is the CLI's job.
"""

from __future__ import annotations

import sys
from collections.abc import Collection
from dataclasses import dataclass

from secret_scanner import __version__
from secret_scanner.core.clock import Clock, isoformat_utc
from secret_scanner.core.errors import ConfigError, ExitCode, UsageError, combine_exit_codes
from secret_scanner.core.findings import finding_sort_key
from secret_scanner.core.limits import DEFAULT_LIMITS, Limits
from secret_scanner.core.models import (
    Confidence,
    Finding,
    OutputFormat,
    Report,
    Rule,
    Severity,
    SuppressedBy,
    Suppressions,
    Target,
)
from secret_scanner.core.pathrules import native_flavour, validate_user_path
from secret_scanner.core.sanitize import sanitize_path
from secret_scanner.core.suppress import (
    apply_suppressions,
    baseline_document,
    count_stale,
)
from secret_scanner.fs import safe_files, walk
from secret_scanner.host.hostinfo import resolve_host_label
from secret_scanner.render.json_out import render_json
from secret_scanner.render.table import render_table
from secret_scanner.services.config import (
    ScanConfig,
    load_baseline,
    load_config,
    serialize_baseline,
)
from secret_scanner.services.fs_scanner import ScanSettings, scan_tree
from secret_scanner.services.loader import RuleSet, load_builtin_rules

DEFAULT_MIN_CONFIDENCE = Confidence.MEDIUM
DEFAULT_FAIL_ON = Severity.LOW
_SHOWN_PATH_CHARS = 1_024
_NOTICE_PATH_CHARS = 120


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


@dataclass(frozen=True, slots=True)
class ScanOutcome:
    """The result of a scan. `text` is the rendered report (what `--output` received, or what
    belongs on stdout); `notices` are one-line messages for stderr, already escaped."""

    exit_code: ExitCode
    report: Report
    text: str
    notices: tuple[str, ...] = ()


def _display_path(path: str, max_chars: int) -> str:
    return sanitize_path(path, windows=sys.platform == "win32", max_chars=max_chars)


def _shown(path: str) -> str:
    return _display_path(path, _NOTICE_PATH_CHARS)


def _validate_paths(request: ScanRequest) -> None:
    flavour = native_flavour(sys.platform)
    given = {
        "path": request.path,
        "--output": request.output,
        "--config": request.config,
        "--baseline": request.baseline,
        "--write-baseline": request.write_baseline,
    }
    for value in given.values():
        if value is not None:
            validate_user_path(value, flavour)


def _load_config(request: ScanRequest, builtin_ids: Collection[str]) -> ScanConfig:
    if request.config is None:
        return ScanConfig()
    data = safe_files.read_own_file(
        request.config, DEFAULT_LIMITS.max_config_bytes, "configuration file"
    )
    return load_config(data, builtin_rule_ids=builtin_ids)


def _load_baseline(request: ScanRequest, limits: Limits) -> Suppressions:
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


def _check_outputs(request: ScanRequest) -> None:
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


def _render(report: Report, output_format: OutputFormat, host: str) -> str:
    if output_format is OutputFormat.JSON:
        return render_json(report, host)
    return render_table(report)


def run_scan(
    request: ScanRequest, clock: Clock, *, reader: walk.Reader | None = None
) -> ScanOutcome:
    """Run the scan described by `request`. Raises `SecretScannerError` subclasses for refusals
    (exit code 2); every problem found while scanning is a recorded issue instead (exit code 4)."""
    _validate_paths(request)
    host = resolve_host_label(request.host_label)
    builtin = load_builtin_rules()
    config = _load_config(request, {rule.id for rule in builtin.rules})
    limits = config.limits
    suppressions = _load_baseline(request, limits)
    min_confidence = request.min_confidence or config.min_confidence or DEFAULT_MIN_CONFIDENCE
    fail_on = request.fail_on or config.fail_on or DEFAULT_FAIL_ON
    settings = ScanSettings(
        rules=_effective_rules(builtin, config, limits),
        entropy=config.entropy,
        limits=limits,
        exclude_globs=config.exclude,
        default_excludes=request.default_excludes,
    )
    _check_outputs(request)

    result = scan_tree(request.path, settings, clock, reader)

    eligible = [f for f in result.findings if f.confidence.at_least(min_confidence)]
    split = apply_suppressions(eligible, suppressions, limits)
    shown: list[Finding] = list(split.reported)
    if request.show_suppressed:
        shown += split.suppressed
    complete = result.complete
    report = Report(
        target=Target.FS,
        target_display=_display_path(request.path, _SHOWN_PATH_CHARS),
        findings=tuple(sorted(shown, key=finding_sort_key)),
        suppressed_by_fingerprint=split.by_fingerprint,
        suppressed_by_path=split.by_path,
        # Staleness is judged against everything detected, whatever the confidence filter hid,
        # and only when the whole tree was scanned (an unread file could hold the finding).
        stale=count_stale(suppressions.entries, result.findings) if complete else None,
        issues=result.issues,
        stats=result.stats,
        complete=complete,
        truncated=result.truncated,
        rules_sha256=builtin.sha256,
        generated_at=isoformat_utc(clock.now_utc()),
        tool_version=__version__,
    )
    text = _render(report, request.output_format, host)

    notices: list[str] = []
    if request.write_baseline is not None:
        current = [*split.reported, *(f for f in split.suppressed if _by_fingerprint(f))]
        reasons = {e.fingerprint: e.reason for e in suppressions.entries if e.reason is not None}
        document = baseline_document(current, paths=suppressions.paths, reasons=reasons)
        data = serialize_baseline(document)
        safe_files.write_new_file(request.write_baseline, data, force=request.force)
        count = len({finding.fingerprint for finding in current})
        notice = f"baseline with {count} entries written to {_shown(request.write_baseline)}"
        if not complete:
            notice += " (the run was incomplete: findings in unscanned parts are not in it)"
        notices.append(notice)
    if request.output is not None:
        safe_files.write_new_file(request.output, text.encode("utf-8"), force=request.force)
        notices.append(f"report written to {_shown(request.output)}")
    if not complete:
        notices.append(
            f"warning: the scan is incomplete ({len(report.issues)} issue(s)); "
            "this is not a clean result"
        )

    codes = []
    if not complete:
        codes.append(ExitCode.INCOMPLETE)
    if any(f.severity.at_least(fail_on) for f in split.reported):
        codes.append(ExitCode.FINDINGS)
    return ScanOutcome(combine_exit_codes(codes), report, text, tuple(notices))


def _by_fingerprint(finding: Finding) -> bool:
    return finding.suppressed_by is SuppressedBy.FINGERPRINT
