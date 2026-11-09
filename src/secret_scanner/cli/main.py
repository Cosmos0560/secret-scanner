"""Argument parsing, exit codes, and the single place that prints (PLAN.md section 1.5).

`scan` (Phase 3), `scan-git` (Phase 4), `rules` and `demo` (Phase 5) are built.
This module only wires things together: it turns arguments into a request, calls the
application, prints the rendered report on stdout and one-line notices on stderr, and maps every
refusal to an exit code. Error text always passes through the sanitiser, including argparse's
own messages, which would otherwise echo an argument verbatim.
"""

from __future__ import annotations

import argparse
import sys
from collections.abc import Sequence
from typing import NoReturn

from secret_scanner import __version__
from secret_scanner.app.common import ScanOutcome
from secret_scanner.app.demo import run_demo
from secret_scanner.app.rules import run_rules
from secret_scanner.app.scan import ScanRequest, run_scan
from secret_scanner.app.scan_git import GitScanRequest, run_scan_git
from secret_scanner.core.errors import MAX_ERROR_MESSAGE_CHARS, ExitCode, SecretScannerError
from secret_scanner.core.models import Confidence, OutputFormat, Severity
from secret_scanner.core.sanitize import sanitize
from secret_scanner.host.clock import SystemClock

PROG = "secret-scanner"
INTERRUPTED = 130  # the shell convention for SIGINT, outside the tool's own exit codes


class _Parser(argparse.ArgumentParser):
    """An argument parser whose error text is escaped before it is printed."""

    def error(self, message: str) -> NoReturn:
        self.print_usage(sys.stderr)
        shown = sanitize(message, max_chars=MAX_ERROR_MESSAGE_CHARS)
        print(f"{self.prog}: error: {shown}", file=sys.stderr)
        raise SystemExit(int(ExitCode.USAGE))


def _add_report_options(parser: argparse.ArgumentParser) -> None:
    """The output, baseline and filtering options both commands have."""
    parser.add_argument(
        "--format",
        dest="output_format",
        choices=[fmt.value for fmt in OutputFormat],
        default=OutputFormat.TABLE.value,
        help="report format (default: table)",
    )
    parser.add_argument("--output", metavar="FILE", help="write the report to FILE, not to stdout")
    parser.add_argument(
        "--force", action="store_true", help="replace --output / --write-baseline if it exists"
    )
    parser.add_argument("--config", metavar="FILE", help="a configuration file (YAML)")
    parser.add_argument("--baseline", metavar="FILE", help="suppress the findings listed in FILE")
    parser.add_argument(
        "--write-baseline",
        metavar="FILE",
        help="write a baseline of the current findings to FILE",
    )
    parser.add_argument(
        "--show-suppressed", action="store_true", help="also list findings the baseline suppresses"
    )
    parser.add_argument(
        "--min-confidence",
        choices=[c.value for c in Confidence],
        help="lowest confidence to report (default: medium)",
    )
    parser.add_argument(
        "--fail-on",
        choices=[s.value for s in Severity],
        help="lowest severity that fails the run (default: low)",
    )
    parser.add_argument(
        "--host-label", metavar="TEXT", help="host name for machine-readable output"
    )


def _add_scan_parser(subcommands: argparse._SubParsersAction[_Parser]) -> None:
    scan = subcommands.add_parser(
        "scan",
        help="scan the files of a directory tree",
        description=(
            "Scan the files of a directory tree for secrets. Read-only: nothing in the tree is "
            "changed, and no full secret is ever printed."
        ),
        allow_abbrev=False,
    )
    scan.add_argument("path", metavar="PATH", help="the directory to scan")
    scan.add_argument(
        "--gitignore",
        action="store_true",
        help="scan only the files git lists (tracked, plus untracked and not ignored)",
    )
    _add_git_options(scan)
    scan.add_argument(
        "--no-default-excludes",
        action="store_true",
        help="also scan .git, node_modules, .venv and the other default excluded directories",
    )
    _add_report_options(scan)


def _add_git_options(parser: argparse.ArgumentParser) -> None:
    parser.add_argument(
        "--allow-other-owner",
        action="store_true",
        help="trust a repository that belongs to another user (git's dubious ownership check)",
    )
    parser.add_argument(
        "--git", metavar="PATH", help="the git program to use (an absolute path; default: PATH)"
    )


def _add_scan_git_parser(subcommands: argparse._SubParsersAction[_Parser]) -> None:
    scan_git = subcommands.add_parser(
        "scan-git",
        help="scan the history of a git repository",
        description=(
            "Scan every blob added or modified in the history of a git repository and name the "
            "commit that introduced each secret. Read-only: git runs with a fixed environment "
            "and configuration, and no full secret is ever printed."
        ),
        allow_abbrev=False,
    )
    scan_git.add_argument("path", metavar="REPO", help="the top directory of the work tree")
    revisions = scan_git.add_mutually_exclusive_group()
    revisions.add_argument("--rev", metavar="REV", help="scan the history reachable from REV")
    revisions.add_argument("--range", metavar="A..B", help="scan the commits in A..B only")
    scan_git.add_argument(
        "--allow-shallow",
        action="store_true",
        help="accept a shallow repository (the run is then not marked incomplete)",
    )
    _add_git_options(scan_git)
    _add_report_options(scan_git)


def _add_demo_parser(subcommands: argparse._SubParsersAction[_Parser]) -> None:
    subcommands.add_parser(
        "demo",
        help="plant fake secrets in a temporary directory and repository, scan them, clean up",
        description=(
            "Plant generated fake secrets in a temporary directory and in a throw-away git "
            "repository, scan both through the real code, show the redacted result and remove "
            "everything. Nothing outside the temporary directory is touched and nothing is "
            "sent anywhere."
        ),
        allow_abbrev=False,
    )


def _add_rules_parser(subcommands: argparse._SubParsersAction[_Parser]) -> None:
    rules = subcommands.add_parser(
        "rules",
        help="list the built-in rules",
        description=(
            "List every built-in rule and detector: id, severity, confidence, description and "
            "pre-filter keywords. No example secret is printed."
        ),
        allow_abbrev=False,
    )
    rules.add_argument(
        "--format",
        dest="output_format",
        choices=[OutputFormat.TABLE.value, OutputFormat.JSON.value],
        default=OutputFormat.TABLE.value,
        help="listing format (default: table)",
    )


def build_parser() -> argparse.ArgumentParser:
    parser = _Parser(
        prog=PROG,
        description="Defensive, offline, read-only secret scanner.",
        allow_abbrev=False,
    )
    parser.add_argument("--version", action="version", version=f"{PROG} {__version__}")
    subcommands = parser.add_subparsers(dest="command", metavar="COMMAND", parser_class=_Parser)
    _add_scan_parser(subcommands)
    _add_scan_git_parser(subcommands)
    _add_rules_parser(subcommands)
    _add_demo_parser(subcommands)
    return parser


def _harden_streams() -> None:
    """A cp1252 console must never crash the tool: unencodable characters are escaped."""
    for stream in (sys.stdout, sys.stderr):
        reconfigure = getattr(stream, "reconfigure", None)
        if callable(reconfigure):
            reconfigure(errors="backslashreplace")


def _run_scan_command(args: argparse.Namespace) -> ExitCode:
    request = ScanRequest(
        path=args.path,
        output_format=OutputFormat(args.output_format),
        output=args.output,
        force=args.force,
        config=args.config,
        baseline=args.baseline,
        write_baseline=args.write_baseline,
        show_suppressed=args.show_suppressed,
        min_confidence=None if args.min_confidence is None else Confidence(args.min_confidence),
        fail_on=None if args.fail_on is None else Severity(args.fail_on),
        default_excludes=not args.no_default_excludes,
        host_label=args.host_label,
        gitignore=args.gitignore,
        allow_other_owner=args.allow_other_owner,
        git=args.git,
    )
    return _print_outcome(run_scan(request, SystemClock()), request.output)


def _print_outcome(outcome: ScanOutcome, output: str | None) -> ExitCode:
    if output is None:
        sys.stdout.write(outcome.text)
        sys.stdout.flush()
    for notice in outcome.notices:
        print(f"{PROG}: {notice}", file=sys.stderr)
    return outcome.exit_code


def _run_scan_git_command(args: argparse.Namespace) -> ExitCode:
    request = GitScanRequest(
        path=args.path,
        revision=args.rev,
        revision_range=args.range,
        allow_shallow=args.allow_shallow,
        allow_other_owner=args.allow_other_owner,
        git=args.git,
        output_format=OutputFormat(args.output_format),
        output=args.output,
        force=args.force,
        config=args.config,
        baseline=args.baseline,
        write_baseline=args.write_baseline,
        show_suppressed=args.show_suppressed,
        min_confidence=None if args.min_confidence is None else Confidence(args.min_confidence),
        fail_on=None if args.fail_on is None else Severity(args.fail_on),
        host_label=args.host_label,
    )
    return _print_outcome(run_scan_git(request, SystemClock()), request.output)


def _run_rules_command(args: argparse.Namespace) -> ExitCode:
    sys.stdout.write(run_rules(OutputFormat(args.output_format)))
    sys.stdout.flush()
    return ExitCode.OK


def _run_demo_command() -> ExitCode:
    outcome = run_demo(SystemClock())
    sys.stdout.write(outcome.text)
    sys.stdout.flush()
    for notice in outcome.notices:
        print(f"{PROG}: {notice}", file=sys.stderr)
    return outcome.exit_code


def _dispatch(args: argparse.Namespace, parser: argparse.ArgumentParser) -> ExitCode:
    """Run the requested command; with none given, print usage."""
    if args.command == "scan":
        return _run_scan_command(args)
    if args.command == "scan-git":
        return _run_scan_git_command(args)
    if args.command == "rules":
        return _run_rules_command(args)
    if args.command == "demo":
        return _run_demo_command()
    parser.print_usage(sys.stderr)
    return ExitCode.USAGE


def main(argv: Sequence[str] | None = None) -> int:
    """Entry point. Returns the process exit code; never raises for expected failures."""
    _harden_streams()
    parser = build_parser()
    try:
        args = parser.parse_args(argv)
    except SystemExit as exit_request:
        code = exit_request.code
        return code if isinstance(code, int) else int(ExitCode.USAGE)
    try:
        return int(_dispatch(args, parser))
    except SecretScannerError as error:
        print(f"{PROG}: error: {error}", file=sys.stderr)
        return int(error.exit_code)
    except KeyboardInterrupt:
        # Ctrl-C: whatever the command had to clean up (the demo's directory) was cleaned up by
        # its own `finally` before the interrupt reached here.
        print(f"{PROG}: interrupted", file=sys.stderr)
        return INTERRUPTED
    except Exception as error:
        # Top-level handler: prints the type name only (a message could carry content) and exits
        # 2, never 1, which means "findings".
        name = sanitize(type(error).__name__, max_chars=80)
        print(f"{PROG}: internal error: {name}", file=sys.stderr)
        return int(ExitCode.USAGE)
