"""Argument parsing, exit codes, and the single place that prints (PLAN.md section 1.5).

`scan` is built (Phase 3); `scan-git`, `demo` and `rules` arrive with their phases. This module
only wires things together: it turns arguments into a request, calls the application, prints
the rendered report on stdout and one-line notices on stderr, and maps every refusal to an exit
code. Error text always passes through the sanitiser, including argparse's own messages, which
would otherwise echo an argument verbatim.
"""

from __future__ import annotations

import argparse
import sys
from collections.abc import Sequence
from typing import NoReturn

from secret_scanner import __version__
from secret_scanner.app.scan import ScanRequest, run_scan
from secret_scanner.core.errors import MAX_ERROR_MESSAGE_CHARS, ExitCode, SecretScannerError
from secret_scanner.core.models import Confidence, OutputFormat, Severity
from secret_scanner.core.sanitize import sanitize
from secret_scanner.host.clock import SystemClock

PROG = "secret-scanner"


class _Parser(argparse.ArgumentParser):
    """An argument parser whose error text is escaped before it is printed."""

    def error(self, message: str) -> NoReturn:
        self.print_usage(sys.stderr)
        shown = sanitize(message, max_chars=MAX_ERROR_MESSAGE_CHARS)
        print(f"{self.prog}: error: {shown}", file=sys.stderr)
        raise SystemExit(int(ExitCode.USAGE))


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
        "--format",
        dest="output_format",
        choices=[fmt.value for fmt in OutputFormat],
        default=OutputFormat.TABLE.value,
        help="report format (default: table)",
    )
    scan.add_argument("--output", metavar="FILE", help="write the report to FILE, not to stdout")
    scan.add_argument(
        "--force", action="store_true", help="replace --output / --write-baseline if it exists"
    )
    scan.add_argument("--config", metavar="FILE", help="a configuration file (YAML)")
    scan.add_argument("--baseline", metavar="FILE", help="suppress the findings listed in FILE")
    scan.add_argument(
        "--write-baseline",
        metavar="FILE",
        help="write a baseline of the current findings to FILE",
    )
    scan.add_argument(
        "--show-suppressed", action="store_true", help="also list findings the baseline suppresses"
    )
    scan.add_argument(
        "--min-confidence",
        choices=[c.value for c in Confidence],
        help="lowest confidence to report (default: medium)",
    )
    scan.add_argument(
        "--fail-on",
        choices=[s.value for s in Severity],
        help="lowest severity that fails the run (default: low)",
    )
    scan.add_argument(
        "--no-default-excludes",
        action="store_true",
        help="also scan .git, node_modules, .venv and the other default excluded directories",
    )
    scan.add_argument("--host-label", metavar="TEXT", help="host name for machine-readable output")


def build_parser() -> argparse.ArgumentParser:
    parser = _Parser(
        prog=PROG,
        description="Defensive, offline, read-only secret scanner.",
        allow_abbrev=False,
    )
    parser.add_argument("--version", action="version", version=f"{PROG} {__version__}")
    subcommands = parser.add_subparsers(dest="command", metavar="COMMAND", parser_class=_Parser)
    _add_scan_parser(subcommands)
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
    )
    outcome = run_scan(request, SystemClock())
    if request.output is None:
        sys.stdout.write(outcome.text)
        sys.stdout.flush()
    for notice in outcome.notices:
        print(f"{PROG}: {notice}", file=sys.stderr)
    return outcome.exit_code


def _dispatch(args: argparse.Namespace, parser: argparse.ArgumentParser) -> ExitCode:
    """Run the requested command; with none given, print usage."""
    if args.command == "scan":
        return _run_scan_command(args)
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
    except Exception as error:
        # Top-level handler: prints the type name only (a message could carry content) and exits
        # 2, never 1, which means "findings".
        name = sanitize(type(error).__name__, max_chars=80)
        print(f"{PROG}: internal error: {name}", file=sys.stderr)
        return int(ExitCode.USAGE)
