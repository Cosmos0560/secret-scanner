"""Argument parsing, exit codes, and the single place that prints (PLAN.md section 1.5).

Phase 1 provides `--version` only; subcommands arrive with their phases.
"""

from __future__ import annotations

import argparse
import sys
from collections.abc import Sequence

from secret_scanner import __version__
from secret_scanner.core.errors import ExitCode, SecretScannerError
from secret_scanner.core.sanitize import sanitize

PROG = "secret-scanner"


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog=PROG,
        description="Defensive, offline, read-only secret scanner.",
        allow_abbrev=False,
    )
    parser.add_argument("--version", action="version", version=f"{PROG} {__version__}")
    return parser


def _harden_streams() -> None:
    """A cp1252 console must never crash the tool: unencodable characters are escaped."""
    for stream in (sys.stdout, sys.stderr):
        reconfigure = getattr(stream, "reconfigure", None)
        if callable(reconfigure):
            reconfigure(errors="backslashreplace")


def _dispatch(args: argparse.Namespace, parser: argparse.ArgumentParser) -> ExitCode:
    """Run the requested command. With no subcommand yet, print usage."""
    del args
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
