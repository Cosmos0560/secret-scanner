"""Error hierarchy, exit codes and their precedence (PLAN.md D10).

Exceptions never carry file content: every message passes through the sanitiser and is bounded,
so a hostile name or line cannot reach a terminal or a log through an error.
"""

from __future__ import annotations

from collections.abc import Iterable
from enum import IntEnum
from typing import ClassVar

from secret_scanner.core.sanitize import sanitize

MAX_ERROR_MESSAGE_CHARS = 512


class ExitCode(IntEnum):
    """Process exit codes, aligned with file-integrity-monitor."""

    OK = 0  # clean and complete
    FINDINGS = 1  # findings at or above --fail-on
    USAGE = 2  # usage, config, rules, baseline or I/O error
    GIT = 3  # git unavailable or failed
    INCOMPLETE = 4  # any limit, time budget, missing objects, shallow history


# Highest priority first: 2 > 3 > 4 > 1 > 0.
EXIT_PRECEDENCE: tuple[ExitCode, ...] = (
    ExitCode.USAGE,
    ExitCode.GIT,
    ExitCode.INCOMPLETE,
    ExitCode.FINDINGS,
    ExitCode.OK,
)


def combine_exit_codes(codes: Iterable[ExitCode]) -> ExitCode:
    """Return the code that wins by precedence; no codes at all means a clean run."""
    present = set(codes)
    for code in EXIT_PRECEDENCE:
        if code in present:
            return code
    return ExitCode.OK


class SecretScannerError(Exception):
    """Base class. Each subclass maps to exactly one exit code."""

    exit_code: ClassVar[ExitCode] = ExitCode.USAGE

    def __init__(self, message: str) -> None:
        super().__init__(sanitize(message, max_chars=MAX_ERROR_MESSAGE_CHARS))


class UsageError(SecretScannerError):
    """A command line, path or option the tool refuses."""

    exit_code = ExitCode.USAGE


class ConfigError(SecretScannerError):
    """A configuration, rules or baseline file the tool refuses."""

    exit_code = ExitCode.USAGE


def unknown_key_error(where: str, allowed: Iterable[str]) -> ConfigError:
    """The error for a key a file must not have. The key is never echoed: a mistyped key can be a
    pasted secret, and error text reaches terminals and CI logs. The allowed keys are listed
    instead, which is what a person needs to find the typo."""
    return ConfigError(f"{where}: unknown key (allowed: {', '.join(sorted(allowed))})")


class ScanIOError(SecretScannerError):
    """An I/O failure on one of the tool's own files."""

    exit_code = ExitCode.USAGE


class GitError(SecretScannerError):
    """git is missing, too old, refused, or failed."""

    exit_code = ExitCode.GIT


class IncompleteRunError(SecretScannerError):
    """A limit or budget stopped the run before it finished."""

    exit_code = ExitCode.INCOMPLETE
