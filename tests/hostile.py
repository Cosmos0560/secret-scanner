"""Marker commands for the hostile-repository tests (PLAN.md D2, CLAUDE.md section 7).

A "marker" is a program a hostile repository tries to make git run. It writes a sentinel file into
a directory the test owns and exits non-zero, so a test can assert that nothing ran: the directory
holds the marker script and nothing else. The command is built with forward slashes and double
quotes so that git's `sh` accepts it on Windows and on Linux.
"""

from __future__ import annotations

import os
import stat
import sys
from pathlib import Path

SCRIPT_NAME = "marker.py"
SENTINEL_PREFIX = "SENTINEL-"

_SCRIPT = """\
import os
import sys

here = os.path.dirname(os.path.abspath(__file__))
label = sys.argv[1] if len(sys.argv) > 1 else "unnamed"
with open(os.path.join(here, "SENTINEL-" + label), "w", encoding="utf-8") as handle:
    handle.write("ran")
sys.exit(1)
"""


class Markers:
    """A directory with the marker script; `command(label)` is what a repository is told to run."""

    def __init__(self, directory: Path) -> None:
        self.directory = directory
        directory.mkdir(parents=True, exist_ok=True)
        self.script = directory / SCRIPT_NAME
        self.script.write_text(_SCRIPT, encoding="utf-8", newline=chr(10))

    @staticmethod
    def _posix(path: str | Path) -> str:
        return str(path).replace(os.sep, "/")

    def command(self, label: str) -> str:
        return f'"{self._posix(sys.executable)}" "{self._posix(self.script)}" {label}'

    def shell_script(self, label: str) -> bytes:
        """The body of an executable hook that runs the marker."""
        return (f"#!/bin/sh{chr(10)}{self.command(label)}{chr(10)}").encode()

    def fired(self) -> list[str]:
        """The labels of the markers that ran (the sentinel files present)."""
        return sorted(
            name.removeprefix(SENTINEL_PREFIX)
            for name in os.listdir(self.directory)
            if name.startswith(SENTINEL_PREFIX)
        )


def make_executable(path: Path) -> None:
    path.chmod(path.stat().st_mode | stat.S_IXUSR | stat.S_IXGRP | stat.S_IXOTH)
