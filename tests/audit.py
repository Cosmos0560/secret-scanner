"""Records what a piece of code does to the file system, the process and the network, using Python's
audit hooks (PEP 578), so a test can prove what a command did *not* touch.

The hook is installed once, when this module is imported, and cannot be removed; it does nothing
unless a `recording()` block is active, and it ignores byte-code caches (`.pyc`), which the
interpreter may write for a module it imports for the first time inside the block.
"""

from __future__ import annotations

import os
import sys
from collections.abc import Iterator
from contextlib import contextmanager
from dataclasses import dataclass, field
from typing import Any

WRITE_FLAGS = os.O_WRONLY | os.O_RDWR | os.O_CREAT | os.O_TRUNC | os.O_APPEND
NETWORK_PREFIXES = ("socket.", "ssl.", "urllib.", "http.", "ftplib.", "smtplib.", "imaplib.")
MUTATING_EVENTS = frozenset(
    {
        "os.remove",
        "os.rename",
        "os.mkdir",
        "os.rmdir",
        "os.chmod",
        "os.truncate",
        "os.utime",
        "os.symlink",
        "os.link",
        "shutil.rmtree",
        "shutil.move",
        "shutil.copyfile",
        "tempfile.mkdtemp",
        "tempfile.mkstemp",
    }
)
PROCESS_EVENTS = frozenset(
    {
        "os.chdir",
        "os.putenv",
        "os.unsetenv",
        "os.system",
        "os.exec",
        "os.posix_spawn",
        "os.spawn",
        "os.fork",
        "os.forkpty",
        "ctypes.dlopen",
    }
)
WATCHED = MUTATING_EVENTS | PROCESS_EVENTS | {"open", "subprocess.Popen"}


@dataclass
class Recording:
    """The events of one `recording()` block."""

    events: list[tuple[str, tuple[Any, ...]]] = field(default_factory=list)

    def named(self, *names: str) -> list[tuple[Any, ...]]:
        return [args for event, args in self.events if event in names]

    def network(self) -> list[str]:
        return [event for event, _ in self.events if event.startswith(NETWORK_PREFIXES)]

    def process(self) -> list[str]:
        return [event for event, _ in self.events if event in PROCESS_EVENTS]

    def written_paths(self) -> list[str]:
        """Every path that was created, written, renamed, changed or removed (not the null device,
        which a child process's standard input is opened on, and not byte-code caches)."""
        paths: list[str] = []
        for event, args in self.events:
            if event == "open":
                path, flags = args[0], args[2]
                if isinstance(flags, int) and flags & WRITE_FLAGS and _as_text(path):
                    paths.append(_as_text(path))
            elif event in MUTATING_EVENTS:
                for value in args:
                    if _as_text(value):
                        paths.append(_as_text(value))
        null = os.path.normcase(os.devnull)
        return [
            path for path in paths if not path.endswith(".pyc") and os.path.normcase(path) != null
        ]

    def spawned(self) -> list[Spawned]:
        """Every subprocess that was started."""
        started = []
        for args in self.named("subprocess.Popen"):
            executable, argv, cwd, env = args[0], args[1], args[2], args[3]
            command = argv if isinstance(argv, str) else " ".join(_as_text(a) for a in argv)
            names = sorted(_as_text(key) for key in env) if env is not None else None
            started.append(Spawned(_as_text(executable), command, _as_text(cwd) or None, names))
        return started


@dataclass(frozen=True)
class Spawned:
    """One `subprocess.Popen` event: the executable (empty when only a command line was given),
    the command line, the working directory and the names of the environment variables."""

    executable: str
    command: str
    cwd: str | None
    environment_names: list[str] | None


def _as_text(value: object) -> str:
    if isinstance(value, bytes | str | os.PathLike):
        return os.fsdecode(value)
    return ""


_ACTIVE: list[Recording] = []


def _hook(event: str, args: tuple[Any, ...]) -> None:
    if _ACTIVE and (event in WATCHED or event.startswith(NETWORK_PREFIXES)):
        _ACTIVE[-1].events.append((event, args))


sys.addaudithook(_hook)


@contextmanager
def recording() -> Iterator[Recording]:
    """Record the watched events of the current process while the block runs."""
    recorded = Recording()
    _ACTIVE.append(recorded)
    try:
        yield recorded
    finally:
        _ACTIVE.remove(recorded)
