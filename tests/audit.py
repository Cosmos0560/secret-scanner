"""Records what a piece of code does to the file system, the process and the network, using Python's
audit hooks (PEP 578), so a test can prove what a command did *not* touch.

The hook is installed once, when this module is imported, and cannot be removed; it does nothing
unless a `recording()` block is active, and it ignores byte-code caches (`.pyc`), which the
interpreter may write for a module it imports for the first time inside the block.

On Linux `shutil.rmtree` and similar work relative to an open directory (`dir_fd`), so the event
holds only a name. The hook turns it into a full path at event time, while the descriptor is
still open, through `/proc/self/fd`. Where that does not exist, the path is recorded as
`<fd N>/name`, which no test accepts: the check fails closed instead of passing on a guess.
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
        "os.spawn",
        "os.fork",
        "os.forkpty",
        "ctypes.dlopen",
    }
)
# Python 3.14 (and some builds of older versions) start a child with `os.posix_spawn` from inside
# `subprocess.Popen`; the tests check its target instead of treating it as a process change.
WATCHED = MUTATING_EVENTS | PROCESS_EVENTS | {"open", "subprocess.Popen", "os.posix_spawn"}
# For events that take a `dir_fd`: (index of a path argument, index of the `dir_fd` it is relative
# to). Other mutating events carry absolute paths, or paths relative to the current directory.
DIR_FD_ARGUMENTS: dict[str, tuple[tuple[int, int], ...]] = {
    "os.remove": ((0, 1),),
    "os.rmdir": ((0, 1),),
    "os.mkdir": ((0, 2),),
    "os.chmod": ((0, 2),),
    "os.utime": ((0, 3),),
    "os.rename": ((0, 2), (1, 3)),
    "os.link": ((0, 2), (1, 3)),
    "os.symlink": ((1, 2),),
}


@dataclass
class Recording:
    """The events of one `recording()` block."""

    events: list[tuple[str, tuple[Any, ...]]] = field(default_factory=list)
    mutations: list[tuple[str, str]] = field(default_factory=list)  # (event, full path)

    def named(self, *names: str) -> list[tuple[Any, ...]]:
        return [args for event, args in self.events if event in names]

    def network(self) -> list[str]:
        return [event for event, _ in self.events if event.startswith(NETWORK_PREFIXES)]

    def process(self) -> list[str]:
        return [event for event, _ in self.events if event in PROCESS_EVENTS]

    def written_paths(self) -> list[str]:
        """Every path that was created, written, renamed, changed or removed (not the null device,
        which a child process's standard input is opened on, and not byte-code caches)."""
        paths = [path for _, path in self.mutations]
        for event, args in self.events:
            if event == "open":
                path, flags = args[0], args[2]
                if isinstance(flags, int) and flags & WRITE_FLAGS and _as_text(path):
                    paths.append(_as_text(path))
        null = os.path.normcase(os.devnull)
        return [
            path for path in paths if not path.endswith(".pyc") and os.path.normcase(path) != null
        ]

    def posix_spawned(self) -> list[str]:
        """The programs `os.posix_spawn` was asked to start."""
        return [_as_text(args[0]) for args in self.named("os.posix_spawn")]

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


def _directory_of(descriptor: object) -> str | None:
    """The path of an open directory descriptor, where the system can say (Linux)."""
    if not isinstance(descriptor, int) or isinstance(descriptor, bool) or descriptor < 0:
        return None
    try:
        return os.readlink(f"/proc/self/fd/{descriptor}")
    except OSError:
        return None


def _mutated_paths(event: str, args: tuple[Any, ...]) -> list[str]:
    """The full paths an event changes; one relative to a `dir_fd` is made absolute."""
    layout = DIR_FD_ARGUMENTS.get(event)
    if layout is None:
        return [_as_text(value) for value in args if _as_text(value)]
    paths = []
    for path_index, fd_index in layout:
        path = _as_text(args[path_index]) if path_index < len(args) else ""
        descriptor = args[fd_index] if fd_index < len(args) else None
        if path and not os.path.isabs(path) and isinstance(descriptor, int) and descriptor >= 0:
            directory = _directory_of(descriptor)
            path = os.path.join(directory, path) if directory else f"<fd {descriptor}>/{path}"
        if path:
            paths.append(path)
    return paths


def _hook(event: str, args: tuple[Any, ...]) -> None:
    if not _ACTIVE or not (event in WATCHED or event.startswith(NETWORK_PREFIXES)):
        return
    recorded = _ACTIVE[-1]
    recorded.events.append((event, args))
    if event in MUTATING_EVENTS:
        recorded.mutations.extend((event, path) for path in _mutated_paths(event, args))


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
