"""The ONLY module that runs git for scanning (PLAN.md D2, CLAUDE.md section 5, invariant 4).

A repository is hostile input: its config, attributes, hooks and objects are written by whoever
made it, and git reads them. This module is the single place that turns the tool's request into a
git process, and it removes every documented way for a repository to make git run a program, reach
the network or write something:

* argument lists only, never a shell; the command set is a closed enum with fixed arguments, and
  the only variable parts are object ids, validated revisions and absolute directory names;
* an environment built from scratch (`environment_for`), never inherited: no user or system
  configuration, no pager, no prompt, no replace objects, no lazy fetch, no optional locks;
* command-line configuration (`PINNED_CONFIG`), which wins over the repository's own config, for
  every key that names a program (fsmonitor, hooks, pager, credential helper, ssh command, proxy,
  external diff, signature program) or a transport (`protocol.allow=never`);
* global options `--no-pager --no-replace-objects --literal-pathspecs --no-optional-locks` and an
  explicit `--git-dir`, so that after discovery git never walks upwards or looks at a work tree;
* content read as raw blobs: `cat-file --batch` without `--filters` or `--textconv`, and
  `log --raw` with `--no-ext-diff --no-textconv`, so no attribute-selected driver ever runs;
* bounded output, stderr, time and run budget; a process that exceeds one is killed through its
  handle (and its process tree by PID on Windows), never by image name.

docs/git-hardening.md lists every pinned setting with the documentation it was checked against.
"""

from __future__ import annotations

import contextlib
import os
import queue
import subprocess
import sys
import threading
from collections.abc import Callable, Generator, Mapping, Sequence
from dataclasses import dataclass
from enum import StrEnum
from typing import IO, Protocol

from secret_scanner.core import gitparse
from secret_scanner.core.clock import Clock
from secret_scanner.core.errors import GitError, IncompleteRunError, UsageError
from secret_scanner.core.gitparse import FailureKind, ObjectInfo
from secret_scanner.core.limits import Limits

# -- the closed command set --------------------------------------------------------------------


class GitCommand(StrEnum):
    """Every git invocation the tool can make. There is no way to pass a free-form subcommand."""

    VERSION = "version"
    REV_PARSE = "rev-parse"
    LOG = "log"
    CAT_FILE_CHECK = "cat-file --batch-check"
    CAT_FILE_BATCH = "cat-file --batch"
    LS_FILES = "ls-files"


# The fixed arguments of each command, after the global options and the pinned config.
_FIXED_ARGUMENTS: Mapping[GitCommand, tuple[str, ...]] = {
    GitCommand.VERSION: ("version",),
    GitCommand.REV_PARSE: ("rev-parse",),
    GitCommand.LOG: (
        "log",
        "--raw",
        "-z",
        "--no-abbrev",
        "--no-renames",
        "--no-ext-diff",
        "--no-textconv",
        "--no-color",
        "--no-decorate",
        "--no-show-signature",
        "--no-mailmap",
        "--diff-merges=first-parent",
        "--diff-filter=AMT",
        "--reverse",
        "--topo-order",
        "--format=%x01%H %P %ct",
    ),
    GitCommand.CAT_FILE_CHECK: ("cat-file", "--batch-check"),
    GitCommand.CAT_FILE_BATCH: ("cat-file", "--batch"),
    GitCommand.LS_FILES: ("ls-files", "-z", "--cached", "--others", "--exclude-standard"),
}

GLOBAL_OPTIONS: tuple[str, ...] = (
    "--no-pager",
    "--no-replace-objects",
    "--literal-pathspecs",
    "--no-optional-locks",
)

# Command-line configuration wins over the repository's config, which is the point: a hostile
# `.git/config` cannot turn any of these back on. `/dev/null` is what the git manual gives for
# "no hooks" and git for Windows understands it.
PINNED_CONFIG: tuple[tuple[str, str], ...] = (
    ("core.fsmonitor", "false"),
    ("core.hooksPath", "/dev/null"),
    ("core.pager", "cat"),
    ("core.untrackedCache", "false"),
    ("credential.helper", ""),
    ("protocol.allow", "never"),
    ("core.sshCommand", ""),
    ("core.gitProxy", ""),
    ("log.showSignature", "false"),
    ("diff.external", ""),
    ("gc.auto", "0"),
    ("maintenance.auto", "false"),
    ("log.showRoot", "true"),
    ("color.ui", "never"),
    ("core.quotePath", "true"),
)

# The environment git runs in. Anything the caller's environment holds is dropped; these are all
# there is, plus PATH (the directory of the git binary) and, on Windows, SYSTEMROOT.
FIXED_ENVIRONMENT: tuple[tuple[str, str], ...] = (
    ("GIT_CONFIG_NOSYSTEM", "1"),
    ("GIT_CONFIG_GLOBAL", os.devnull),
    ("GIT_TERMINAL_PROMPT", "0"),
    ("GIT_PAGER", "cat"),
    ("PAGER", "cat"),
    ("GIT_OPTIONAL_LOCKS", "0"),
    ("GIT_NO_REPLACE_OBJECTS", "1"),
    ("GIT_NO_LAZY_FETCH", "1"),
    ("GIT_ATTR_NOSYSTEM", "1"),
    ("GIT_PROTOCOL_FROM_USER", "0"),
    ("LC_ALL", "C"),
)

OBJECT_CHECK_BATCH = 256  # ids per `--batch-check` round trip (a request of about 16 KiB)
_POLL_SECONDS = 0.05
_CHUNK_BYTES = 64 * 1024
_QUEUE_DEPTH = 16
_REAP_SECONDS = 5.0
_HEADER_LINE_LIMIT = 256


def environment_for(
    binary: str,
    parent: Mapping[str, str],
    *,
    platform: str,
    ceiling: str | None = None,
) -> dict[str, str]:
    """The complete environment of a git process. `parent` is read for `SYSTEMROOT` only (Windows);
    `ceiling` is the directory above which repository discovery must not look."""
    environment = dict(FIXED_ENVIRONMENT)
    environment["PATH"] = os.path.dirname(binary)
    if platform == "win32":
        environment["SYSTEMROOT"] = parent.get("SYSTEMROOT") or parent.get("SystemRoot") or ""
        if not environment["SYSTEMROOT"]:
            del environment["SYSTEMROOT"]
    if ceiling is not None:
        environment["GIT_CEILING_DIRECTORIES"] = ceiling
    return environment


# -- processes ----------------------------------------------------------------------------------


class ProcessLike(Protocol):
    """The part of `subprocess.Popen` the runner uses; tests inject fakes with the same shape."""

    stdin: IO[bytes] | None
    stdout: IO[bytes] | None
    stderr: IO[bytes] | None
    pid: int

    def poll(self) -> int | None: ...

    def wait(self, timeout: float | None = None) -> int: ...

    def kill(self) -> None: ...


Spawn = Callable[[Sequence[str], Mapping[str, str], str | None], ProcessLike]
KillTree = Callable[[int], None]


def spawn_process(
    argv: Sequence[str], environment: Mapping[str, str], cwd: str | None
) -> ProcessLike:
    """Start one process: no shell, no inherited descriptors, all three standard streams piped."""
    flags = 0
    if sys.platform == "win32":
        flags = subprocess.CREATE_NO_WINDOW
    return subprocess.Popen(
        list(argv),
        env=dict(environment),
        cwd=cwd,
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        shell=False,
        close_fds=True,
        creationflags=flags,
    )


def taskkill_argv(system_root: str, pid: int) -> list[str] | None:
    """The command that ends a process tree by PID, or None without a system root."""
    if not system_root:
        return None
    program = os.path.join(system_root, "System32", "taskkill.exe")
    return [program, "/PID", str(int(pid)), "/T", "/F"]


def kill_process_tree(pid: int) -> None:
    """Windows: the `git.exe` in the Git for Windows `cmd` directory starts the real git as a
    child, which `Popen.kill` alone
    would leave running. `taskkill /PID <pid> /T /F` ends the tree by PID, never by image name.
    Other platforms have nothing to do here (the process itself is the git)."""
    if sys.platform == "win32":
        argv = taskkill_argv(os.environ.get("SYSTEMROOT", ""), pid)
        if argv is not None:
            with contextlib.suppress(OSError, subprocess.SubprocessError):
                subprocess.run(
                    argv,
                    stdin=subprocess.DEVNULL,
                    stdout=subprocess.DEVNULL,
                    stderr=subprocess.DEVNULL,
                    shell=False,
                    timeout=_REAP_SECONDS,
                    check=False,
                )


class GitLimitError(IncompleteRunError):
    """A cap or a deadline stopped a git call and the process was killed (exit code 4).
    `time_budget` tells the two apart for the issue that records it."""

    def __init__(self, message: str, *, time_budget: bool) -> None:
        super().__init__(message)
        self.time_budget = time_budget


class _Nothing:
    """Marker for 'no chunk yet' on the queue."""


_NOTHING = _Nothing()


def _read_some(pipe: IO[bytes]) -> bytes:
    reader = getattr(pipe, "read1", None)
    if callable(reader):
        return bytes(reader(_CHUNK_BYTES))
    return bytes(pipe.read(_CHUNK_BYTES))


class _Pump:
    """Reads one pipe on a daemon thread into a bounded queue (`None` marks the end)."""

    def __init__(self, pipe: IO[bytes] | None, label: str) -> None:
        self._queue: queue.Queue[bytes | None] = queue.Queue(maxsize=_QUEUE_DEPTH)
        self._stop = threading.Event()
        self._thread = threading.Thread(
            target=self._run, args=(pipe,), name=f"git-{label}", daemon=True
        )
        self._thread.start()

    def _offer(self, item: bytes | None) -> bool:
        while not self._stop.is_set():
            try:
                self._queue.put(item, timeout=_POLL_SECONDS)
            except queue.Full:
                continue
            return True
        return False

    def _run(self, pipe: IO[bytes] | None) -> None:
        try:
            while pipe is not None and not self._stop.is_set():
                chunk = _read_some(pipe)
                if not chunk or not self._offer(chunk):
                    break
        except (OSError, ValueError):
            pass  # the pipe was closed under us (the process was killed): the end of the stream
        finally:
            self._offer(None)

    def get(self, timeout: float) -> bytes | _Nothing | None:
        try:
            return self._queue.get(timeout=timeout)
        except queue.Empty:
            return _NOTHING

    def stop(self) -> None:
        self._stop.set()


class _StderrCollector:
    """Drains stderr on a thread into a bounded buffer; going over the cap sets `overflow`."""

    def __init__(self, pipe: IO[bytes] | None, cap: int) -> None:
        self._cap = cap
        self._data = bytearray()
        self.overflow = threading.Event()
        self._thread = threading.Thread(target=self._run, args=(pipe,), name="git-err", daemon=True)
        self._thread.start()

    def _run(self, pipe: IO[bytes] | None) -> None:
        try:
            while pipe is not None:
                chunk = _read_some(pipe)
                if not chunk:
                    break
                room = self._cap - len(self._data)
                if len(chunk) > room:
                    self.overflow.set()
                self._data += chunk[: max(room, 0)]
        except (OSError, ValueError):
            pass

    def text(self) -> bytes:
        self._thread.join(timeout=_REAP_SECONDS)
        return bytes(self._data)


@dataclass(frozen=True, slots=True)
class GitResult:
    returncode: int
    stdout: bytes
    stderr: bytes


class _Call:
    """One running git process with its readers, a deadline and the caps. Everything that can go
    wrong ends the process and raises: `GitLimitError` for a cap or the deadline, `GitError` for git
    itself failing."""

    def __init__(
        self,
        runner: GitRunner,
        argv: Sequence[str],
        *,
        cwd: str | None,
        environment: Mapping[str, str],
        timeout: float,
    ) -> None:
        self._runner = runner
        self._deadline = runner.clock.monotonic() + timeout
        self._stdout_cap = runner.limits.max_git_output_bytes
        self.process = runner.spawn(argv, environment, cwd)
        self._pump = _Pump(self.process.stdout, "out")
        self._stderr = _StderrCollector(self.process.stderr, runner.limits.max_git_stderr_bytes)
        self._buffer = bytearray()
        self._eof = False
        self._total = 0
        self._writer: threading.Thread | None = None
        self._write_failed = threading.Event()

    # -- stdin ------------------------------------------------------------------------------

    def send(self, data: bytes) -> None:
        """Start writing `data` to git's input and return at once. The write runs on its own
        thread because git answers while it reads: a writer that blocks on a full input pipe
        while nobody reads the output pipe would deadlock both sides. The caller reads the answers
        (`read_line`, `read_exact`) and the next `send` waits for this write to end first."""
        stream = self.process.stdin
        if stream is None:
            raise GitError("git has no input stream")
        self._wait_for_writer()
        writer = threading.Thread(
            target=self._write, args=(stream, data), name="git-in", daemon=True
        )
        self._writer = writer
        writer.start()

    def _write(self, stream: IO[bytes], data: bytes) -> None:
        try:
            stream.write(data)
            stream.flush()
        except (OSError, ValueError):
            self._write_failed.set()

    def _wait_for_writer(self) -> None:
        writer = self._writer
        while writer is not None and writer.is_alive():
            self._check_limits()
            writer.join(_POLL_SECONDS)
        self._writer = None
        if self._write_failed.is_set():
            self.terminate()
            raise GitError(f"git stopped reading its input: {self.stderr_summary()}")

    def close_input(self) -> None:
        self._wait_for_writer()
        stream = self.process.stdin
        if stream is not None:
            try:
                stream.close()
            except (OSError, ValueError):
                return

    # -- stdout -----------------------------------------------------------------------------

    def _check_limits(self) -> None:
        if self._write_failed.is_set():
            self.terminate()
            raise GitError(f"git stopped reading its input: {self.stderr_summary()}")
        if self._stderr.overflow.is_set():
            self.terminate()
            raise GitLimitError(
                f"git wrote more than {self._runner.limits.max_git_stderr_bytes} bytes of "
                "error output; stopped",
                time_budget=False,
            )
        if self._total > self._stdout_cap:
            self.terminate()
            raise GitLimitError(
                f"git wrote more than {self._stdout_cap} bytes in one call; stopped",
                time_budget=False,
            )
        if self._runner.clock.monotonic() >= self._deadline:
            self.terminate()
            raise GitLimitError(
                "a git call exceeded its time limit and was stopped", time_budget=True
            )

    def _fill(self) -> None:
        """Take one more chunk of stdout into the buffer (or learn that the stream ended)."""
        while True:
            self._check_limits()
            item = self._pump.get(_POLL_SECONDS)
            if isinstance(item, _Nothing):
                continue
            if item is None:
                self._eof = True
                return
            self._total += len(item)
            self._buffer += item
            self._check_limits()
            return

    def read_chunk(self) -> bytes:
        """Whatever is buffered, or the next chunk; `b""` at the end of the stream."""
        if not self._buffer and not self._eof:
            self._fill()
        data = bytes(self._buffer)
        self._buffer.clear()
        return data

    def read_line(self, limit: int) -> bytes:
        """One line including its `\\n`; more than `limit` bytes without one is an error."""
        while True:
            newline = self._buffer.find(b"\n")
            if newline >= 0:
                line = bytes(self._buffer[: newline + 1])
                del self._buffer[: newline + 1]
                return line
            if len(self._buffer) > limit:
                self.terminate()
                raise gitparse.GitOutputError("unexpected git output: a line longer than the limit")
            if self._eof:
                self._wait_for_writer()
                raise GitError(f"git ended unexpectedly: {self.stderr_summary()}")
            self._fill()

    def read_exact(self, count: int) -> bytes:
        while len(self._buffer) < count:
            if self._eof:
                self._wait_for_writer()
                raise GitError(f"git ended unexpectedly: {self.stderr_summary()}")
            self._fill()
        data = bytes(self._buffer[:count])
        del self._buffer[:count]
        return data

    # -- the end ----------------------------------------------------------------------------

    def stderr_bytes(self) -> bytes:
        return self._stderr.text()

    def stderr_summary(self) -> str:
        return gitparse.summarize_stderr(self.stderr_bytes())

    def terminate(self) -> None:
        """Stop the process by its handle (and its tree by PID on Windows) and reap it."""
        self._pump.stop()
        if self.process.poll() is None:
            self._runner.kill_tree(self.process.pid)
            with contextlib.suppress(OSError):  # already gone
                self.process.kill()
        with contextlib.suppress(subprocess.TimeoutExpired, OSError):
            self.process.wait(timeout=_REAP_SECONDS)

    def finish(self) -> int:
        """Wait for a process whose output has been read completely; return its exit code."""
        self.close_input()
        remaining = max(self._deadline - self._runner.clock.monotonic(), 1.0)
        try:
            return self.process.wait(timeout=remaining)
        except subprocess.TimeoutExpired:
            self.terminate()
            raise GitLimitError(
                "a git call did not end after its output was read; stopped", time_budget=True
            ) from None

    def close(self) -> None:
        """Idempotent cleanup: end the process if it still runs, release the pipes."""
        self._pump.stop()
        if self.process.poll() is None:
            self.terminate()
        for stream in (self.process.stdin, self.process.stdout, self.process.stderr):
            if stream is not None:
                try:
                    stream.close()
                except (OSError, ValueError):
                    continue


# -- the runner ---------------------------------------------------------------------------------


class GitRunner:
    """Runs the allowlisted commands against one repository.

    `binary` is an absolute path chosen by the caller (`fs.safe_files.find_program`). `clock` is
    injected so the deadline is testable; `deadline` is the run's end on that clock.
    """

    def __init__(
        self,
        binary: str,
        *,
        limits: Limits,
        clock: Clock,
        deadline: float,
        parent_environment: Mapping[str, str],
        platform: str,
        spawn: Spawn = spawn_process,
        kill_tree: KillTree = kill_process_tree,
    ) -> None:
        if not os.path.isabs(binary):
            raise GitError("the git binary must be given as an absolute path")
        self.binary = binary
        self.limits = limits
        self.clock = clock
        self.spawn = spawn
        self.kill_tree = kill_tree
        self._deadline = deadline
        self._parent_environment = parent_environment
        self._platform = platform

    # -- assembly ---------------------------------------------------------------------------

    def argv(
        self,
        command: GitCommand,
        arguments: Sequence[str] = (),
        *,
        git_dir: str | None,
        safe_directory: str | None = None,
    ) -> list[str]:
        """The full argument list. `arguments` are the variable parts: object ids and validated
        revisions only (the callers validate; `_check_argument` is the last line of defence)."""
        command = GitCommand(command)  # a name outside the enum is a ValueError, never a process
        for argument in arguments:
            _check_argument(argument)
        argv = [self.binary, *GLOBAL_OPTIONS]
        if git_dir is not None:
            argv.append(f"--git-dir={git_dir}")
        for key, value in PINNED_CONFIG:
            argv += ["-c", f"{key}={value}"]
        if safe_directory is not None:
            argv += ["-c", f"safe.directory={safe_directory}"]
        argv += _FIXED_ARGUMENTS[command]
        argv += arguments
        return argv

    def _environment(self, ceiling: str | None) -> dict[str, str]:
        return environment_for(
            self.binary, self._parent_environment, platform=self._platform, ceiling=ceiling
        )

    def _timeout(self, *, short: bool) -> float:
        remaining = self._deadline - self.clock.monotonic()
        if remaining <= 0:
            raise GitLimitError(
                f"the run budget of {self.limits.max_run_seconds} seconds is exhausted",
                time_budget=True,
            )
        if short:
            return min(float(self.limits.git_call_timeout_seconds), remaining)
        return remaining

    def _run(
        self,
        command: GitCommand,
        arguments: Sequence[str] = (),
        *,
        git_dir: str | None,
        cwd: str | None,
        ceiling: str | None = None,
        safe_directory: str | None = None,
    ) -> GitResult:
        argv = self.argv(command, arguments, git_dir=git_dir, safe_directory=safe_directory)
        call = _Call(
            self,
            argv,
            cwd=cwd,
            environment=self._environment(ceiling),
            timeout=self._timeout(short=True),
        )
        try:
            call.close_input()
            chunks: list[bytes] = []
            while True:
                chunk = call.read_chunk()
                if not chunk:
                    break
                chunks.append(chunk)
            code = call.finish()
            return GitResult(code, b"".join(chunks), call.stderr_bytes())
        finally:
            call.close()

    # -- short commands ---------------------------------------------------------------------

    def version(self) -> tuple[int, int, int]:
        """The installed git's version; GitError when it is older than the supported minimum."""
        result = self._run(GitCommand.VERSION, git_dir=None, cwd=None)
        if result.returncode != 0:
            raise GitError(f"`git version` failed: {gitparse.summarize_stderr(result.stderr)}")
        found = gitparse.parse_git_version(result.stdout)
        if not gitparse.version_is_supported(found):
            raise GitError(
                f"git {gitparse.describe_version(found)} is older than the supported minimum "
                f"{gitparse.describe_version(gitparse.MIN_GIT_VERSION)}"
            )
        return found

    def discover(self, directory: str, *, ceiling: str | None, allow_other_owner: bool) -> str:
        """The absolute git directory of the repository at `directory`, found without looking
        above `ceiling`. A repository of another owner is refused unless allowed, then trusted for
        exactly this directory (D2); the pinned config already removed what the check guards."""
        result = self._run(
            GitCommand.REV_PARSE,
            ("--absolute-git-dir",),
            git_dir=None,
            cwd=directory,
            ceiling=ceiling,
            safe_directory=directory if allow_other_owner else None,
        )
        if result.returncode != 0:
            raise self.failure(result, "the directory is not a git repository")
        return gitparse.parse_single_line_path(result.stdout)

    def is_shallow(self, git_dir: str) -> bool:
        result = self._run(
            GitCommand.REV_PARSE, ("--is-shallow-repository",), git_dir=git_dir, cwd=git_dir
        )
        if result.returncode != 0:
            raise self.failure(result, "cannot tell whether the repository is shallow")
        return gitparse.parse_boolean_line(result.stdout)

    def resolve_commit(self, git_dir: str, revision: str) -> str:
        """A validated revision as a full commit id, resolved after `--end-of-options`."""
        gitparse.validate_revision(revision)
        result = self._run(
            GitCommand.REV_PARSE,
            ("--verify", "--end-of-options", f"{revision}^{{commit}}"),
            git_dir=git_dir,
            cwd=git_dir,
        )
        if result.returncode != 0:
            raise GitError(
                "revision does not name a commit: "
                f"{gitparse.summarize_stderr(result.stderr, max_chars=120)}"
            )
        return gitparse.parse_rev_parse_id(result.stdout)

    def list_files(self, directory: str, *, allow_other_owner: bool) -> list[bytes]:
        """`ls-files` for `scan --gitignore`: tracked plus untracked-not-ignored paths of the work
        tree that contains `directory`, relative to it. Discovery may look above `directory` (the
        directory is allowed to be inside a work tree)."""
        result = self._run(
            GitCommand.LS_FILES,
            (),
            git_dir=None,
            cwd=directory,
            safe_directory=directory if allow_other_owner else None,
        )
        if result.returncode != 0:
            if gitparse.classify_failure(result.stderr) is FailureKind.NOT_A_REPOSITORY:
                raise UsageError("--gitignore: the path is not inside a git work tree")
            raise self.failure(result, "git could not list the files of the work tree")
        return gitparse.parse_nul_paths(result.stdout)

    def failure(self, result: GitResult, context: str) -> GitError:
        """The error for a non-zero exit, with a message that never echoes more than the first
        line of git's error text, escaped."""
        kind = gitparse.classify_failure(result.stderr)
        if kind is FailureKind.DUBIOUS_OWNERSHIP:
            return GitError(
                "git refuses the repository because it belongs to another user (dubious "
                "ownership); if you trust it, run again with --allow-other-owner"
            )
        if kind is FailureKind.NOT_A_REPOSITORY:
            return GitError(f"{context}: not a git repository")
        return GitError(f"{context}: {gitparse.summarize_stderr(result.stderr)}")

    # -- the history stream -------------------------------------------------------------------

    def stream_history(
        self, git_dir: str, revisions: Sequence[str], *, all_refs: bool
    ) -> Generator[bytes, None, None]:
        """Chunks of the `log --raw -z` stream for `revisions` (full object ids, a leading `^`
        excludes). `--all` is an option, so it goes before `--end-of-options`; after it only
        object ids appear. A non-zero exit raises after the last chunk; leaving the iterator early
        ends the process."""
        for revision in revisions:
            if not gitparse.is_object_id(revision.removeprefix("^").encode("ascii", "replace")):
                raise GitError("internal error: a history revision that is not an object id")
        arguments = ["--all"] if all_refs else []
        arguments += ["--end-of-options", *revisions, "--"]
        argv = self.argv(GitCommand.LOG, arguments, git_dir=git_dir)
        call = _Call(
            self,
            argv,
            cwd=git_dir,
            environment=self._environment(None),
            timeout=self._timeout(short=False),
        )
        try:
            call.close_input()
            while True:
                chunk = call.read_chunk()
                if not chunk:
                    break
                yield chunk
            code = call.finish()
            if code != 0:
                raise self.failure(
                    GitResult(code, b"", call.stderr_bytes()), "git could not read the history"
                )
        finally:
            call.close()

    # -- object reads -------------------------------------------------------------------------

    def open_objects(self, git_dir: str) -> ObjectReader:
        return ObjectReader(self, git_dir)


def _check_argument(argument: str) -> None:
    """Variable arguments are object ids (optionally `^`-excluded), one of the fixed tokens, or a
    validated revision followed by `^{commit}`. Anything else is a bug in the caller, and it must
    never reach a process."""
    if argument in _FIXED_TOKENS:
        return
    if argument.endswith("^{commit}"):
        gitparse.validate_revision(argument.removesuffix("^{commit}"))
        return
    if not gitparse.is_object_id(argument.removeprefix("^").encode("ascii", "replace")):
        raise GitError("internal error: a git argument that is not allowed")


_FIXED_TOKENS = frozenset(
    {
        "--all",
        "--end-of-options",
        "--",
        "--absolute-git-dir",
        "--is-shallow-repository",
        "--verify",
    }
)


class ObjectReader:
    """Two long-running `cat-file` processes: `--batch-check` for sizes (so an oversized blob is
    never read) and `--batch` for the contents. Requests are written one batch at a time and the
    answers read back before the next, so neither pipe can fill and block the other side."""

    def __init__(self, runner: GitRunner, git_dir: str) -> None:
        self._runner = runner
        self._git_dir = git_dir
        self._check: _Call | None = None
        self._batch: _Call | None = None

    def _start(self, command: GitCommand) -> _Call:
        runner = self._runner
        return _Call(
            runner,
            runner.argv(command, (), git_dir=self._git_dir),
            cwd=self._git_dir,
            environment=runner._environment(None),
            timeout=runner._timeout(short=False),
        )

    def sizes(self, oids: Sequence[str]) -> list[ObjectInfo]:
        """The type and size of each object, or kind `missing`, in the order asked."""
        answers: list[ObjectInfo] = []
        for start in range(0, len(oids), OBJECT_CHECK_BATCH):
            group = oids[start : start + OBJECT_CHECK_BATCH]
            for oid in group:
                gitparse.require_object_id(oid)
            if self._check is None:
                self._check = self._start(GitCommand.CAT_FILE_CHECK)
            self._check.send(("\n".join(group) + "\n").encode("ascii"))
            for oid in group:
                line = self._check.read_line(_HEADER_LINE_LIMIT)
                answers.append(gitparse.parse_object_line(line, oid))
        return answers

    def read_blob(self, oid: str, size: int) -> bytes:
        """The raw content of blob `oid`, whose size `sizes` reported. A different size or type is
        an error: the repository changed under us or git did not do what was asked."""
        gitparse.require_object_id(oid)
        if self._batch is None:
            self._batch = self._start(GitCommand.CAT_FILE_BATCH)
        self._batch.send(oid.encode("ascii") + b"\n")
        header = gitparse.parse_object_line(self._batch.read_line(_HEADER_LINE_LIMIT), oid)
        if header.kind != "blob" or header.size != size:
            self._batch.terminate()
            raise GitError("git returned a different object than the one measured")
        data = self._batch.read_exact(size)
        if self._batch.read_exact(1) != b"\n":
            self._batch.terminate()
            raise gitparse.GitOutputError("unexpected git output: a blob not ended by a newline")
        return data

    def close(self) -> None:
        for call in (self._check, self._batch):
            if call is not None:
                call.close()
        self._check = None
        self._batch = None

    def __enter__(self) -> ObjectReader:
        return self

    def __exit__(self, *exc: object) -> None:
        self.close()
