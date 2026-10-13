"""The git runner (`gitio/runner.py`): environment, pinned configuration, the closed command set,
bounds and process control. Fake process objects stand in for git, so a hang or a flood is
deterministic and nothing waits."""

from __future__ import annotations

import os
import queue
import subprocess
import sys
from collections.abc import Callable, Mapping, Sequence
from datetime import UTC, datetime
from pathlib import Path
from typing import IO, cast

import pytest

from secret_scanner.core.errors import GitError, IncompleteRunError, UsageError
from secret_scanner.core.limits import DEFAULT_LIMITS, Limits
from secret_scanner.gitio import runner as runner_module
from secret_scanner.gitio.runner import (
    FIXED_ENVIRONMENT,
    GLOBAL_OPTIONS,
    OBJECT_CHECK_BATCH,
    PINNED_CONFIG,
    GitCommand,
    GitLimitError,
    GitRunner,
    Spawn,
    environment_for,
    spawn_process,
    taskkill_argv,
)

ZERO = "0" * 40
LF = chr(10).encode()


def oid(number: int) -> str:
    return f"{number:040x}"


# -- fakes ---------------------------------------------------------------------------------------


class Pipe:
    """A readable pipe fed by the test: `feed` data, `end` it (or `kill` the process)."""

    def __init__(self, chunks: Sequence[bytes] = (), *, ended: bool = True) -> None:
        self._queue: queue.Queue[bytes | None] = queue.Queue()
        self._pending = b""
        for chunk in chunks:
            self._queue.put(chunk)
        if ended:
            self._queue.put(None)
        self.closed = False

    def feed(self, data: bytes) -> None:
        self._queue.put(data)

    def end(self) -> None:
        self._queue.put(None)

    def read1(self, size: int = -1) -> bytes:
        if not self._pending:
            item = self._queue.get()
            if item is None:
                self._queue.put(None)
                return b""
            self._pending = item
        if size > 0:
            taken, self._pending = self._pending[:size], self._pending[size:]
        else:
            taken, self._pending = self._pending, b""
        return taken

    def read(self, size: int = -1) -> bytes:
        return self.read1(size)

    def close(self) -> None:
        self.closed = True


class Sink:
    def __init__(self, on_write: Callable[[bytes], None] | None = None) -> None:
        self.data = bytearray()
        self.closed = False
        self._on_write = on_write

    def write(self, data: bytes) -> int:
        self.data += data
        if self._on_write is not None:
            self._on_write(bytes(data))
        return len(data)

    def flush(self) -> None:
        return None

    def close(self) -> None:
        self.closed = True


class FakeProcess:
    """Stands in for `subprocess.Popen`. A process that never ends is `hang=True`: its pipes stay
    open and `wait` times out until `kill` is called."""

    def __init__(
        self,
        stdout: Sequence[bytes] = (),
        stderr: Sequence[bytes] = (),
        *,
        returncode: int = 0,
        hang: bool = False,
        on_stdin: Callable[[FakeProcess, bytes], None] | None = None,
        pid: int = 4242,
    ) -> None:
        self.stdout = Pipe(stdout, ended=not hang)
        self.stderr = Pipe(stderr, ended=not hang)
        self.stdin = Sink(lambda data: on_stdin(self, data) if on_stdin else None)
        self.pid = pid
        self._returncode = returncode
        self._hang = hang
        self.killed = False

    def poll(self) -> int | None:
        if self._hang and not self.killed:
            return None
        return -9 if self.killed else self._returncode

    def wait(self, timeout: float | None = None) -> int:
        if self._hang and not self.killed:
            raise subprocess.TimeoutExpired("git", timeout or 0)
        return -9 if self.killed else self._returncode

    def kill(self) -> None:
        self.killed = True
        self.stdout.end()
        self.stderr.end()


class TickClock:
    """Every reading advances time by `step` seconds, so a deadline passes deterministically."""

    def __init__(self, step: float = 0.0) -> None:
        self.now = 1000.0
        self.step = step

    def monotonic(self) -> float:
        self.now += self.step
        return self.now

    def now_utc(self) -> datetime:
        return datetime(2026, 1, 1, tzinfo=UTC)


class Recorder:
    """A `spawn` that hands out scripted processes and remembers every call."""

    def __init__(self, *processes: FakeProcess) -> None:
        self._processes = list(processes)
        self.calls: list[tuple[list[str], dict[str, str], str | None]] = []
        self.spawned: list[FakeProcess] = []
        self.tree_kills: list[int] = []

    def __call__(
        self, argv: Sequence[str], environment: Mapping[str, str], cwd: str | None
    ) -> FakeProcess:
        self.calls.append((list(argv), dict(environment), cwd))
        process = self._processes.pop(0)
        self.spawned.append(process)
        return process

    def kill_tree(self, pid: int) -> None:
        self.tree_kills.append(pid)


def make_runner(
    tmp_path: Path,
    recorder: Recorder,
    *,
    limits: Limits = DEFAULT_LIMITS,
    clock: TickClock | None = None,
    deadline: float = 10_000.0,
    platform: str = "linux",
    parent: Mapping[str, str] | None = None,
) -> GitRunner:
    return GitRunner(
        str(tmp_path / "bin" / "git"),
        limits=limits,
        clock=clock or TickClock(),
        deadline=deadline,
        parent_environment=parent if parent is not None else {},
        platform=platform,
        spawn=cast(Spawn, recorder),
        kill_tree=recorder.kill_tree,
    )


# -- the environment -----------------------------------------------------------------------------


def test_environment_is_exactly_the_fixed_keys_plus_path_on_posix() -> None:
    environment = environment_for("/usr/bin/git", {"HOME": "/home/u"}, platform="linux")
    assert environment == {
        "GIT_CONFIG_NOSYSTEM": "1",
        "GIT_CONFIG_GLOBAL": os.devnull,
        "GIT_TERMINAL_PROMPT": "0",
        "GIT_PAGER": "cat",
        "PAGER": "cat",
        "GIT_OPTIONAL_LOCKS": "0",
        "GIT_NO_REPLACE_OBJECTS": "1",
        "GIT_NO_LAZY_FETCH": "1",
        "GIT_ATTR_NOSYSTEM": "1",
        "GIT_PROTOCOL_FROM_USER": "0",
        "LC_ALL": "C",
        "PATH": os.path.dirname("/usr/bin/git"),
    }


def test_windows_adds_only_systemroot() -> None:
    parent = {"SYSTEMROOT": r"C:\Windows", "TEMP": r"C:\x", "USERPROFILE": r"C:\Users\u"}
    environment = environment_for(r"C:\Git\cmd\git.exe", parent, platform="win32")
    posix = environment_for(r"C:\Git\cmd\git.exe", parent, platform="linux")
    assert set(environment) - set(posix) == {"SYSTEMROOT"}
    assert environment["SYSTEMROOT"] == r"C:\Windows"
    assert "TEMP" not in environment
    assert "USERPROFILE" not in environment


def test_windows_systemroot_is_found_case_insensitively_and_may_be_absent() -> None:
    assert environment_for("g", {"SystemRoot": "R"}, platform="win32")["SYSTEMROOT"] == "R"
    assert "SYSTEMROOT" not in environment_for("g", {}, platform="win32")


def test_the_callers_environment_is_never_inherited() -> None:
    poison = dict.fromkeys(
        (
            "GIT_DIR",
            "GIT_WORK_TREE",
            "GIT_EXTERNAL_DIFF",
            "GIT_SSH",
            "GIT_SSH_COMMAND",
            "GIT_ASKPASS",
            "SSH_ASKPASS",
            "GIT_EXEC_PATH",
            "GIT_TRACE",
            "GIT_TRACE_PACKET",
            "GIT_CONFIG_PARAMETERS",
            "GIT_CONFIG_COUNT",
            "GIT_CONFIG_KEY_0",
            "GIT_CONFIG_VALUE_0",
            "GIT_ALTERNATE_OBJECT_DIRECTORIES",
            "GIT_OBJECT_DIRECTORY",
            "GIT_INDEX_FILE",
            "GIT_NAMESPACE",
            "GIT_EDITOR",
            "GIT_PROXY_COMMAND",
            "HOME",
            "XDG_CONFIG_HOME",
            "PATH",
            "PYTHONPATH",
        ),
        "poison",
    )
    environment = environment_for("/usr/bin/git", poison, platform="linux")
    assert "poison" not in environment.values()
    assert set(environment) == {name for name, _ in FIXED_ENVIRONMENT} | {"PATH"}
    assert environment["PATH"] == os.path.dirname("/usr/bin/git")


def test_a_discovery_ceiling_is_the_only_optional_key() -> None:
    environment = environment_for("/usr/bin/git", {}, platform="linux", ceiling="/work")
    assert environment["GIT_CEILING_DIRECTORIES"] == "/work"
    assert "GIT_CEILING_DIRECTORIES" not in environment_for("/usr/bin/git", {}, platform="linux")


# -- pinned configuration and the command line ----------------------------------------------------


def test_pinned_configuration_key_by_key() -> None:
    assert dict(PINNED_CONFIG) == {
        "core.fsmonitor": "false",
        "core.hooksPath": "/dev/null",
        "core.pager": "cat",
        "core.untrackedCache": "false",
        "credential.helper": "",
        "protocol.allow": "never",
        "core.sshCommand": "",
        "core.gitProxy": "",
        "log.showSignature": "false",
        "diff.external": "",
        "gc.auto": "0",
        "maintenance.auto": "false",
        "log.showRoot": "true",
        "color.ui": "never",
        "core.quotePath": "true",
    }
    assert len({key for key, _ in PINNED_CONFIG}) == len(PINNED_CONFIG)  # no key twice


def test_global_options() -> None:
    assert GLOBAL_OPTIONS == (
        "--no-pager",
        "--no-replace-objects",
        "--literal-pathspecs",
        "--no-optional-locks",
    )


def test_the_command_set_is_closed() -> None:
    assert {command.name for command in GitCommand} == {
        "VERSION",
        "REV_PARSE",
        "LOG",
        "CAT_FILE_CHECK",
        "CAT_FILE_BATCH",
        "LS_FILES",
    }
    assert set(runner_module._FIXED_ARGUMENTS) == set(GitCommand)


def test_argv_layout_for_the_history_walk(tmp_path: Path) -> None:
    runner = make_runner(tmp_path, Recorder())
    argv = runner.argv(
        GitCommand.LOG, ["--all", "--end-of-options", oid(1), f"^{oid(2)}", "--"], git_dir="/g/.git"
    )
    assert argv[0] == runner.binary
    assert argv[1:5] == list(GLOBAL_OPTIONS)
    assert argv[5] == "--git-dir=/g/.git"
    pinned = argv[6 : 6 + 2 * len(PINNED_CONFIG)]
    assert pinned[0::2] == ["-c"] * len(PINNED_CONFIG)
    assert pinned[1::2] == [f"{key}={value}" for key, value in PINNED_CONFIG]
    tail = argv[6 + 2 * len(PINNED_CONFIG) :]
    assert tail[0] == "log"
    for flag in (
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
    ):
        assert flag in tail
    # --all is an option: before --end-of-options; after it only object ids and the final `--`
    assert tail.index("--all") < tail.index("--end-of-options")
    assert tail[tail.index("--end-of-options") + 1 :] == [oid(1), f"^{oid(2)}", "--"]
    assert not any(argument.startswith("--git-dir") for argument in tail)


def test_cat_file_never_filters_or_converts(tmp_path: Path) -> None:
    runner = make_runner(tmp_path, Recorder())
    for command in (GitCommand.CAT_FILE_CHECK, GitCommand.CAT_FILE_BATCH):
        argv = runner.argv(command, (), git_dir="/g/.git")
        assert "--filters" not in argv
        assert "--textconv" not in argv
        assert "--follow-symlinks" not in argv
    assert runner.argv(GitCommand.CAT_FILE_CHECK, (), git_dir="/g")[-2:] == [
        "cat-file",
        "--batch-check",
    ]
    assert runner.argv(GitCommand.CAT_FILE_BATCH, (), git_dir="/g")[-2:] == ["cat-file", "--batch"]


@pytest.mark.parametrize(
    "argument",
    [
        "--output=x",
        "-c",
        "-c core.pager=x",
        "main",
        "HEAD",
        "--upload-pack=cmd",
        "--exec-path=/x",
        "$(touch x)",
        "a b",
        oid(1) + "x",
        "^main",
        "--help",
        "--version",
        "",
    ],
)
def test_free_form_arguments_cannot_reach_a_process(tmp_path: Path, argument: str) -> None:
    runner = make_runner(tmp_path, Recorder())
    with pytest.raises(GitError):
        runner.argv(GitCommand.LOG, [argument], git_dir="/g/.git")


def test_a_command_outside_the_enum_is_refused(tmp_path: Path) -> None:
    runner = make_runner(tmp_path, Recorder())
    for name in ("status", "fetch", "config", "gc", "clone", "checkout", "!sh"):
        with pytest.raises(ValueError, match="is not a valid GitCommand"):
            runner.argv(name, (), git_dir=None)  # type: ignore[arg-type]


def test_the_binary_must_be_absolute() -> None:
    with pytest.raises(GitError, match="absolute"):
        GitRunner(
            "git",
            limits=DEFAULT_LIMITS,
            clock=TickClock(),
            deadline=1.0,
            parent_environment={},
            platform="linux",
        )


def test_safe_directory_only_when_allowed_and_only_for_that_directory(tmp_path: Path) -> None:
    runner = make_runner(tmp_path, Recorder())
    plain = runner.argv(GitCommand.REV_PARSE, ("--absolute-git-dir",), git_dir=None)
    assert not any("safe.directory" in argument for argument in plain)
    trusted = runner.argv(
        GitCommand.REV_PARSE, ("--absolute-git-dir",), git_dir=None, safe_directory="/r"
    )
    assert trusted.count("safe.directory=/r") == 1


# -- short commands ------------------------------------------------------------------------------


def test_version_is_read_and_checked(tmp_path: Path) -> None:
    recorder = Recorder(FakeProcess([b"git version 2.54.0.windows.1" + LF]))
    runner = make_runner(tmp_path, recorder)
    assert runner.version() == (2, 54, 0)
    argv, environment, cwd = recorder.calls[0]
    assert argv[-1] == "version"
    assert cwd is None
    assert "GIT_DIR" not in environment


def test_an_old_git_is_refused_with_both_versions_named(tmp_path: Path) -> None:
    runner = make_runner(tmp_path, Recorder(FakeProcess([b"git version 2.31.1" + LF])))
    with pytest.raises(GitError, match=r"2\.31\.1.*2\.32\.0"):
        runner.version()


def test_version_failures(tmp_path: Path) -> None:
    runner = make_runner(tmp_path, Recorder(FakeProcess([b""], [b"boom" + LF], returncode=1)))
    with pytest.raises(GitError, match="boom"):
        runner.version()
    runner = make_runner(tmp_path, Recorder(FakeProcess([b"not git" + LF])))
    with pytest.raises(GitError, match="unexpected git output"):
        runner.version()


def test_discovery_uses_the_ceiling_and_the_directory(tmp_path: Path) -> None:
    recorder = Recorder(FakeProcess([b"/r/.git" + LF]))
    runner = make_runner(tmp_path, recorder)
    assert runner.discover("/r", ceiling="/", allow_other_owner=False) == "/r/.git"
    argv, environment, cwd = recorder.calls[0]
    assert cwd == "/r"
    assert environment["GIT_CEILING_DIRECTORIES"] == "/"
    assert "--absolute-git-dir" in argv
    assert not any(argument.startswith("--git-dir") for argument in argv)


def test_discovery_with_allow_other_owner_trusts_exactly_that_directory(tmp_path: Path) -> None:
    recorder = Recorder(FakeProcess([b"/r/.git" + LF]))
    make_runner(tmp_path, recorder).discover("/r", ceiling=None, allow_other_owner=True)
    assert "safe.directory=/r" in recorder.calls[0][0]


def test_dubious_ownership_is_explained_and_names_the_option(tmp_path: Path) -> None:
    stderr = b"fatal: detected dubious ownership in repository at '/r'" + LF
    runner = make_runner(tmp_path, Recorder(FakeProcess([], [stderr], returncode=128)))
    with pytest.raises(GitError, match="--allow-other-owner") as caught:
        runner.discover("/r", ceiling=None, allow_other_owner=False)
    assert "/r" not in str(caught.value)


def test_not_a_repository(tmp_path: Path) -> None:
    stderr = b"fatal: not a git repository (or any of the parent directories): .git" + LF
    runner = make_runner(tmp_path, Recorder(FakeProcess([], [stderr], returncode=128)))
    with pytest.raises(GitError, match="not a git repository"):
        runner.discover("/r", ceiling=None, allow_other_owner=False)


def test_resolution_uses_end_of_options_and_the_peel(tmp_path: Path) -> None:
    recorder = Recorder(FakeProcess([oid(9).encode() + LF]))
    runner = make_runner(tmp_path, recorder)
    assert runner.resolve_commit("/g/.git", "feature/x") == oid(9)
    tail = recorder.calls[0][0][-3:]
    assert tail == ["--verify", "--end-of-options", "feature/x^{commit}"]


def test_resolution_validates_before_any_process_starts(tmp_path: Path) -> None:
    recorder = Recorder()
    runner = make_runner(tmp_path, recorder)
    for revision in ("--output=x", "a:b", "@{-1}", "-c x"):
        with pytest.raises(UsageError):
            runner.resolve_commit("/g/.git", revision)
    assert recorder.calls == []


def test_unresolvable_revision(tmp_path: Path) -> None:
    runner = make_runner(
        tmp_path,
        Recorder(FakeProcess([], [b"fatal: Needed a single revision" + LF], returncode=128)),
    )
    with pytest.raises(GitError, match="does not name a commit"):
        runner.resolve_commit("/g/.git", "nope")


def test_shallow_answers(tmp_path: Path) -> None:
    runner = make_runner(
        tmp_path, Recorder(FakeProcess([b"true" + LF]), FakeProcess([b"false" + LF]))
    )
    assert runner.is_shallow("/g/.git") is True
    assert runner.is_shallow("/g/.git") is False


def test_listing_files(tmp_path: Path) -> None:
    recorder = Recorder(FakeProcess([b"a.txt\x00d/b.txt\x00"]))
    runner = make_runner(tmp_path, recorder)
    assert runner.list_files("/w", allow_other_owner=False) == [b"a.txt", b"d/b.txt"]
    argv, environment, cwd = recorder.calls[0]
    assert cwd == "/w"
    assert "GIT_CEILING_DIRECTORIES" not in environment  # PATH may be inside a work tree
    assert argv[-5:] == ["ls-files", "-z", "--cached", "--others", "--exclude-standard"]
    assert not any(argument.startswith("--git-dir") for argument in argv)


def test_listing_files_outside_a_work_tree_is_a_usage_error(tmp_path: Path) -> None:
    stderr = b"fatal: not a git repository (or any of the parent directories): .git" + LF
    runner = make_runner(tmp_path, Recorder(FakeProcess([], [stderr], returncode=128)))
    with pytest.raises(UsageError, match="not inside a git work tree"):
        runner.list_files("/w", allow_other_owner=False)


# -- bounds and process control ------------------------------------------------------------------


def test_a_hung_short_call_is_killed_by_pid_and_is_a_time_limit(tmp_path: Path) -> None:
    process = FakeProcess(hang=True, pid=777)
    recorder = Recorder(process)
    limits = Limits(git_call_timeout_seconds=30)
    runner = make_runner(tmp_path, recorder, limits=limits, clock=TickClock(step=5.0))
    with pytest.raises(GitLimitError) as caught:
        runner.version()
    assert caught.value.time_budget is True
    assert isinstance(caught.value, IncompleteRunError)
    assert process.killed
    assert recorder.tree_kills == [777]


def test_a_call_that_never_ends_after_its_output_is_stopped(tmp_path: Path) -> None:
    class Stubborn(FakeProcess):
        def wait(self, timeout: float | None = None) -> int:
            if not self.killed:
                raise subprocess.TimeoutExpired("git", timeout or 0)
            return -9

        def poll(self) -> int | None:
            return None if not self.killed else -9

    process = Stubborn([b"git version 2.54.0" + LF])
    recorder = Recorder(process)
    runner = make_runner(tmp_path, recorder)
    with pytest.raises(GitLimitError, match="did not end"):
        runner.version()
    assert process.killed
    assert recorder.tree_kills == [process.pid]


def test_stdout_over_the_cap_is_killed_and_is_not_a_time_limit(tmp_path: Path) -> None:
    process = FakeProcess([b"x" * 1000, b"y" * 1000], hang=True)
    recorder = Recorder(process)
    runner = make_runner(tmp_path, recorder, limits=Limits(max_git_output_bytes=1500))
    with pytest.raises(GitLimitError) as caught:
        runner.version()
    assert caught.value.time_budget is False
    assert "1500" in str(caught.value)
    assert process.killed


def test_stderr_over_the_cap_is_killed(tmp_path: Path) -> None:
    process = FakeProcess([], [b"e" * 3000], hang=True)
    recorder = Recorder(process)
    runner = make_runner(tmp_path, recorder, limits=Limits(max_git_stderr_bytes=1024))
    with pytest.raises(GitLimitError, match="error output") as caught:
        runner.version()
    assert caught.value.time_budget is False
    assert process.killed


def test_a_nonzero_exit_reports_only_the_first_line_of_stderr(tmp_path: Path) -> None:
    stderr = b"fatal: first line" + LF + b"second line with detail" + LF
    runner = make_runner(tmp_path, Recorder(FakeProcess([], [stderr], returncode=128)))
    with pytest.raises(GitError) as caught:
        runner.version()
    assert "first line" in str(caught.value)
    assert "second line" not in str(caught.value)


def test_an_exhausted_run_budget_stops_before_a_process_starts(tmp_path: Path) -> None:
    recorder = Recorder()
    runner = make_runner(tmp_path, recorder, deadline=999.0)
    with pytest.raises(GitLimitError) as caught:
        runner.version()
    assert caught.value.time_budget is True
    assert recorder.calls == []


def test_the_short_call_timeout_is_capped_by_the_remaining_run_budget(tmp_path: Path) -> None:
    clock = TickClock(step=4.0)
    runner = make_runner(
        tmp_path,
        Recorder(FakeProcess(hang=True)),
        limits=Limits(git_call_timeout_seconds=100),
        clock=clock,
        deadline=1010.0,
    )
    with pytest.raises(GitLimitError):
        runner.version()
    assert clock.now - 1000.0 < 40.0  # the 100 s call limit was not what ended it


def test_history_stream_yields_chunks_then_checks_the_exit_status(tmp_path: Path) -> None:
    good = Recorder(FakeProcess([b"abc", b"def"]))
    runner = make_runner(tmp_path, good)
    chunks = list(runner.stream_history("/g/.git", [oid(1), f"^{oid(2)}"], all_refs=False))
    assert b"".join(chunks) == b"abcdef"
    argv = good.calls[0][0]
    assert "--all" not in argv
    assert argv[argv.index("--end-of-options") + 1 :] == [oid(1), f"^{oid(2)}", "--"]
    assert good.calls[0][2] == "/g/.git"

    bad = Recorder(FakeProcess([b"partial"], [b"fatal: bad object" + LF], returncode=128))
    runner = make_runner(tmp_path, bad)
    seen: list[bytes] = []

    def drain() -> None:
        for chunk in runner.stream_history("/g/.git", [], all_refs=True):
            seen.append(chunk)

    with pytest.raises(GitError, match="bad object"):
        drain()
    assert seen == [b"partial"]


def test_history_stream_refuses_a_revision_that_is_not_an_object_id(tmp_path: Path) -> None:
    recorder = Recorder()
    runner = make_runner(tmp_path, recorder)
    with pytest.raises(GitError):
        list(runner.stream_history("/g/.git", ["main"], all_refs=False))
    assert recorder.calls == []


def test_leaving_the_history_stream_early_ends_the_process(tmp_path: Path) -> None:
    process = FakeProcess([b"a", b"b", b"c"], hang=True, pid=99)
    recorder = Recorder(process)
    runner = make_runner(tmp_path, recorder)
    stream = runner.stream_history("/g/.git", [], all_refs=True)
    assert next(stream) == b"a"
    stream.close()
    assert process.killed
    assert recorder.tree_kills == [99]


def test_history_stream_deadline(tmp_path: Path) -> None:
    process = FakeProcess([b"a"], hang=True)
    recorder = Recorder(process)
    runner = make_runner(tmp_path, recorder, clock=TickClock(step=100.0), deadline=1250.0)
    with pytest.raises(GitLimitError) as caught:
        for _ in runner.stream_history("/g/.git", [], all_refs=True):
            pass
    assert caught.value.time_budget is True
    assert process.killed


# -- object reads --------------------------------------------------------------------------------


def cat_file_check(known: Mapping[str, tuple[str, int]]) -> Callable[[FakeProcess, bytes], None]:
    """Answers `--batch-check` requests from a table (`missing` when not in it)."""

    def respond(process: FakeProcess, data: bytes) -> None:
        for line in data.decode("ascii").splitlines():
            if line in known:
                kind, size = known[line]
                process.stdout.feed(f"{line} {kind} {size}".encode() + LF)
            else:
                process.stdout.feed(f"{line} missing".encode() + LF)

    return respond


def cat_file_batch(blobs: Mapping[str, bytes]) -> Callable[[FakeProcess, bytes], None]:
    def respond(process: FakeProcess, data: bytes) -> None:
        name = data.decode("ascii").strip()
        content = blobs[name]
        process.stdout.feed(f"{name} blob {len(content)}".encode() + LF + content + LF)

    return respond


def test_sizes_come_back_in_order_with_missing_objects_marked(tmp_path: Path) -> None:
    known = {oid(1): ("blob", 10), oid(3): ("blob", 5)}
    process = FakeProcess(hang=True, on_stdin=cat_file_check(known))
    recorder = Recorder(process)
    runner = make_runner(tmp_path, recorder)
    with runner.open_objects("/g/.git") as objects:
        answers = objects.sizes([oid(1), oid(2), oid(3)])
    assert [(a.oid, a.kind, a.size) for a in answers] == [
        (oid(1), "blob", 10),
        (oid(2), "missing", None),
        (oid(3), "blob", 5),
    ]
    assert recorder.calls[0][0][-2:] == ["cat-file", "--batch-check"]
    assert bytes(process.stdin.data) == b"".join(
        f"{n}".encode() + LF for n in (oid(1), oid(2), oid(3))
    )
    assert process.killed  # closing the reader ends the long-running process


def test_sizes_are_requested_in_bounded_batches(tmp_path: Path) -> None:
    ids = [oid(n) for n in range(OBJECT_CHECK_BATCH * 2 + 5)]
    known = dict.fromkeys(ids, ("blob", 1))
    writes: list[int] = []

    def respond(process: FakeProcess, data: bytes) -> None:
        writes.append(data.count(LF))
        cat_file_check(known)(process, data)

    process = FakeProcess(hang=True, on_stdin=respond)
    runner = make_runner(tmp_path, Recorder(process))
    with runner.open_objects("/g/.git") as objects:
        assert len(objects.sizes(ids)) == len(ids)
    assert writes == [OBJECT_CHECK_BATCH, OBJECT_CHECK_BATCH, 5]


def test_read_blob_returns_exactly_the_content(tmp_path: Path) -> None:
    content = b"line one" + LF + b"line two\x00binary" + LF
    process = FakeProcess(hang=True, on_stdin=cat_file_batch({oid(1): content}))
    recorder = Recorder(process)
    runner = make_runner(tmp_path, recorder)
    with runner.open_objects("/g/.git") as objects:
        assert objects.read_blob(oid(1), len(content)) == content
    assert recorder.calls[0][0][-2:] == ["cat-file", "--batch"]


def test_a_blob_whose_size_changed_is_an_error(tmp_path: Path) -> None:
    process = FakeProcess(hang=True, on_stdin=cat_file_batch({oid(1): b"abc"}))
    runner = make_runner(tmp_path, Recorder(process))
    with runner.open_objects("/g/.git") as objects, pytest.raises(GitError, match="different"):
        objects.read_blob(oid(1), 10)


def test_a_blob_answered_as_another_type_is_an_error(tmp_path: Path) -> None:
    def respond(process: FakeProcess, data: bytes) -> None:
        process.stdout.feed(f"{oid(1)} tree 3".encode() + LF + b"abc" + LF)

    runner = make_runner(tmp_path, Recorder(FakeProcess(hang=True, on_stdin=respond)))
    with runner.open_objects("/g/.git") as objects, pytest.raises(GitError, match="different"):
        objects.read_blob(oid(1), 3)


def test_a_blob_not_ended_by_a_newline_is_an_error(tmp_path: Path) -> None:
    def respond(process: FakeProcess, data: bytes) -> None:
        process.stdout.feed(f"{oid(1)} blob 3".encode() + LF + b"abcX")

    runner = make_runner(tmp_path, Recorder(FakeProcess(hang=True, on_stdin=respond)))
    with runner.open_objects("/g/.git") as objects, pytest.raises(GitError, match="newline"):
        objects.read_blob(oid(1), 3)


def test_git_ending_in_the_middle_of_a_blob_is_an_error(tmp_path: Path) -> None:
    def respond(process: FakeProcess, data: bytes) -> None:
        process.stdout.feed(f"{oid(1)} blob 100".encode() + LF + b"abc")
        process.stdout.end()
        process.stderr.end()

    runner = make_runner(
        tmp_path,
        Recorder(FakeProcess([], [b"fatal: boom" + LF], hang=True, on_stdin=respond)),
    )
    with runner.open_objects("/g/.git") as objects, pytest.raises(GitError, match="ended"):
        objects.read_blob(oid(1), 100)


def test_an_answer_line_without_a_newline_is_bounded(tmp_path: Path) -> None:
    def respond(process: FakeProcess, data: bytes) -> None:
        process.stdout.feed(b"x" * 1000)

    runner = make_runner(tmp_path, Recorder(FakeProcess(hang=True, on_stdin=respond)))
    with runner.open_objects("/g/.git") as objects, pytest.raises(GitError, match="line longer"):
        objects.sizes([oid(1)])


def test_object_ids_are_validated_before_they_are_written(tmp_path: Path) -> None:
    process = FakeProcess(hang=True)
    runner = make_runner(tmp_path, Recorder(process))
    with runner.open_objects("/g/.git") as objects:
        with pytest.raises(GitError):
            objects.sizes(["main"])
        with pytest.raises(GitError):
            objects.read_blob("HEAD:path", 1)
    assert bytes(process.stdin.data) == b""


def test_an_object_reader_that_was_never_used_starts_nothing(tmp_path: Path) -> None:
    recorder = Recorder()
    runner = make_runner(tmp_path, recorder)
    with runner.open_objects("/g/.git"):
        pass
    assert recorder.calls == []


class _BoundedPipe(Pipe):
    """A pipe with a small capacity, like the 4 KiB pipes of Windows: a writer blocks when
    nobody reads. A block that lasts five seconds is reported as the deadlock it is."""

    def __init__(self, capacity: int) -> None:
        super().__init__(ended=False)
        self._queue = queue.Queue(maxsize=capacity)

    def feed(self, data: bytes) -> None:
        try:
            self._queue.put(data, timeout=5.0)
        except queue.Full:
            raise AssertionError("deadlock: git blocked writing answers nobody reads") from None


def test_requests_and_answers_cannot_deadlock_on_small_pipes(tmp_path: Path) -> None:
    """Regression: writing a batch of requests on the thread that must read the answers hangs
    both sides as soon as the output pipe is full (found by scanning this repository)."""
    ids = [oid(n) for n in range(OBJECT_CHECK_BATCH)]
    process = FakeProcess(hang=True)
    process.stdout = _BoundedPipe(capacity=4)
    handler = cat_file_check(dict.fromkeys(ids, ("blob", 1)))
    process.stdin = Sink(lambda data: handler(process, data))
    runner = make_runner(tmp_path, Recorder(process))
    with runner.open_objects("/g/.git") as objects:
        answers = objects.sizes(ids)
    assert [a.oid for a in answers] == ids


def test_a_failed_write_is_an_error_not_a_hang(tmp_path: Path) -> None:
    class Broken(Sink):
        def write(self, data: bytes) -> int:
            raise BrokenPipeError

    process = FakeProcess([], [b"fatal: gone" + LF], hang=True)
    process.stdin = Broken()
    runner = make_runner(tmp_path, Recorder(process))
    with (
        runner.open_objects("/g/.git") as objects,
        pytest.raises(GitError, match="stopped reading"),
    ):
        objects.sizes([oid(1)])
    assert process.killed


# -- windows process trees ---------------------------------------------------------------------


def test_taskkill_command_names_a_pid_and_never_an_image() -> None:
    argv = taskkill_argv(r"C:\Windows", 1234)
    assert argv is not None
    assert argv[0].lower().endswith("taskkill.exe")
    assert argv[1:] == ["/PID", "1234", "/T", "/F"]
    assert "/IM" not in argv
    assert taskkill_argv("", 1) is None


@pytest.mark.posix_only
def test_kill_process_tree_does_nothing_off_windows(monkeypatch: pytest.MonkeyPatch) -> None:
    def refuse(*args: object, **kwargs: object) -> None:
        raise AssertionError("no helper process may be started off Windows")

    monkeypatch.setattr(subprocess, "run", refuse)
    runner_module.kill_process_tree(1234)


# -- a real process --------------------------------------------------------------------------------


def test_spawn_process_runs_an_argument_list_without_a_shell(tmp_path: Path) -> None:
    marker = "x;echo injected"
    process = spawn_process(
        [sys.executable, "-c", "import sys; print(sys.argv[1])", marker],
        {"PATH": os.path.dirname(sys.executable), "SYSTEMROOT": os.environ.get("SYSTEMROOT", "")},
        str(tmp_path),
    )
    assert process.stdout is not None
    assert process.stdin is not None
    process.stdin.close()
    output = process.stdout.read()
    process.wait(timeout=30)
    assert output.decode().strip() == marker  # one argument, not interpreted by a shell
    assert process.stderr is not None
    process.stderr.close()
    process.stdout.close()


def test_pump_threads_are_daemons() -> None:
    process = FakeProcess([b"x"])
    pump = runner_module._Pump(cast(IO[bytes], process.stdout), "t")
    assert pump._thread.daemon
    assert pump.get(5.0) == b"x"
    assert pump.get(5.0) is None
    pump.stop()
