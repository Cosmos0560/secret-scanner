"""Edge cases of the runner's process plumbing: pipes that fail, writers that block, cleanup that
cannot succeed. Each is a place where a real git could misbehave."""

from __future__ import annotations

import os
import threading
from pathlib import Path
from typing import IO, cast

import pytest

from secret_scanner.app.common import open_runner
from secret_scanner.core.errors import GitError
from secret_scanner.fs import walk
from secret_scanner.gitio import runner as runner_module
from secret_scanner.services import git_scanner
from secret_scanner.services.fs_scanner import ScanSettings
from secret_scanner.services.git_scanner import HistorySpec, scan_history
from secret_scanner.services.loader import load_builtin_rules
from tests.helpers import FakeClock
from tests.test_git_fs import standard_repository
from tests.test_git_runner import (
    LF,
    FakeProcess,
    Pipe,
    Recorder,
    Sink,
    make_runner,
)
from tests.test_git_scanner import Repo, change, commit, run, text


class NoRead1:
    """A pipe without `read1`, like a plain file object."""

    def __init__(self, data: bytes) -> None:
        self._data = data

    def read(self, size: int = -1) -> bytes:
        taken, self._data = self._data[:size], self._data[size:]
        return taken


class Exploding:
    def read1(self, size: int = -1) -> bytes:
        raise ValueError("closed under us")

    def close(self) -> None:
        raise OSError("cannot close")


def pump_of(pipe: object) -> runner_module._Pump:
    return runner_module._Pump(cast(IO[bytes], pipe), "t")


def test_a_pipe_without_read1_is_read_with_read() -> None:
    pump = pump_of(NoRead1(b"abc"))
    assert pump.get(5.0) == b"abc"
    assert pump.get(5.0) is None


def test_a_pipe_that_fails_ends_the_stream() -> None:
    pump = pump_of(Exploding())
    assert pump.get(5.0) is None


def test_a_missing_pipe_is_an_empty_stream() -> None:
    pump = runner_module._Pump(None, "t")
    assert pump.get(5.0) is None
    collector = runner_module._StderrCollector(None, 100)
    assert collector.text() == b""


def test_a_failing_stderr_pipe_ends_collection() -> None:
    collector = runner_module._StderrCollector(cast(IO[bytes], Exploding()), 100)
    assert collector.text() == b""
    assert not collector.overflow.is_set()


def test_a_slow_consumer_blocks_the_pump_instead_of_growing_memory() -> None:
    chunks = [bytes([n]) for n in range(runner_module._QUEUE_DEPTH * 3)]
    pump = pump_of(Pipe(chunks))
    for _ in range(200):  # wait until the pump has filled its queue and is waiting
        if pump._queue.full():
            break
        threading.Event().wait(0.01)
    assert pump._queue.full()
    received = []
    while True:
        item = pump.get(5.0)
        if item is None:
            break
        received.append(item)
    assert received == chunks


def test_a_stopped_pump_gives_up_offering(monkeypatch: pytest.MonkeyPatch) -> None:
    pump = pump_of(Pipe([b"x"] * (runner_module._QUEUE_DEPTH + 5), ended=False))
    for _ in range(200):
        if pump._queue.full():
            break
        threading.Event().wait(0.01)
    pump.stop()
    pump._thread.join(timeout=5.0)
    assert not pump._thread.is_alive()


def make_call(tmp_path: Path, process: FakeProcess) -> runner_module._Call:
    runner = make_runner(tmp_path, Recorder(process))
    return runner_module._Call(
        runner,
        ["git"],
        cwd=None,
        environment={},
        timeout=60.0,
    )


def test_sending_without_an_input_stream(tmp_path: Path) -> None:
    process = FakeProcess([], hang=True)
    process.stdin = None  # type: ignore[assignment]
    call = make_call(tmp_path, process)
    with pytest.raises(GitError, match="no input stream"):
        call.send(b"x")
    call.close()


def test_the_next_send_waits_for_a_blocked_writer(tmp_path: Path) -> None:
    release = threading.Event()
    written: list[bytes] = []

    class Blocking(Sink):
        def write(self, data: bytes) -> int:
            release.wait(5.0)
            written.append(data)
            return len(data)

    process = FakeProcess([], hang=True)
    process.stdin = Blocking()
    call = make_call(tmp_path, process)
    call.send(b"one")
    timer = threading.Timer(0.2, release.set)
    timer.start()
    call.send(b"two")  # waits for the first write to end, polling the limits
    call.close_input()
    timer.join()
    assert written == [b"one", b"two"]
    call.close()


def test_a_failed_write_surfaces_when_the_input_is_closed(tmp_path: Path) -> None:
    class Broken(Sink):
        def write(self, data: bytes) -> int:
            raise BrokenPipeError

    process = FakeProcess([], hang=True)
    process.stdin = Broken()
    call = make_call(tmp_path, process)
    call.send(b"x")
    call._writer.join(5.0)  # type: ignore[union-attr]
    with pytest.raises(GitError, match="stopped reading"):
        call.close_input()
    assert process.killed


def test_closing_an_input_that_cannot_be_closed_is_not_an_error(tmp_path: Path) -> None:
    class Stubborn(Sink):
        def close(self) -> None:
            raise OSError("broken pipe")

    process = FakeProcess([b"x"], hang=False)
    process.stdin = Stubborn()
    call = make_call(tmp_path, process)
    call.close_input()
    call.close()  # closes the pipes, one of which raises
    assert call.read_chunk() == b"x"


def test_read_chunk_returns_what_a_line_read_left_behind(tmp_path: Path) -> None:
    call = make_call(tmp_path, FakeProcess([b"first" + LF + b"second" + LF]))
    assert call.read_line(100) == b"first" + LF
    assert call.read_chunk() == b"second" + LF
    assert call.read_chunk() == b""


def test_a_line_that_never_ends_before_the_stream_ends(tmp_path: Path) -> None:
    call = make_call(tmp_path, FakeProcess([b"no newline"], [b"fatal: cut" + LF]))
    with pytest.raises(GitError, match="ended unexpectedly"):
        call.read_line(100)


def test_terminating_a_finished_process_is_harmless(tmp_path: Path) -> None:
    process = FakeProcess([], hang=False, returncode=0)
    call = make_call(tmp_path, process)
    call.terminate()
    assert not process.killed  # it had ended already
    call.close()


def test_a_process_that_cannot_be_killed_is_still_released(tmp_path: Path) -> None:
    class Immortal(FakeProcess):
        def kill(self) -> None:
            raise OSError("access denied")

    process = Immortal([], hang=True)
    call = make_call(tmp_path, process)
    call.terminate()  # kill fails, wait times out: neither is raised
    process.killed = True
    process.stdout.end()
    process.stderr.end()


def test_shallow_and_listing_failures_name_git_not_a_crash(tmp_path: Path) -> None:
    failing = FakeProcess([], [b"fatal: broken" + LF], returncode=128)
    runner = make_runner(tmp_path, Recorder(failing))
    with pytest.raises(GitError, match="cannot tell whether the repository is shallow"):
        runner.is_shallow("/g/.git")
    failing = FakeProcess([], [b"fatal: broken" + LF], returncode=128)
    runner = make_runner(tmp_path, Recorder(failing))
    with pytest.raises(GitError, match="could not list the files"):
        runner.list_files("/w", allow_other_owner=False)


def test_a_missing_path_variable_means_git_is_not_found(tmp_path: Path) -> None:
    from secret_scanner.core.limits import DEFAULT_LIMITS

    with pytest.raises(GitError, match="not found"):
        open_runner(
            git=None, root=str(tmp_path), limits=DEFAULT_LIMITS, clock=FakeClock(), environment={}
        )
    found = os.path.dirname(os.path.abspath(__file__))  # a directory without git in it
    with pytest.raises(GitError, match="not found"):
        open_runner(
            git=None,
            root=str(tmp_path),
            limits=DEFAULT_LIMITS,
            clock=FakeClock(),
            environment={"Path": found},  # the name is matched case-insensitively
        )


# -- repository inspection under failures ---------------------------------------------------------


def test_an_alternates_file_that_cannot_be_opened_counts_as_present(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    git_dir = standard_repository(tmp_path / "r")
    (git_dir / "objects" / "info" / "alternates").write_bytes(b"/x" + LF)
    original = os.open

    def refuse(path: object, *args: object, **kwargs: object) -> int:
        if str(path).endswith("alternates"):
            raise PermissionError
        return original(path, *args, **kwargs)  # type: ignore[arg-type]

    monkeypatch.setattr("secret_scanner.fs.walk.os.open", refuse)
    assert walk.inspect_repository(str(tmp_path / "r")).alternates is True


def test_an_alternates_file_that_cannot_be_read_counts_as_present(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    git_dir = standard_repository(tmp_path / "r")
    (git_dir / "info" / "grafts").write_bytes(b"x" + LF)

    def refuse(descriptor: int, count: int) -> bytes:
        raise OSError("input/output error")

    monkeypatch.setattr("secret_scanner.fs.walk.os.read", refuse)
    assert walk.inspect_repository(str(tmp_path / "r")).grafts is True


# -- the scanner's less common paths ------------------------------------------------------------


def test_the_same_blob_with_the_other_entropy_setting_is_sized_again(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    from secret_scanner.core.fakes import fake_entropy_token

    monkeypatch.setattr(git_scanner, "FLUSH_ENTRIES", 1)
    body = text(f"api_token = {fake_entropy_token('edge')}" + chr(10))
    # one entry per flush: the second path needs the entropy detector the first did not use
    stream = commit(1) + change("poetry.lock", 11) + change("app.cfg", 11)
    result = run(tmp_path, Repo(stream, {11: body}))
    assert [f.location.path for f in result.findings] == ["app.cfg"]
    assert result.stats.files_seen == 1
    assert result.stats.blobs_scanned == 2


def test_a_changed_file_that_git_calls_a_tree_fails_closed(tmp_path: Path) -> None:
    def respond(process: FakeProcess, data: bytes) -> None:
        for name in data.decode("ascii").split():
            process.stdout.feed(f"{name} tree 3".encode() + LF)

    processes = [
        FakeProcess([commit(1) + change("odd", 11)]),
        FakeProcess(hang=True, on_stdin=respond),
    ]
    runner = make_runner(tmp_path, Recorder(*processes))
    settings = ScanSettings(rules=load_builtin_rules().rules)
    with pytest.raises(GitError, match="not a blob"):
        scan_history(runner, "/g/.git", HistorySpec(), settings, FakeClock())
