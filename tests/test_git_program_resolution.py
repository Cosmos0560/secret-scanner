"""Which git program the tool runs (PLAN.md D2 "Binary", threat model "A planted git program").

Found by CI run 5: on Windows `shutil.which` (and CreateProcess) search the current directory
first, so a `git.exe` planted there is what a naive search returns. The product's own search must
never do that. Every test here plants programs where a naive search would find them, runs
`open_runner` and proves two things: the chosen binary is the real git, and no planted program was
ever started. "Started" is observed at the only place a process can be started, the runner's spawn
function, and (for programs that can run) through a marker file the planted program writes beside
itself.

The planted programs are scripts on POSIX. On Windows a script named `git.exe` is not an
executable at all (CreateProcess fails with WinError 216), so the fast tests there prove the
refusal through the spawn record, and the slow test compiles a real, harmless executable with the
C# compiler that ships with Windows, proves with a control run that it does write its marker, and
plants copies of it.
"""

from __future__ import annotations

import os
import subprocess
import sys
import tempfile
from collections.abc import Mapping, Sequence
from pathlib import Path

import pytest

from secret_scanner.app.common import open_runner
from secret_scanner.core.errors import GitError, ScanIOError
from secret_scanner.core.limits import DEFAULT_LIMITS
from secret_scanner.gitio.runner import GitRunner, ProcessLike, spawn_process
from tests.gitrepo import git_binary
from tests.helpers import FakeClock
from tests.hostile import make_executable

pytestmark = pytest.mark.requires_git

WINDOWS = sys.platform == "win32"
PROGRAM = "git.exe" if WINDOWS else "git"
MARKER = "ran"
SCRIPT = (
    "#!/bin/sh" + chr(10) + 'printf x > "$(dirname "$0")/' + MARKER + '"' + chr(10)
    # a plausible answer, so that a program that did run would be accepted as git
    + "echo 'git version 2.99.0'" + chr(10)
)  # fmt: skip
CSHARP = """\
using System;
using System.IO;
using System.Reflection;
class Planted {
    static void Main() {
        string here = Path.GetDirectoryName(Assembly.GetExecutingAssembly().Location);
        File.WriteAllText(Path.Combine(here, "ran"), "x");
        Console.WriteLine("git version 2.99.0");
    }
}
"""


class Recorder:
    """A spawn function that records which program every process was started from."""

    def __init__(self) -> None:
        self.programs: list[str] = []

    def __call__(
        self, argv: Sequence[str], environment: Mapping[str, str], cwd: str | None
    ) -> ProcessLike:
        self.programs.append(argv[0])
        return spawn_process(argv, environment, cwd)


def same(first: str, second: str) -> bool:
    return os.path.normcase(os.path.realpath(first)) == os.path.normcase(os.path.realpath(second))


def real_directory() -> str:
    return str(Path(git_binary()).parent)


def plant_script(path: Path) -> None:
    """The planted program on POSIX; on Windows only a decoy that is not an executable."""
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(SCRIPT.encode())
    make_executable(path)


class World:
    """Where the planted programs go. `temp` is made the system temporary directory, away from
    pytest's own directory, so that a refusal can only come from the rule a test is about."""

    def __init__(self, base: Path) -> None:
        self.repo = base / "repo"
        self.cwd = base / "cwd"
        self.temp = base / "system-temp"
        self.elsewhere = base / "elsewhere"
        for directory in (self.repo, self.cwd, self.temp, self.elsewhere):
            directory.mkdir(parents=True)

    def open(self, search: Sequence[str | Path], recorder: Recorder) -> GitRunner:
        return open_runner(
            git=None,
            root=str(self.repo),
            limits=DEFAULT_LIMITS,
            clock=FakeClock(),
            spawn=recorder,
            environment={
                "PATH": os.pathsep.join(str(entry) for entry in search),
                "SYSTEMROOT": os.environ.get("SYSTEMROOT", ""),
            },
        )

    def markers(self) -> list[Path]:
        base = self.repo.parent
        return sorted(path for path in base.rglob(MARKER) if path.is_file())


@pytest.fixture
def world(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> World:
    git_binary()  # resolved before any test changes directory or PATH
    # CI runners do not set this; some developer machines do, which hid CI run 5's failure
    monkeypatch.delenv("NoDefaultCurrentDirectoryInExePath", raising=False)
    built = World(tmp_path)
    monkeypatch.setattr(tempfile, "tempdir", str(built.temp))
    monkeypatch.chdir(built.cwd)
    return built


def assert_real_git_and_nothing_planted_ran(
    world: World, runner: GitRunner, recorder: Recorder
) -> None:
    assert same(runner.binary, git_binary())
    assert os.path.isabs(runner.binary)
    assert recorder.programs, "the version check must have started git"
    assert all(same(program, git_binary()) for program in recorder.programs)
    assert world.markers() == []


# -- relative and empty PATH entries ------------------------------------------------------------


@pytest.mark.parametrize("entry", ["", ".", "..", "bin", "./bin", "bin/..", "./", "bin/./"])
def test_an_empty_or_relative_path_entry_is_never_searched(world: World, entry: str) -> None:
    plant_script(world.cwd / PROGRAM)
    plant_script(world.cwd / "bin" / PROGRAM)
    plant_script(world.cwd.parent / PROGRAM)  # what ".." reaches
    recorder = Recorder()
    runner = world.open([entry, real_directory()], recorder)
    assert_real_git_and_nothing_planted_ran(world, runner, recorder)


@pytest.mark.windows_only
@pytest.mark.parametrize("entry", ["\\bin", "\\", "C:bin", "C:", "bin\\", ".\\bin"])
def test_a_windows_entry_that_depends_on_the_current_drive_or_directory_is_never_searched(
    world: World, entry: str
) -> None:
    plant_script(world.cwd / PROGRAM)
    plant_script(world.cwd / "bin" / PROGRAM)
    recorder = Recorder()
    runner = world.open([entry, real_directory()], recorder)
    assert_real_git_and_nothing_planted_ran(world, runner, recorder)


def test_the_path_with_only_relative_entries_means_git_is_not_found(world: World) -> None:
    plant_script(world.cwd / PROGRAM)
    recorder = Recorder()
    with pytest.raises(GitError, match="not found"):
        world.open(["", ".", "bin"], recorder)
    assert recorder.programs == []
    assert world.markers() == []


# -- absolute entries that are still not to be trusted ------------------------------------------


def test_the_current_directory_given_as_an_absolute_entry_is_refused(world: World) -> None:
    """The exact CI #5 scenario: the planted directory is on PATH by absolute name."""
    plant_script(world.cwd / PROGRAM)
    recorder = Recorder()
    runner = world.open([world.cwd, real_directory()], recorder)
    assert_real_git_and_nothing_planted_ran(world, runner, recorder)


def test_a_directory_in_the_system_temporary_tree_is_refused(world: World) -> None:
    plant_script(world.temp / PROGRAM)
    plant_script(world.temp / "deep" / "er" / PROGRAM)
    recorder = Recorder()
    runner = world.open([world.temp, world.temp / "deep" / "er", real_directory()], recorder)
    assert_real_git_and_nothing_planted_ran(world, runner, recorder)


def test_a_directory_in_the_scanned_tree_is_refused(world: World) -> None:
    plant_script(world.repo / PROGRAM)
    plant_script(world.repo / "bin" / PROGRAM)
    recorder = Recorder()
    runner = world.open([world.repo / "bin", world.repo, real_directory()], recorder)
    assert_real_git_and_nothing_planted_ran(world, runner, recorder)


@pytest.mark.parametrize("name", ["git.cmd", "git.bat", "git.com", "git.ps1", "git.vbs", "git.js"])
def test_a_script_type_is_never_taken_for_git(world: World, name: str) -> None:
    """On Windows these run through cmd.exe or a script host; only git.exe is accepted."""
    plant_script(world.elsewhere / name)
    recorder = Recorder()
    runner = world.open([world.elsewhere, real_directory()], recorder)
    assert_real_git_and_nothing_planted_ran(world, runner, recorder)


@pytest.mark.windows_only
def test_a_windows_program_without_the_exe_extension_is_never_taken_for_git(
    world: World,
) -> None:
    plant_script(world.elsewhere / "git")
    recorder = Recorder()
    runner = world.open([world.elsewhere, real_directory()], recorder)
    assert_real_git_and_nothing_planted_ran(world, runner, recorder)


def test_the_found_program_is_an_absolute_normalised_path(world: World) -> None:
    messy = os.path.join(real_directory(), "..", os.path.basename(real_directory()))
    recorder = Recorder()
    runner = world.open([messy], recorder)
    assert runner.binary == os.path.normpath(runner.binary)
    assert os.path.isabs(runner.binary)
    assert ".." not in runner.binary.split(os.sep)
    assert recorder.programs == [runner.binary]


def test_the_test_harness_does_not_find_a_program_in_the_current_directory(
    world: World,
) -> None:
    plant_script(world.cwd / PROGRAM)
    resolve = git_binary.__wrapped__  # functools.cache keeps the undecorated function
    assert same(resolve(), git_binary())
    assert not same(os.path.dirname(resolve()), str(world.cwd))


# -- an explicit --git PATH --------------------------------------------------------------------


def open_explicit(world: World, git: str) -> GitRunner:
    return open_runner(
        git=git, root=str(world.repo), limits=DEFAULT_LIMITS, clock=FakeClock(), spawn=Recorder()
    )


@pytest.mark.parametrize("given", ["git", "./git", "bin/git", "..", "", ".", "git.exe"])
def test_an_explicit_relative_program_is_refused_and_never_started(
    world: World, given: str
) -> None:
    plant_script(world.cwd / PROGRAM)
    plant_script(world.cwd / "bin" / PROGRAM)
    with pytest.raises(ScanIOError, match="absolute"):
        open_explicit(world, given)
    assert world.markers() == []


@pytest.mark.windows_only
@pytest.mark.parametrize("given", ["\\git.exe", "C:git.exe"])
def test_an_explicit_program_that_depends_on_the_current_drive_is_refused(
    world: World, given: str
) -> None:
    with pytest.raises(ScanIOError, match="absolute"):
        open_explicit(world, given)


def test_an_explicit_program_must_exist_and_be_a_regular_file(world: World) -> None:
    with pytest.raises(ScanIOError, match="cannot be examined"):
        open_explicit(world, str(world.elsewhere / PROGRAM))
    directory = world.elsewhere / PROGRAM
    directory.mkdir()
    with pytest.raises(ScanIOError, match="not a regular file"):
        open_explicit(world, str(directory))


def test_an_explicit_program_inside_the_scanned_tree_is_refused(world: World) -> None:
    plant_script(world.repo / "tools" / PROGRAM)
    with pytest.raises(ScanIOError, match="inside the scanned tree"):
        open_explicit(world, str(world.repo / "tools" / PROGRAM))
    assert world.markers() == []


@pytest.mark.windows_only
@pytest.mark.parametrize(
    "name", ["git.cmd", "git.bat", "git", "git.exe.bat", "xgit.exe", "git.com"]
)
def test_an_explicit_windows_program_must_be_called_git_exe(world: World, name: str) -> None:
    plant_script(world.elsewhere / name)
    with pytest.raises(ScanIOError, match=r"git\.exe"):
        open_explicit(world, str(world.elsewhere / name))
    assert world.markers() == []


@pytest.mark.posix_only
def test_an_explicit_program_must_be_executable_on_posix(world: World) -> None:
    plain = world.elsewhere / "git"
    plain.write_bytes(SCRIPT.encode())
    with pytest.raises(ScanIOError, match="not executable"):
        open_explicit(world, str(plain))
    assert world.markers() == []


def test_an_explicit_real_git_is_used_as_a_normalised_absolute_path(world: World) -> None:
    messy = os.path.join(real_directory(), "..", os.path.basename(real_directory()), PROGRAM)
    runner = open_explicit(world, messy)
    assert runner.binary == os.path.normpath(messy)
    assert same(runner.binary, git_binary())


# -- a planted program that can really run -----------------------------------------------------


@pytest.fixture(scope="session")
def valid_program(tmp_path_factory: pytest.TempPathFactory) -> bytes:
    """The bytes of a harmless executable that writes the marker beside itself and answers like
    git. POSIX: a script. Windows: compiled here with the .NET Framework compiler of Windows."""
    if not WINDOWS:
        return SCRIPT.encode()
    compiler = Path(os.environ.get("SYSTEMROOT", "")) / "Microsoft.NET" / "Framework64"
    compiler = compiler / "v4.0.30319" / "csc.exe"
    if not compiler.is_file():
        pytest.fail(f"windows_only: the C# compiler {compiler.name} is missing from Windows")
    work = tmp_path_factory.mktemp("csc")
    source = work / "planted.cs"
    source.write_text(CSHARP, encoding="ascii")
    target = work / "planted.exe"
    done = subprocess.run(
        [str(compiler), "/nologo", "/target:exe", f"/out:{target}", str(source)],
        capture_output=True,
        check=False,
        timeout=120,
    )
    assert done.returncode == 0, "the harmless planted program did not compile"
    return target.read_bytes()


def plant_valid(path: Path, content: bytes) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(content)
    make_executable(path)


@pytest.mark.slow
def test_a_planted_program_that_would_run_is_never_run(world: World, valid_program: bytes) -> None:
    # control: the planted program really runs and the marker really shows it
    control = world.elsewhere / "control" / PROGRAM
    plant_valid(control, valid_program)
    started = subprocess.run([str(control)], capture_output=True, check=False, timeout=60)
    assert started.returncode == 0
    assert (control.parent / MARKER).is_file(), "control run did not write its marker"
    (control.parent / MARKER).unlink()

    # reachable only through an empty or relative entry
    for place in (world.cwd / "bin", world.cwd.parent):
        plant_valid(place / PROGRAM, valid_program)
    # absolute entries that must be refused: the working directory, the scanned tree, the system
    # temporary tree
    refused = [world.cwd, world.repo, world.repo / "bin", world.temp / "sub"]
    for place in refused:
        plant_valid(place / PROGRAM, valid_program)
    search: list[str | Path] = ["", ".", "..", "bin", "./bin", *refused, real_directory()]
    recorder = Recorder()
    runner = world.open(search, recorder)
    assert_real_git_and_nothing_planted_ran(world, runner, recorder)
