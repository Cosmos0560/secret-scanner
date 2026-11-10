"""The `demo` command: it runs as designed, prints no full fake, touches nothing outside its own
temporary directory, makes no network call, and cleans up when a step fails or is interrupted
(PLAN.md Phase 5, CLAUDE.md section 5 invariants 1 to 3)."""

from __future__ import annotations

import dataclasses
import os
import re
import subprocess
import sys
import tempfile
from collections.abc import Callable
from dataclasses import dataclass
from pathlib import Path

import pytest

from secret_scanner.app import demo as demo_module
from secret_scanner.app.common import resolve_git_program
from secret_scanner.app.demo import SHOWN_DIRECTORY, DemoOutcome, plan_demo, run_demo
from secret_scanner.app.scan import run_scan
from secret_scanner.cli import main as cli_main
from secret_scanner.core.errors import DemoError, ExitCode
from secret_scanner.core.models import Detector
from secret_scanner.core.rules import PRIVATE_KEY_ID
from secret_scanner.fs.sandbox import PREFIX
from secret_scanner.gitio.demo_git import DemoRepo, environment_for
from secret_scanner.services.loader import load_builtin_rules
from tests.audit import Recording, recording
from tests.helpers import PROJECT_ROOT, FakeClock, local_traces, login_name

NO_GIT = {"PATH": ""}
GIT_SUBCOMMANDS = {"init", "add", "rm", "commit", "rev-parse"}


def inside(path: str, directory: Path) -> bool:
    base = os.path.normcase(os.path.realpath(directory))
    candidate = os.path.normcase(os.path.realpath(path))
    return candidate == base or candidate.startswith(base + os.sep)


@dataclass(frozen=True)
class RealRun:
    outcome: DemoOutcome
    events: Recording
    parent: Path
    git: str
    cwd_before: str
    cwd_after: str
    environment_before: dict[str, str]
    environment_after: dict[str, str]


@pytest.fixture(scope="module")
def real_run(tmp_path_factory: pytest.TempPathFactory) -> RealRun:
    """One real demo run in a parent directory of its own, recorded with the audit hook."""
    parent = tmp_path_factory.mktemp("demo-parent")
    tempfile.gettempdir()  # Python's one-time probe of the temporary directory is not the demo's
    git = resolve_git_program(git=None, root=str(parent))
    cwd_before, environment_before = os.getcwd(), dict(os.environ)
    with recording() as events:
        outcome = run_demo(FakeClock(), parent=str(parent))
    return RealRun(
        outcome,
        events,
        parent,
        git,
        cwd_before,
        os.getcwd(),
        environment_before,
        dict(os.environ),
    )


# -- the plan -------------------------------------------------------------------------------------


def test_the_plan_plants_five_fakes_built_at_run_time_for_five_detections() -> None:
    plan = plan_demo()
    assert [fake.rule_id for fake in plan.fakes] == [
        "aws-access-key-id",
        "github-token",
        PRIVATE_KEY_ID,
        "npm-token",
        "stripe-secret-key",
    ]
    rules = {rule.id: rule for rule in load_builtin_rules().rules}
    for fake in plan.fakes:
        rule = rules.get(fake.rule_id)
        assert fake.allowed_shown == (0 if rule is None else rule.shown_chars)
        assert rule is None or rule.detector is Detector.RULE
    assert set(plan.tree) == {".env", "config/settings.py", "deploy/id_demo", "legacy/notes.txt"}
    for fake in plan.fakes[:4]:
        text = plan.tree[fake.path]
        if fake.rule_id == PRIVATE_KEY_ID:  # the body is stored without its line breaks
            assert fake.secret == "".join(
                line for line in text.splitlines() if not line.startswith("-----")
            )
        else:
            assert fake.secret in text
    assert plan.fakes[4].secret in plan.history_before
    assert plan.fakes[4].secret not in plan.history_after


def test_the_plan_is_the_same_every_time_and_changes_with_the_seed() -> None:
    assert plan_demo() == plan_demo()
    assert plan_demo("other").fakes != plan_demo().fakes


# -- one real run ---------------------------------------------------------------------------------


@pytest.mark.requires_git
def test_the_demo_runs_as_designed(real_run: RealRun) -> None:
    outcome = real_run.outcome
    assert outcome.exit_code is ExitCode.OK
    assert outcome.notices == ()
    text = outcome.text
    assert text.startswith("secret-scanner demo\n")
    for heading in ("Step 1: scan a directory", "Step 2: scan git history", "Cleanup:"):
        assert heading in text
    for rule_id in ("aws-access-key-id", "github-token", "private-key", "npm-token"):
        assert rule_id in text
    assert "stripe-secret-key" in text
    assert "[suppressed: fingerprint]" in text
    assert "3 reported, 1 suppressed (1 by fingerprint, 0 by path)" in text
    assert "1 reported, 0 suppressed" in text
    assert "history complete: yes" in text
    assert re.search(r"service/settings\.txt:2:\d+@[0-9a-f]{12}\b", text)
    assert "generated 2026-01-01T00:00:00Z" in text, "the injected clock is used"
    assert text.endswith("was removed.\n")


@pytest.mark.requires_git
def test_the_demo_prints_no_full_fake(
    real_run: RealRun, assert_not_leaked: Callable[..., None]
) -> None:
    shown = real_run.outcome.text + "\n".join(real_run.outcome.notices)
    for fake in plan_demo().fakes:
        assert_not_leaked(shown, fake.secret, allowed_shown=fake.allowed_shown)
    assert shown.isascii() or "\r" not in shown


@pytest.mark.requires_git
def test_the_demo_output_names_no_real_path_account_or_temporary_directory(
    real_run: RealRun,
) -> None:
    """The directory is random, is gone at the end and, on Windows, names the user's account: the
    demo shows a fixed label for it (owner decision, Phase 6 step 0a)."""
    shown = real_run.outcome.text + "\n".join(real_run.outcome.notices)
    assert local_traces(shown, real_run.parent) == []
    assert PREFIX not in shown, "the directory's own random name is not printed either"
    assert f"shown here as {SHOWN_DIRECTORY}." in shown
    assert f" - scan of {SHOWN_DIRECTORY}/tree\n" in shown
    assert f" - history of {SHOWN_DIRECTORY}/repo\n" in shown


@pytest.mark.slow
@pytest.mark.requires_git
def test_the_demo_prints_the_same_text_wherever_its_directory_is(
    real_run: RealRun, tmp_path: Path
) -> None:
    """Nothing in the text depends on the place, so nothing in it can name the place."""
    elsewhere = tmp_path / "Users" / "some-account" / "Temp"
    elsewhere.mkdir(parents=True)
    again = run_demo(FakeClock(), parent=str(elsewhere))
    assert again.text == real_run.outcome.text
    assert again.notices == real_run.outcome.notices
    assert local_traces(again.text, elsewhere, names=("some-account",)) == []


def test_without_git_the_demo_output_names_no_real_path_either(parent: Path) -> None:
    outcome = run_demo(FakeClock(), parent=str(parent), environment=NO_GIT)
    assert local_traces(outcome.text + "\n".join(outcome.notices), parent) == []
    assert PREFIX not in outcome.text


def test_the_check_for_local_traces_finds_each_kind(tmp_path: Path) -> None:
    """The helper behind the test above is not vacuous."""
    assert local_traces("a relative/path.txt:2:14 and <label>/tree, --format json") == []
    assert local_traces("see https://example.invalid/page") == []
    assert local_traces("scan of C:" + "/" + "work") == ["a Windows drive path"]
    assert local_traces("scan of d:" + "\\" + "work") == ["a Windows drive path"]
    assert local_traces("at " + "\\" * 2 + "server" + "\\" + "share") == ["a UNC or device path"]
    assert local_traces("scan of /srv/project") == ["a POSIX absolute path"]
    assert local_traces("/srv/project", absolute_paths=False) == []
    assert "directory 1" in local_traces(f"in {tmp_path}", tmp_path)
    assert "directory 1" in local_traces(f"in {tmp_path.as_posix().upper()}", tmp_path)
    assert "the system temporary directory" in local_traces(f"{tempfile.gettempdir()}/x")
    assert local_traces("made by Some-Account", names=("some-account",)) == ["name 1"]
    user = login_name()
    if user is not None:
        assert "the account name as a part of a path" in local_traces(
            f"home/{user}/x", absolute_paths=False
        )
        assert local_traces(f"the word {user} alone, or home/{user}-other") == []


@pytest.mark.requires_git
def test_the_demo_removes_everything_and_leaves_the_process_as_it_was(real_run: RealRun) -> None:
    assert os.listdir(real_run.parent) == []
    assert real_run.cwd_after == real_run.cwd_before
    assert real_run.environment_after == real_run.environment_before


@pytest.mark.requires_git
def test_the_demo_touches_no_path_outside_its_temporary_directory(real_run: RealRun) -> None:
    written = real_run.events.written_paths()
    assert written, "the audit hook saw nothing: the guard would prove nothing"
    outside = [path for path in written if not inside(path, real_run.parent)]
    assert outside == []
    # the repository under test is untouched too: no write below the project folder
    assert not [p for p in written if inside(p, PROJECT_ROOT)]
    created = real_run.events.named("tempfile.mkdtemp")
    assert len(created) == 1
    assert os.path.basename(str(created[0][0])).startswith(PREFIX)


@pytest.mark.requires_git
def test_the_demo_makes_no_network_call_and_changes_no_process_state(real_run: RealRun) -> None:
    assert real_run.events.network() == []
    assert real_run.events.process() == []
    # Python may start a child with os.posix_spawn from inside subprocess: then it is git
    git = os.path.normcase(os.path.realpath(real_run.git))
    for program in real_run.events.posix_spawned():
        assert os.path.normcase(os.path.realpath(program)) == git


@pytest.mark.requires_git
def test_the_demo_starts_only_git_inside_its_own_repository(real_run: RealRun) -> None:
    spawned = real_run.events.spawned()
    git = os.path.normcase(real_run.git)
    expected = sorted(environment_for(real_run.git, "home", 0))
    # the builder's commands (init, add, commit, rev-parse, add, commit, rev-parse) are the ones
    # with the builder's own environment; the scanner's runner has another one
    builder = [s for s in spawned if s.environment_names == expected]
    assert len(builder) == 7
    for started in spawned:
        command = os.path.normcase(started.command)
        if sys.platform == "win32" and "taskkill" in command:
            assert os.path.normcase("/pid") in command, "a stopped git is ended by its process id"
            continue
        assert git in os.path.normcase(started.executable + " " + started.command)
        assert started.environment_names is not None, "never the inherited environment"
        assert "user.name" not in command
        assert "user.email" not in command
        assert started.cwd is None or inside(started.cwd, real_run.parent)
    for started in builder:
        assert started.cwd is not None
        assert inside(started.cwd, real_run.parent)
        subcommand = next(token for token in started.command.split() if token in GIT_SUBCOMMANDS)
        assert subcommand in GIT_SUBCOMMANDS


# -- failure, interruption, no git ----------------------------------------------------------------


@pytest.fixture
def parent(tmp_path: Path) -> Path:
    directory = tmp_path / "parent"
    directory.mkdir()
    return directory


def test_a_failing_step_propagates_and_the_directory_is_removed(
    parent: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    calls: list[str] = []
    original = run_scan

    def fail_second(*args: object, **kwargs: object) -> object:
        calls.append("scan")
        if len(calls) == 2:
            raise RuntimeError("a step failed")
        return original(*args, **kwargs)  # type: ignore[arg-type]

    monkeypatch.setattr(demo_module, "run_scan", fail_second)
    with pytest.raises(RuntimeError, match="a step failed"):
        run_demo(FakeClock(), parent=str(parent))
    assert len(calls) == 2
    assert os.listdir(parent) == []


def test_ctrl_c_removes_the_directory_too(parent: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    def interrupt(*args: object, **kwargs: object) -> object:
        raise KeyboardInterrupt

    monkeypatch.setattr(demo_module, "run_scan", interrupt)
    with pytest.raises(KeyboardInterrupt):
        run_demo(FakeClock(), parent=str(parent))
    assert os.listdir(parent) == []


@pytest.mark.requires_git
def test_an_interrupt_in_the_middle_of_the_history_part_removes_everything(
    parent: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    def interrupt(self: object) -> None:
        raise KeyboardInterrupt

    monkeypatch.setattr(DemoRepo, "init", interrupt)
    with pytest.raises(KeyboardInterrupt):
        run_demo(FakeClock(), parent=str(parent))
    assert os.listdir(parent) == []


def test_the_demo_reports_a_result_it_does_not_expect_and_cleans_up(
    parent: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    plan = plan_demo()
    smaller = {path: text for path, text in plan.tree.items() if path != "legacy/notes.txt"}
    monkeypatch.setattr(demo_module, "plan_demo", lambda: dataclasses.replace(plan, tree=smaller))
    with pytest.raises(DemoError, match="four planted secrets found"):
        run_demo(FakeClock(), parent=str(parent))
    assert os.listdir(parent) == []


@pytest.mark.requires_git
def test_a_history_without_the_removed_secret_is_reported_and_cleaned_up(
    parent: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    plan = plan_demo()
    clean = dataclasses.replace(plan, history_before=plan.history_after + "# an earlier note\n")
    monkeypatch.setattr(demo_module, "plan_demo", lambda: clean)
    with pytest.raises(DemoError, match="removed secret found in the commit that added it"):
        run_demo(FakeClock(), parent=str(parent))
    assert os.listdir(parent) == []


def test_without_git_the_directory_part_runs_and_the_history_part_is_skipped(
    parent: Path, assert_not_leaked: Callable[..., None]
) -> None:
    outcome = run_demo(FakeClock(), parent=str(parent), environment=NO_GIT)
    assert outcome.exit_code is ExitCode.GIT
    assert "Step 1: scan a directory" in outcome.text
    assert "3 reported, 1 suppressed" in outcome.text
    assert "Step 2: scan git history" in outcome.text
    assert "Skipped: git was not found" in outcome.text
    assert "stripe-secret-key" not in outcome.text
    assert len(outcome.notices) == 1
    assert outcome.notices[0].startswith("warning: the history part of the demo was skipped")
    assert os.listdir(parent) == []
    for fake in plan_demo().fakes:
        assert_not_leaked(outcome.text, fake.secret, allowed_shown=fake.allowed_shown)


def test_a_git_that_is_not_a_regular_file_is_refused_before_anything_is_built(
    parent: Path,
) -> None:
    with pytest.raises(Exception, match="program"):
        run_demo(FakeClock(), parent=str(parent), git=str(parent / "nope"))
    assert os.listdir(parent) == []


def test_the_default_directory_is_the_system_temporary_directory(
    parent: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(tempfile, "tempdir", str(parent))
    outcome = run_demo(FakeClock(), environment=NO_GIT)
    assert outcome.exit_code is ExitCode.GIT
    assert os.listdir(parent) == []


# -- the command ----------------------------------------------------------------------------------


def test_the_command_prints_the_text_and_the_notices_and_returns_the_exit_code(
    capsys: pytest.CaptureFixture[str], monkeypatch: pytest.MonkeyPatch
) -> None:
    canned = DemoOutcome(ExitCode.GIT, "the demo text\n", ("warning: skipped",))
    monkeypatch.setattr(cli_main, "run_demo", lambda clock: canned)
    assert cli_main.main(["demo"]) == 3
    captured = capsys.readouterr()
    assert captured.out == "the demo text\n"
    assert captured.err == "secret-scanner: warning: skipped\n"


def test_the_command_takes_no_arguments(capsys: pytest.CaptureFixture[str]) -> None:
    assert cli_main.main(["demo", "somewhere"]) == 2
    assert cli_main.main(["demo", "--format", "json"]) == 2
    assert capsys.readouterr().out == ""


def test_ctrl_c_ends_the_command_with_a_message_and_no_traceback(
    capsys: pytest.CaptureFixture[str], monkeypatch: pytest.MonkeyPatch
) -> None:
    def interrupt(clock: object) -> DemoOutcome:
        raise KeyboardInterrupt

    monkeypatch.setattr(cli_main, "run_demo", interrupt)
    assert cli_main.main(["demo"]) == cli_main.INTERRUPTED == 130
    captured = capsys.readouterr()
    assert captured.out == ""
    assert captured.err == "secret-scanner: interrupted\n"


def test_a_demo_error_is_an_ordinary_error_exit(
    capsys: pytest.CaptureFixture[str], monkeypatch: pytest.MonkeyPatch
) -> None:
    def refuse(clock: object) -> DemoOutcome:
        raise DemoError("the demo could not run")

    monkeypatch.setattr(cli_main, "run_demo", refuse)
    assert cli_main.main(["demo"]) == 2
    assert capsys.readouterr().err == "secret-scanner: error: the demo could not run\n"


@pytest.mark.slow
@pytest.mark.requires_git
def test_the_demo_works_as_a_real_process_with_a_clean_exit(
    tmp_path: Path, assert_not_leaked: Callable[..., None]
) -> None:
    temporary = tmp_path / "Users" / "some-account" / "Temp"  # the shape of a Windows profile
    temporary.mkdir(parents=True)
    environment = {
        "PATH": os.environ.get("PATH", ""),
        "TMP": str(temporary),
        "TEMP": str(temporary),
        "TMPDIR": str(temporary),
        "HOME": str(tmp_path),
        "PYTHONIOENCODING": "utf-8",
    }
    if sys.platform == "win32":
        environment["SYSTEMROOT"] = os.environ.get("SYSTEMROOT", r"C:\Windows")
    done = subprocess.run(
        [sys.executable, "-I", "-m", "secret_scanner", "demo"],
        cwd=tmp_path,
        env=environment,
        capture_output=True,
        text=True,
        encoding="utf-8",
        timeout=300,
        check=False,
    )
    assert done.returncode == 0, done.stderr
    assert done.stderr == ""
    assert "Step 2: scan git history" in done.stdout
    assert os.listdir(temporary) == []
    assert local_traces(done.stdout, temporary, tmp_path, names=("some-account",)) == []
    for fake in plan_demo().fakes:
        assert_not_leaked(done.stdout, fake.secret, allowed_shown=fake.allowed_shown)
