"""The `demo` use case (PLAN.md Phase 5): plant fakes, scan them, show the result, clean up.

In a temporary directory that `fs/sandbox.py` makes and removes, the demo

1. writes a few files with fake secrets that the generator builds at run time (PLAN.md D16): one in
   an `.env` file, one in a settings file, one private key block, and one that a baseline written
   by the demo suppresses;
2. runs `scan` on that tree, through the real application code, with the baseline and
   `--show-suppressed`;
3. builds a throw-away git repository (`gitio/demo_git.py`, identity through the subprocess
   environment only, PLAN.md D17) in which one fake is committed and removed again in the next
   commit, and runs `scan` on its current files (nothing) and `scan-git` on its history (the
   removed secret, with the commit that introduced it);
4. returns the redacted tables and a short explanation, and removes the directory in a `finally`,
   so also when a step fails or the user presses Ctrl-C.

The demo checks what it expects (every planted secret found, the suppressed one suppressed, the
removed secret found in the right commit); a result that differs raises `DemoError` (exit code 2).
Without git the directory part still runs; the history part is skipped and the exit code is 3.

Nothing is printed here (the CLI prints the returned text) and nothing outside the sandbox is
touched. No full fake is ever put in the text: it comes from `ScanOutcome.text`, which is redacted.
"""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass

from secret_scanner.app.common import ScanOutcome, resolve_git_program
from secret_scanner.app.scan import ScanRequest, run_scan
from secret_scanner.app.scan_git import GitScanRequest, run_scan_git
from secret_scanner.core.clock import Clock
from secret_scanner.core.errors import DemoError, ExitCode, GitError
from secret_scanner.core.fakes import build_fake, fake_private_key
from secret_scanner.core.models import Finding, SuppressedBy
from secret_scanner.core.rules import PRIVATE_KEY_ID
from secret_scanner.core.suppress import baseline_document
from secret_scanner.fs import sandbox
from secret_scanner.gitio.demo_git import DemoRepo
from secret_scanner.services.config import serialize_baseline
from secret_scanner.services.loader import load_builtin_rules

__all__ = ["DemoOutcome", "DemoPlan", "PlantedFake", "plan_demo", "run_demo"]

SEED = "demo"
HOST_LABEL = "demo"  # not used in the table; it keeps the host name lookup out of the demo
# The directory's real path is never printed: it is random, it is gone when the demo ends, and on
# Windows it names the user's account. Every place that would show it shows this label instead.
SHOWN_DIRECTORY = "<temporary directory>"
BASELINE_REASON = "demo: this fake is accepted so that the report shows a suppressed finding"
TREE = "tree"
REPO = "repo"
HOME = "home"
BASELINE = "baseline.yaml"
SUPPRESSED_PATH = "legacy/notes.txt"
HISTORY_PATH = "service/settings.txt"
HISTORY_RULE = "stripe-secret-key"
TREE_RULES = ("aws-access-key-id", "github-token", PRIVATE_KEY_ID, "npm-token")


@dataclass(frozen=True, slots=True)
class PlantedFake:
    """One fake secret the demo plants: what it is, where, and how many leading characters of it
    the tool may show (the rule's public prefix). Tests use it to prove none is ever printed."""

    rule_id: str
    path: str
    secret: str
    allowed_shown: int


@dataclass(frozen=True, slots=True)
class DemoPlan:
    """Everything the demo writes, as text: the files of the directory tree, the two states of the
    history file, and the fakes (a sub-string of those files)."""

    tree: Mapping[str, str]
    repo_readme: str
    history_before: str
    history_after: str
    fakes: tuple[PlantedFake, ...]


@dataclass(frozen=True, slots=True)
class DemoOutcome:
    """The text to print, the one-line notices for stderr and the exit code."""

    exit_code: ExitCode
    text: str
    notices: tuple[str, ...] = ()


def plan_demo(seed: str = SEED) -> DemoPlan:
    """The files and fakes of the demo, built at run time from the generator."""
    rules = {rule.id: rule for rule in load_builtin_rules().rules}

    def fake(rule_id: str, path: str) -> PlantedFake:
        rule = rules[rule_id]
        return PlantedFake(rule_id, path, build_fake(rule, seed), rule.shown_chars)

    aws = fake("aws-access-key-id", ".env")
    github = fake("github-token", "config/settings.py")
    npm = fake("npm-token", SUPPRESSED_PATH)
    stripe = fake(HISTORY_RULE, HISTORY_PATH)
    key = fake_private_key(seed, label="RSA")
    key_body = "".join(line for line in key.splitlines() if not line.startswith("-----"))
    private_key = PlantedFake(PRIVATE_KEY_ID, "deploy/id_demo", key_body, 0)
    tree = {
        aws.path: f"# demo settings\nAWS_ACCESS_KEY_ID={aws.secret}\nREGION=eu-west-1\n",
        github.path: f'"""Demo settings."""\n\nGITHUB_TOKEN = "{github.secret}"\n',
        private_key.path: key,
        npm.path: f"old note: NPM_TOKEN={npm.secret}\n",
    }
    unchanged = "api_url = https://example.invalid/api\n"
    return DemoPlan(
        tree=tree,
        repo_readme="A throw-away repository made by the secret-scanner demo.\n",
        history_before=f"{unchanged}stripe_key = {stripe.secret}\n",
        history_after=f"{unchanged}stripe_key = (read it from the environment)\n",
        fakes=(aws, github, private_key, npm, stripe),
    )


def _rule_ids(findings: tuple[Finding, ...], *, suppressed: bool) -> list[str]:
    return sorted(f.rule_id for f in findings if (f.suppressed_by is not None) is suppressed)


def _expect(condition: bool, what: str) -> None:
    if not condition:
        raise DemoError(f"the demo did not get the result it expects: {what}")


def _scan_tree(box: str, clock: Clock, plan: DemoPlan) -> ScanOutcome:
    """Write the tree, scan it, write a baseline for the one finding at `SUPPRESSED_PATH`, scan
    again with it. Returns the outcome of the second scan."""
    tree = sandbox.make_directory(box, TREE)
    for relative, text in plan.tree.items():
        sandbox.write_text(tree, relative, text)
    baseline = sandbox.member(box, BASELINE)
    first = run_scan(ScanRequest(path=tree, host_label=HOST_LABEL), clock)
    found = first.report.findings
    _expect(_rule_ids(found, suppressed=False) == sorted(TREE_RULES), "four planted secrets found")
    accepted = [f for f in found if f.location.path_key == SUPPRESSED_PATH]
    _expect(len(accepted) == 1, "one finding in the file the baseline will accept")
    document = baseline_document(accepted, reasons={accepted[0].fingerprint: BASELINE_REASON})
    sandbox.write_text(box, BASELINE, serialize_baseline(document).decode("ascii"))
    second = run_scan(
        ScanRequest(path=tree, baseline=baseline, show_suppressed=True, host_label=HOST_LABEL),
        clock,
        shown_as=f"{SHOWN_DIRECTORY}/{TREE}",
    )
    shown = second.report.findings
    _expect(
        _rule_ids(shown, suppressed=False) == sorted(set(TREE_RULES) - {"npm-token"}),
        "three findings reported",
    )
    _expect(
        [f.suppressed_by for f in shown if f.suppressed_by is not None]
        == [SuppressedBy.FINGERPRINT],
        "one finding suppressed by the baseline",
    )
    return second


def _scan_history(
    box: str,
    git: str,
    clock: Clock,
    plan: DemoPlan,
    environment: Mapping[str, str] | None,
) -> tuple[ScanOutcome, ScanOutcome, str]:
    """Build the repository (the secret committed, then removed), scan its current files and its
    history. Returns both outcomes and the id of the commit that added the secret."""
    repo = sandbox.make_directory(box, REPO)
    home = sandbox.make_directory(box, HOME)
    builder = DemoRepo(git, repo, home)
    builder.init()
    sandbox.write_text(repo, "README.md", plan.repo_readme)
    sandbox.write_text(repo, HISTORY_PATH, plan.history_before)
    builder.add("README.md", HISTORY_PATH)
    added = builder.commit("Add the service settings")
    sandbox.write_text(repo, HISTORY_PATH, plan.history_after, replace=True)
    builder.add(HISTORY_PATH)
    builder.commit("Read the key from the environment instead")

    files = run_scan(ScanRequest(path=repo, host_label=HOST_LABEL), clock)
    _expect(not files.report.findings, "no finding in the repository's current files")
    history = run_scan_git(
        GitScanRequest(path=repo, git=git, host_label=HOST_LABEL),
        clock,
        environment=environment,
        shown_as=f"{SHOWN_DIRECTORY}/{REPO}",
    )
    found = history.report.findings
    _expect(
        [(f.rule_id, f.location.commit) for f in found] == [(HISTORY_RULE, added)],
        "the removed secret found in the commit that added it",
    )
    _expect(history.report.complete, "a complete history scan")
    return files, history, added


def _intro() -> str:
    return (
        "secret-scanner demo\n"
        "===================\n\n"
        "Everything below happens in a temporary directory that is removed at the end,\n"
        f"shown here as {SHOWN_DIRECTORY}.\n\n"
        "All secrets are fakes, built at run time from fragments; none is a real credential.\n"
        "The tool never prints a whole secret: it prints a short public prefix, the length and\n"
        "a short hash of the secret, and the place where it was found.\n"
    )


def _directory_part(second: ScanOutcome) -> str:
    return (
        "\nStep 1: scan a directory (secret-scanner scan DIR --baseline FILE --show-suppressed)\n"
        "\n"
        "  The demo planted an AWS key id in .env, a GitHub token in config/settings.py, a\n"
        "  private key block in deploy/id_demo and an npm token in legacy/notes.txt. It wrote a\n"
        "  baseline that accepts the npm token (by fingerprint) and scanned with it:\n"
        "\n" + second.text + "\n"
        "  Three findings are reported. The accepted one is listed only because of\n"
        "  --show-suppressed and is marked; without it, it is counted in the summary and not\n"
        "  listed. A real run would exit with code 1 here, which is what fails a CI job.\n"
    )


def _history_part(files: ScanOutcome, history: ScanOutcome) -> str:
    commits = history.report.stats.commits
    return (
        "\nStep 2: scan git history (secret-scanner scan-git REPO)\n"
        "\n"
        f"  The throw-away repository has {commits} commits. The first adds a Stripe-style key to\n"
        "  service/settings.txt; the second replaces it with a note. Scanning the repository's\n"
        f"  current files finds {len(files.report.findings)} secrets. Scanning its history finds\n"
        "  the key and names the commit that introduced it:\n"
        "\n" + history.text + "\n"
        "  Deleting a secret from the files does not remove it from the history. Revoke it.\n"
    )


_SKIPPED_HISTORY = (
    "\nStep 2: scan git history (secret-scanner scan-git REPO)\n"
    "\n"
    "  Skipped: git was not found. Install git 2.32 or newer, or run the demo with git on PATH.\n"
)

_OTHER_FORMATS = (
    "\nOther output: --format json, jsonl (for mini-siem) and sarif (for code scanning);\n"
    "--write-baseline records the current findings; `secret-scanner rules` lists the rules.\n"
)


def run_demo(
    clock: Clock,
    *,
    parent: str | None = None,
    git: str | None = None,
    environment: Mapping[str, str] | None = None,
) -> DemoOutcome:
    """Run the demo and return its text. `parent` is where the temporary directory is made (the
    system temporary directory by default). Raises `SecretScannerError` subclasses; the directory
    is removed in every case."""
    plan = plan_demo()
    box = sandbox.create_sandbox(parent)
    try:
        parts = [_intro()]
        second = _scan_tree(box, clock, plan)
        parts.append(_directory_part(second))
        notices: tuple[str, ...] = ()
        exit_code = ExitCode.OK
        try:
            program = resolve_git_program(
                git=git, root=sandbox.member(box, REPO), environment=environment
            )
        except GitError as error:
            parts.append(_SKIPPED_HISTORY)
            notices = (f"warning: the history part of the demo was skipped: {error}",)
            exit_code = ExitCode.GIT
        else:
            files, history, _ = _scan_history(box, program, clock, plan, environment)
            parts.append(_history_part(files, history))
        parts.append(_OTHER_FORMATS)
    finally:
        sandbox.remove_sandbox(box)
    parts.append("\nCleanup: the temporary directory and everything in it was removed.\n")
    return DemoOutcome(exit_code, "".join(parts), notices)
