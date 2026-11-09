"""Builds the demo's throw-away git repository inside the demo sandbox (PLAN.md D17).

This is not the scanner's git runner: it creates commits, so it is a separate module, importable
by `app/demo.py` only (`scripts/check_architecture.py`, rule `sandbox`), and it runs git only
inside the demo's own repository. Arguments are lists, never a shell. The environment is built
from scratch: no user or system configuration, no prompts, no pager, a home directory inside the
sandbox. The commit identity comes from `GIT_AUTHOR_*` and `GIT_COMMITTER_*` in the subprocess
environment of these commands and nowhere else (D17): it is written into no git configuration
file, global or local, and its address-like value is built here from fragments, so no file of the
repository holds an email address. Repositories are made with an empty template (no sample hooks),
hooks are pointed at the null device, and commits use `--no-verify`.

Fixed commit dates make the demo's commit ids the same on every run.
"""

from __future__ import annotations

import os
import subprocess
import sys

from secret_scanner.core.errors import GitError

FIRST_COMMIT_EPOCH = 1_767_225_600  # 2026-01-01T00:00:00Z
COMMIT_SPACING_SECONDS = 3_600
TIMEOUT_SECONDS = 60
AUTHOR_NAME = "Demo Author"
PINNED_CONFIG: tuple[tuple[str, str], ...] = (
    ("core.hooksPath", os.devnull),
    ("core.autocrlf", "false"),
    ("core.fsmonitor", "false"),
    ("commit.gpgsign", "false"),
    ("tag.gpgsign", "false"),
    ("protocol.allow", "never"),
    ("gc.auto", "0"),
)


def identity_email() -> str:
    """An address-like value that exists in no file: built from fragments at runtime."""
    return "demo" + "@" + "example" + "." + "invalid"


def environment_for(git: str, home: str, commit_index: int) -> dict[str, str]:
    """The from-scratch environment of one git command inside the demo repository."""
    stamp = f"{FIRST_COMMIT_EPOCH + COMMIT_SPACING_SECONDS * commit_index} +0000"
    environment = {
        "PATH": os.path.dirname(git),
        "HOME": home,
        "GIT_CONFIG_NOSYSTEM": "1",
        "GIT_CONFIG_GLOBAL": os.devnull,
        "GIT_TERMINAL_PROMPT": "0",
        "GIT_PAGER": "cat",
        "PAGER": "cat",
        "LC_ALL": "C",
        "GIT_AUTHOR_NAME": AUTHOR_NAME,
        "GIT_AUTHOR_EMAIL": identity_email(),
        "GIT_COMMITTER_NAME": AUTHOR_NAME,
        "GIT_COMMITTER_EMAIL": identity_email(),
        "GIT_AUTHOR_DATE": stamp,
        "GIT_COMMITTER_DATE": stamp,
    }
    if sys.platform == "win32":
        environment["SYSTEMROOT"] = os.environ.get("SYSTEMROOT", r"C:\Windows")
        environment["TEMP"] = home
        environment["TMP"] = home
    return environment


class DemoRepo:
    """The demo's repository: `init`, `add`, `remove`, `commit`. `git` is the absolute path found
    by the scanner's own search; `repo` and `home` are directories inside the demo sandbox."""

    def __init__(self, git: str, repo: str, home: str) -> None:
        if not os.path.isabs(git):
            raise GitError("the git program must be given by absolute path")
        self._git = git
        self._repo = repo
        self._home = home
        self._commits = 0

    def _run(self, *args: str) -> str:
        pinned: list[str] = []
        for key, value in PINNED_CONFIG:
            pinned += ["-c", f"{key}={value}"]
        try:
            done = subprocess.run(
                [self._git, *pinned, *args],
                executable=self._git,
                cwd=self._repo,
                env=environment_for(self._git, self._home, self._commits),
                stdin=subprocess.DEVNULL,
                capture_output=True,
                text=True,
                encoding="utf-8",
                errors="replace",
                check=False,
                timeout=TIMEOUT_SECONDS,
            )
        except subprocess.TimeoutExpired:
            raise GitError(f"git {args[0]} did not finish in {TIMEOUT_SECONDS} seconds") from None
        except OSError:
            raise GitError(f"git {args[0]} could not be started") from None
        if done.returncode != 0:
            raise GitError(f"git {args[0]} failed in the demo repository (exit {done.returncode})")
        return done.stdout

    def init(self) -> None:
        self._run("init", "-q", "-b", "main", "--template=", self._repo)

    def add(self, *paths: str) -> None:
        """Stage exactly these paths (relative to the repository)."""
        self._run("add", "--", *paths)

    def remove(self, *paths: str) -> None:
        """Stage the removal of these paths (and delete them from the work tree)."""
        self._run("rm", "-q", "--", *paths)

    def commit(self, message: str) -> str:
        """Commit what is staged and return the new commit id."""
        self._run("commit", "-q", "--no-verify", "-m", message)
        self._commits += 1
        return self._run("rev-parse", "HEAD").strip()
