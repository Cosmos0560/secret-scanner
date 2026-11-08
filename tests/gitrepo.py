"""Throw-away git repositories for tests (PLAN.md D17).

Argument lists only, never a shell. The environment is built from scratch: no user or system
configuration, no hooks (`--template=` is empty and `core.hooksPath` points at the null device),
no signing, no prompts. The commit identity is passed only through the subprocess environment of
commands that run inside the temporary repository, and its address-like value is built at runtime
from fragments, so no file contains an email address. Nothing is written to any git config file
other than the repository's own, and no identity is ever written there.
"""

from __future__ import annotations

import functools
import os
import subprocess
import sys
from pathlib import Path

from secret_scanner.fs import safe_files

FIRST_COMMIT_EPOCH = 1_767_225_600  # 2026-01-01T00:00:00Z

PINNED_CONFIG: tuple[tuple[str, str], ...] = (
    ("core.hooksPath", os.devnull),
    ("core.autocrlf", "false"),
    ("core.fsmonitor", "false"),
    ("commit.gpgsign", "false"),
    ("tag.gpgsign", "false"),
    ("protocol.allow", "never"),
    ("gc.auto", "0"),
)


@functools.cache
def git_binary() -> str:
    """Absolute path of the git binary, or raise when there is none.

    Not `shutil.which`: on Windows that looks in the current directory first (unless the machine
    sets NoDefaultCurrentDirectoryInExePath), so a test that changes into a directory holding a
    planted `git.exe` would be handed the plant as "the real git". The product's own search
    ignores the current directory and relative entries, and the answer is kept, so a later change
    of directory or PATH cannot alter it."""
    found = safe_files.find_program(
        "git", os.environ.get("PATH", ""), windows=sys.platform == "win32"
    )
    if found is None:
        raise RuntimeError("git is not available")
    return str(Path(found).resolve())


def identity_email() -> str:
    """An address-like value that exists in no file: built from fragments at runtime."""
    return "demo" + "@" + "example" + "." + "invalid"


def git_environment(home: Path, *, commit_index: int = 0) -> dict[str, str]:
    """A from-scratch environment for git commands inside a throw-away repository."""
    stamp = f"{FIRST_COMMIT_EPOCH + 60 * commit_index} +0000"
    environment = {
        "PATH": str(Path(git_binary()).parent),
        "HOME": str(home),
        "GIT_CONFIG_NOSYSTEM": "1",
        "GIT_CONFIG_GLOBAL": os.devnull,
        "GIT_TERMINAL_PROMPT": "0",
        "GIT_PAGER": "cat",
        "PAGER": "cat",
        "LC_ALL": "C",
        "GIT_AUTHOR_NAME": "Demo Author",
        "GIT_AUTHOR_EMAIL": identity_email(),
        "GIT_COMMITTER_NAME": "Demo Author",
        "GIT_COMMITTER_EMAIL": identity_email(),
        "GIT_AUTHOR_DATE": stamp,
        "GIT_COMMITTER_DATE": stamp,
    }
    if sys.platform == "win32":
        environment["SYSTEMROOT"] = os.environ.get("SYSTEMROOT", r"C:\Windows")
        environment["TEMP"] = str(home)
        environment["TMP"] = str(home)
    return environment


def run_git(
    cwd: Path,
    home: Path,
    *args: str,
    commit_index: int = 0,
    check: bool = True,
    extra_env: dict[str, str] | None = None,
    extra_config: tuple[tuple[str, str], ...] = (),
) -> subprocess.CompletedProcess[str]:
    """Run one git command with the pinned configuration and the from-scratch environment.
    `extra_env` (for example a different author name) and `extra_config` apply to this call only."""
    pinned: list[str] = []
    for key, value in (*PINNED_CONFIG, *extra_config):
        pinned += ["-c", f"{key}={value}"]
    return subprocess.run(
        [git_binary(), *pinned, *args],
        cwd=cwd,
        env={**git_environment(home, commit_index=commit_index), **(extra_env or {})},
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="replace",
        check=check,
        timeout=60,
    )


class GitRepo:
    """A temporary repository. Files are staged by explicit path only."""

    def __init__(self, path: Path, home: Path) -> None:
        self.path = path
        self.home = home
        self.commits = 0

    @classmethod
    def create(cls, path: Path, home: Path) -> GitRepo:
        path.mkdir(parents=True, exist_ok=True)
        run_git(path, home, "init", "-q", "-b", "main", "--template=", str(path))
        return cls(path, home)

    def git(
        self,
        *args: str,
        check: bool = True,
        extra_env: dict[str, str] | None = None,
        extra_config: tuple[tuple[str, str], ...] = (),
    ) -> subprocess.CompletedProcess[str]:
        return run_git(
            self.path,
            self.home,
            *args,
            commit_index=self.commits,
            check=check,
            extra_env=extra_env,
            extra_config=extra_config,
        )

    def write(self, relative: str, content: bytes | str) -> Path:
        target = self.path / relative
        target.parent.mkdir(parents=True, exist_ok=True)
        if isinstance(content, str):
            target.write_text(content, encoding="utf-8", newline="\n")
        else:
            target.write_bytes(content)
        return target

    def add(self, *relatives: str) -> None:
        self.git("add", "--", *relatives)

    def commit(self, message: str, *, author: str | None = None, allow_empty: bool = False) -> str:
        """Commit the staged files; `author` replaces the author name for this commit only (an
        environment override, D17)."""
        self.commits += 1
        extra = {"GIT_AUTHOR_NAME": author} if author is not None else None
        arguments = ["commit", "-q", "--no-verify", "-m", message]
        if allow_empty:
            arguments.append("--allow-empty")
        self.git(*arguments, extra_env=extra)
        return self.head()

    def head(self) -> str:
        return self.git("rev-parse", "HEAD").stdout.strip()

    def commit_files(self, message: str, files: dict[str, bytes | str], **kwargs: object) -> str:
        """Write the files, stage exactly those paths and commit."""
        for relative, content in files.items():
            self.write(relative, content)
        self.add(*files)
        return self.commit(message, **kwargs)  # type: ignore[arg-type]
