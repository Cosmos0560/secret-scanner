"""Shared fixtures: environment isolation, the socket blocker, `assert_not_leaked` and the named
skip markers (CLAUDE.md section 7)."""

from __future__ import annotations

import os
import shutil
import socket
import sys
from collections.abc import Callable
from pathlib import Path

import pytest

from secret_scanner.core.redact import redact_secret

ISOLATED_ENVIRONMENT = ("HOME", "USERPROFILE", "APPDATA", "LOCALAPPDATA", "XDG_CONFIG_HOME")
MIN_LEAK_RUN = 8


class NetworkBlockedError(RuntimeError):
    """Raised by any socket call made during a test."""


class _BlockedSocket(socket.socket):
    def __init__(self, *args: object, **kwargs: object) -> None:
        raise NetworkBlockedError("network access is blocked in tests")


def _blocked(*args: object, **kwargs: object) -> object:
    raise NetworkBlockedError("network access is blocked in tests")


@pytest.fixture(autouse=True)
def _isolated_environment(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """Point every per-user location at a temporary directory, so no test can read or write the
    real home, application data or configuration of the person running the suite."""
    home = tmp_path / "isolated-home"
    home.mkdir()
    for name in ISOLATED_ENVIRONMENT:
        monkeypatch.setenv(name, str(home))


@pytest.fixture(autouse=True)
def _no_network(monkeypatch: pytest.MonkeyPatch) -> None:
    """Make every socket call fail (CLAUDE.md section 5, invariant 2)."""
    monkeypatch.setattr(socket, "socket", _BlockedSocket)
    for name in (
        "create_connection",
        "create_server",
        "getaddrinfo",
        "gethostbyname",
        "gethostbyname_ex",
        "gethostbyaddr",
        "socketpair",
    ):
        monkeypatch.setattr(socket, name, _blocked)


def leak_check(
    text: str | bytes,
    secret: str | bytes,
    *,
    allowed_shown: int = 0,
) -> str | None:
    """Return a redacted description of a leak, or None when `text` is clean.

    A leak is the whole secret, or any run of its characters longer than `allowed_shown` (and at
    least `MIN_LEAK_RUN`, so a short coincidental run is not reported). The description contains
    only the redacted form of the secret, never the secret.
    """
    haystack = text.encode("utf-8", "surrogateescape") if isinstance(text, str) else text
    needle = secret.encode("utf-8", "surrogateescape") if isinstance(secret, str) else secret
    if not needle:
        return None
    window = min(max(allowed_shown + 1, MIN_LEAK_RUN), len(needle))
    for start in range(len(needle) - window + 1):
        if needle[start : start + window] in haystack:
            redacted = redact_secret(needle, 0).text
            return f"{window}-character run of secret {redacted} (offset {start}) in the output"
    return None


@pytest.fixture
def assert_not_leaked() -> Callable[..., None]:
    """Return `assert_not_leaked(text, secret, allowed_shown=0)`.

    It fails with the redacted form only: a bare `assert secret not in text` would make pytest
    print both sides, and with them the fake, into the log.
    """

    def check(text: str | bytes, secret: str | bytes, *, allowed_shown: int = 0) -> None:
        problem = leak_check(text, secret, allowed_shown=allowed_shown)
        if problem is not None:
            pytest.fail(problem, pytrace=False)

    return check


# -- named skip markers ---------------------------------------------------------------------


def symlinks_work() -> bool:
    """True when this account can create a symlink (Windows needs a privilege or developer mode)."""
    import tempfile  # local: only the marker probe needs it

    with tempfile.TemporaryDirectory() as directory:
        target = Path(directory) / "target"
        target.write_text("x", encoding="utf-8")
        try:
            (Path(directory) / "link").symlink_to(target)
        except (OSError, NotImplementedError):
            return False
    return True


def skip_reason(
    marker_names: set[str], *, platform: str, have_symlinks: Callable[[], bool]
) -> str | None:
    """The reason a test carrying these markers must be skipped here, or None."""
    if "posix_only" in marker_names and platform == "win32":
        return "posix_only: meaningful only on POSIX systems"
    if "windows_only" in marker_names and platform != "win32":
        return "windows_only: meaningful only on Windows"
    if "requires_symlinks" in marker_names and not have_symlinks():
        return "requires_symlinks: this account cannot create symlinks"
    return None


# Marker -> the program it needs. A missing one fails CI (a silent skip would hide the coverage
# loss) and skips elsewhere.
REQUIRED_TOOLS = {"requires_git": "git", "requires_sh": "sh"}


def missing_tool_outcome(*, in_ci: bool) -> str:
    """What a `requires_git` / `requires_sh` test does without its tool: fail in CI, skip
    elsewhere."""
    return "fail" if in_ci else "skip"


_SYMLINKS: list[bool] = []


def _have_symlinks() -> bool:
    if not _SYMLINKS:
        _SYMLINKS.append(symlinks_work())
    return _SYMLINKS[0]


def pytest_runtest_setup(item: pytest.Item) -> None:
    names = {marker.name for marker in item.iter_markers()}
    reason = skip_reason(names, platform=sys.platform, have_symlinks=_have_symlinks)
    if reason is not None:
        pytest.skip(reason)
    for marker, tool in REQUIRED_TOOLS.items():
        if marker in names and shutil.which(tool) is None:
            message = f"{marker}: no {tool} binary on PATH"
            if missing_tool_outcome(in_ci=bool(os.environ.get("CI"))) == "fail":
                pytest.fail(message + f" (a skipped {marker} test fails CI)", pytrace=False)
            pytest.skip(message)
