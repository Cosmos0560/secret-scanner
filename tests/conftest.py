"""Shared fixtures: environment isolation, the socket blocker, `assert_not_leaked` and the named
skip markers (CLAUDE.md section 7)."""

from __future__ import annotations

import functools
import importlib
import inspect
import os
import shutil
import socket
import sys
from collections.abc import Callable, Iterator
from pathlib import Path
from typing import Any

import pytest

from secret_scanner.core.redact import redact_secret
from secret_scanner.core.sanitize import sanitize

ISOLATED_ENVIRONMENT = ("HOME", "USERPROFILE", "APPDATA", "LOCALAPPDATA", "XDG_CONFIG_HOME")
MIN_LEAK_RUN = 8


class NetworkBlockedError(RuntimeError):
    """Raised by any socket call made during a test."""


class _BlockedSocket(socket.socket):
    def __init__(self, *args: object, **kwargs: object) -> None:
        raise NetworkBlockedError("network access is blocked in tests")


def _blocked(*args: object, **kwargs: object) -> object:
    raise NetworkBlockedError("network access is blocked in tests")


@pytest.fixture(scope="session")
def isolated_home(tmp_path_factory: pytest.TempPathFactory) -> Path:
    """The one directory every per-user location points at for the whole session."""
    return tmp_path_factory.mktemp("isolated-home")


@pytest.fixture(scope="session", autouse=True)
def _isolated_environment(isolated_home: Path) -> Iterator[None]:
    """Point every per-user location at a temporary directory, so no test can read or write the
    real home, application data or configuration of the person running the suite.

    Done once per session (the per-test cost of a fresh directory and five `setenv` calls was a
    large part of the default gate's time); `_per_test_guards` proves after each test that nothing
    was written there. A test that changes one of these variables uses `monkeypatch`, which puts
    the session value back."""
    saved = {name: os.environ.get(name) for name in ISOLATED_ENVIRONMENT}
    for name in ISOLATED_ENVIRONMENT:
        os.environ[name] = str(isolated_home)
    try:
        yield
    finally:
        for name, value in saved.items():
            if value is None:
                os.environ.pop(name, None)
            else:
                os.environ[name] = value


_SOCKET_FUNCTIONS = (
    "create_connection",
    "create_server",
    "getaddrinfo",
    "gethostbyname",
    "gethostbyname_ex",
    "gethostbyaddr",
    "socketpair",
)


@pytest.fixture(scope="session", autouse=True)
def _no_network() -> Iterator[None]:
    """Make every socket call fail for the whole session (CLAUDE.md section 5, invariant 2)."""
    with pytest.MonkeyPatch.context() as patch:
        patch.setattr(socket, "socket", _BlockedSocket)
        for name in _SOCKET_FUNCTIONS:
            patch.setattr(socket, name, _blocked)
        yield


# -- the path guard (CLAUDE.md section 7) ---------------------------------------------------
#
# The public functions of the modules that touch the file system are wrapped once per session.
# A test that hands one of them a path outside pytest's temporary base fails, so no test can
# read or write the real home directory, the repository or anything else by accident. Tests that
# read this repository on purpose carry the `reads_repository` marker.

GUARDED_FUNCTIONS: dict[str, dict[str, tuple[str, ...]]] = {
    "secret_scanner.fs.walk": {
        "walk_tree": ("root",),
        "check_scan_root": ("root",),
        "read_regular_file": ("path",),
    },
    "secret_scanner.fs.safe_files": {
        "read_own_file": ("path",),
        "write_new_file": ("path",),
        "check_output_target": ("path",),
        "is_inside": ("root", "candidate"),
        "is_same_path": ("first", "second"),
    },
    "secret_scanner.fs.sandbox": {
        "create_sandbox": ("parent",),
        "remove_sandbox": ("root",),
        "write_text": ("root",),
        "make_directory": ("root",),
        "member": ("root",),
    },
}


class PathGuardState:
    """Where the guard currently allows paths. `base` is None before the first test."""

    base: str | None = None
    allow_repository = False


def require_inside_base(value: object, who: str) -> None:
    """Fail the running test when `value` is a path outside the temporary base."""
    base = PathGuardState.base
    if base is None or PathGuardState.allow_repository or not isinstance(value, str | os.PathLike):
        return
    resolved = os.path.normcase(os.path.realpath(value))
    if resolved != base and not resolved.startswith(base + os.sep):
        shown = sanitize(os.fspath(value), max_chars=120)
        pytest.fail(f"{who} was given a path outside the test temporary directory: {shown}")


def _guard(function: Callable[..., Any], parameters: tuple[str, ...]) -> Callable[..., Any]:
    signature = inspect.signature(function)

    @functools.wraps(function)
    def guarded(*args: Any, **kwargs: Any) -> Any:
        bound = signature.bind_partial(*args, **kwargs)
        for name in parameters:
            if name in bound.arguments:
                require_inside_base(bound.arguments[name], function.__qualname__)
        return function(*args, **kwargs)

    return guarded


def pytest_configure(config: pytest.Config) -> None:
    for module_name, functions in GUARDED_FUNCTIONS.items():
        module = importlib.import_module(module_name)
        for name, parameters in functions.items():
            function = getattr(module, name)
            if not getattr(function, "__wrapped__", None):  # wrap once
                setattr(module, name, _guard(function, parameters))


@pytest.fixture(scope="session", autouse=True)
def _path_guard_base(tmp_path_factory: pytest.TempPathFactory) -> None:
    PathGuardState.base = os.path.normcase(os.path.realpath(tmp_path_factory.getbasetemp()))


def check_isolated_home_is_empty(home: Path) -> None:
    """Fail when a test left anything in the isolated home; the leftovers are removed first, so one
    offender does not fail every later test."""
    leftovers = os.listdir(home)
    if not leftovers:
        return
    for name in leftovers:
        path = home / name
        if path.is_dir() and not path.is_symlink():
            shutil.rmtree(path, ignore_errors=True)
        else:
            path.unlink(missing_ok=True)
    pytest.fail(
        f"the test wrote {len(leftovers)} entr{'y' if len(leftovers) == 1 else 'ies'} into "
        "the isolated home directory",
        pytrace=False,
    )


@pytest.fixture(autouse=True)
def _per_test_guards(request: pytest.FixtureRequest, isolated_home: Path) -> Iterator[None]:
    """Per-test guards: the repository-reading marker for the path guard, and a check that the
    test left nothing in the isolated home."""
    PathGuardState.allow_repository = (
        request.node.get_closest_marker("reads_repository") is not None
    )
    yield
    PathGuardState.allow_repository = False
    check_isolated_home_is_empty(isolated_home)


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


_SHA256: list[bool] = []


def git_supports_sha256() -> bool:
    """True when the installed git can create a SHA-256 repository (probed once, in a temporary
    directory, through the same from-scratch environment the git tests use)."""
    if not _SHA256:
        import tempfile  # local: only the probe needs it

        from tests.gitrepo import git_binary, git_environment

        ok = False
        if shutil.which("git") is not None:
            with tempfile.TemporaryDirectory() as directory:
                try:
                    import subprocess

                    done = subprocess.run(
                        [git_binary(), "init", "-q", "--object-format=sha256", directory],
                        env=git_environment(Path(directory)),
                        capture_output=True,
                        timeout=60,
                        check=False,
                    )
                    ok = done.returncode == 0
                except (OSError, subprocess.SubprocessError):
                    ok = False
        _SHA256.append(ok)
    return _SHA256[0]


def pytest_runtest_setup(item: pytest.Item) -> None:
    names = {marker.name for marker in item.iter_markers()}
    reason = skip_reason(names, platform=sys.platform, have_symlinks=_have_symlinks)
    if reason is not None:
        pytest.skip(reason)
    if "requires_git_sha256" in names and not git_supports_sha256():
        pytest.skip("requires_git_sha256: this git cannot create SHA-256 repositories")
    for marker, tool in REQUIRED_TOOLS.items():
        if marker in names and shutil.which(tool) is None:
            message = f"{marker}: no {tool} binary on PATH"
            if missing_tool_outcome(in_ci=bool(os.environ.get("CI"))) == "fail":
                pytest.fail(message + f" (a skipped {marker} test fails CI)", pytrace=False)
            pytest.skip(message)
