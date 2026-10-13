"""User path validation, interpreted for both OS flavours on every platform."""

from __future__ import annotations

import pytest

from secret_scanner.core.errors import UsageError
from secret_scanner.core.limits import MAX_PATH_CHARS
from secret_scanner.core.pathrules import (
    Flavour,
    PathRule,
    PathRuleError,
    native_flavour,
    validate_user_path,
)

BS = chr(92)

# (path, rule that refuses it on every flavour)
REFUSED_EVERYWHERE = [
    ("", PathRule.EMPTY),
    ("a" * (MAX_PATH_CHARS + 1), PathRule.TOO_LONG),
    ("dir/name" + chr(0), PathRule.CONTROL_CHARACTER),
    ("dir/na" + chr(10) + "me", PathRule.CONTROL_CHARACTER),
    ("dir/na" + chr(0x1B) + "[31m", PathRule.CONTROL_CHARACTER),
    ("dir/name" + chr(0x7F), PathRule.CONTROL_CHARACTER),
    ("https://example.invalid/x", PathRule.URL_LIKE),
    ("file:///etc/passwd", PathRule.URL_LIKE),
    ("ssh+git://host/repo", PathRule.URL_LIKE),
    ("../outside", PathRule.PARENT_REFERENCE),
    ("a/../b", PathRule.PARENT_REFERENCE),
    ("a/b/..", PathRule.PARENT_REFERENCE),
    ("..", PathRule.PARENT_REFERENCE),
]

REFUSED_ON_WINDOWS_ONLY = [
    (BS * 2 + "server" + BS + "share" + BS + "dir", PathRule.UNC),
    ("//server/share/dir", PathRule.UNC),
    (BS * 2 + "." + BS + "C:" + BS + "x", PathRule.DEVICE_NAMESPACE),
    (BS * 2 + "?" + BS + "C:" + BS + "x", PathRule.DEVICE_NAMESPACE),
    ("//./pipe/name", PathRule.DEVICE_NAMESPACE),
    ("//?/C:/x", PathRule.DEVICE_NAMESPACE),
    ("C:", PathRule.DRIVE_RELATIVE),
    ("C:file.txt", PathRule.DRIVE_RELATIVE),
    ("c:dir" + BS + "file", PathRule.DRIVE_RELATIVE),
    (BS + "rooted", PathRule.ROOTED_WITHOUT_DRIVE),
    ("/rooted/without/drive", PathRule.ROOTED_WITHOUT_DRIVE),
    ("file.txt:stream", PathRule.ALTERNATE_STREAM),
    ("C:" + BS + "dir" + BS + "file.txt:$DATA", PathRule.ALTERNATE_STREAM),
    ("dir" + BS + "CON", PathRule.RESERVED_NAME),
    ("nul.txt", PathRule.RESERVED_NAME),
    ("dir/aux.tar.gz", PathRule.RESERVED_NAME),
    ("COM1", PathRule.RESERVED_NAME),
    ("lpt9.log", PathRule.RESERVED_NAME),
    ("com" + chr(0xB9), PathRule.RESERVED_NAME),
    ("CONOUT$", PathRule.RESERVED_NAME),
    ("name.", PathRule.TRAILING_DOT_OR_SPACE),
    ("dir" + BS + "name ", PathRule.TRAILING_DOT_OR_SPACE),
    ("...", PathRule.TRAILING_DOT_OR_SPACE),
    ("a" + BS + ".." + BS + "b", PathRule.PARENT_REFERENCE),
]

ACCEPTED_EVERYWHERE = [
    ".",
    "src",
    "src/module.py",
    "dir.with.dots/file-name_1.txt",
    "./relative",
    ".hidden",
    "..data",
    "name..txt",
    "console",
    "a b/c d",
    "unicode-" + chr(0xE9) + "-" + chr(0x4E2D),
    "http",
]

ACCEPTED_ON_WINDOWS = [
    "C:" + BS + "Users" + BS + "me" + BS + "project",
    "C:/Users/me/project",
    "d:" + BS + "x",
    "relative" + BS + "dir",
    "src" + BS + "module.py",
]

ACCEPTED_ON_POSIX_ONLY = [
    "/home/me/project",
    "/",
    "dir" + BS + "with" + BS + "backslashes",
    "name.",
    "nul.txt",
    "file.txt:stream",
    "C:file.txt",
    "name ",
    BS + "rooted",
    "http:/one-slash",
]


@pytest.mark.parametrize(("path", "rule"), REFUSED_EVERYWHERE)
@pytest.mark.parametrize("flavour", list(Flavour))
def test_refused_on_both_flavours(path: str, rule: PathRule, flavour: Flavour) -> None:
    with pytest.raises(PathRuleError) as raised:
        validate_user_path(path, flavour)
    assert raised.value.rule is rule


@pytest.mark.parametrize(("path", "rule"), REFUSED_ON_WINDOWS_ONLY)
def test_refused_on_windows_flavour(path: str, rule: PathRule) -> None:
    with pytest.raises(PathRuleError) as raised:
        validate_user_path(path, Flavour.WINDOWS)
    assert raised.value.rule is rule


@pytest.mark.parametrize("path", ACCEPTED_EVERYWHERE)
@pytest.mark.parametrize("flavour", list(Flavour))
def test_accepted_on_both_flavours(path: str, flavour: Flavour) -> None:
    assert validate_user_path(path, flavour) == path


@pytest.mark.parametrize("path", ACCEPTED_ON_WINDOWS)
def test_accepted_on_windows_flavour(path: str) -> None:
    assert validate_user_path(path, Flavour.WINDOWS) == path


@pytest.mark.parametrize("path", ACCEPTED_ON_POSIX_ONLY)
def test_windows_specific_rules_do_not_apply_to_posix_names(path: str) -> None:
    assert validate_user_path(path, Flavour.POSIX) == path


def test_exactly_at_the_length_limit_is_accepted() -> None:
    assert validate_user_path("a" * MAX_PATH_CHARS, Flavour.POSIX)


def test_posix_backslash_dotdot_is_a_filename_not_a_parent_reference() -> None:
    assert validate_user_path("a" + BS + ".." + BS + "b", Flavour.POSIX)


def test_error_is_a_usage_error_with_a_sanitised_bounded_message() -> None:
    hostile = "x" * 500 + chr(0x202E) + chr(0x1B)
    with pytest.raises(PathRuleError) as raised:
        validate_user_path(hostile, Flavour.POSIX)
    assert isinstance(raised.value, UsageError)
    message = str(raised.value)
    assert "control_character" in message
    assert chr(0x202E) not in message
    assert chr(0x1B) not in message
    assert len(message) < 200


def test_path_is_returned_unchanged() -> None:
    value = "some/dir/../not-refused-here/file"
    with pytest.raises(PathRuleError):
        validate_user_path(value, Flavour.POSIX)
    assert validate_user_path("./some//dir", Flavour.POSIX) == "./some//dir"


def test_native_flavour_follows_sys_platform_values() -> None:
    assert native_flavour("win32") is Flavour.WINDOWS
    assert native_flavour("linux") is Flavour.POSIX
    assert native_flavour("darwin") is Flavour.POSIX


def test_a_refused_windows_path_is_shown_with_forward_slashes() -> None:
    refused = chr(92).join(["C:", "Users", "dev", "..", "x"])
    with pytest.raises(PathRuleError) as caught:
        validate_user_path(refused, Flavour.WINDOWS)
    assert "C:/Users/dev/../x" in str(caught.value)
    assert chr(92) * 2 not in str(caught.value)


def test_a_refused_posix_path_keeps_its_backslash_escaped() -> None:
    with pytest.raises(PathRuleError) as caught:
        validate_user_path("a" + chr(92) + "b/../c", Flavour.POSIX)
    # The backslash is a name character on POSIX: it is escaped, never shown as a separator.
    assert "a" + chr(92) + "b" not in str(caught.value)
    assert "a/b" not in str(caught.value)
