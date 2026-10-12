"""Validation of paths given by the user (PLAN.md D2, CLAUDE.md section 5).

Pure string logic: nothing here touches the file system. Both OS flavours are interpreted on every
platform, so the Windows rules are tested on Linux and the other way round. A refused path raises
`PathRuleError` with a named reason; the path is never normalised or resolved here.

Refused on both flavours: empty paths, control characters, over-long paths, URL-like values
(`scheme://...`), and `..` components. Refused on the Windows flavour in addition: UNC and device
namespace prefixes, drive-relative and rooted-without-drive forms, `:` anywhere except the drive
colon (alternate data streams), reserved device names, and components ending in a dot or a space.
"""

from __future__ import annotations

from enum import StrEnum

from secret_scanner.core.errors import UsageError
from secret_scanner.core.limits import MAX_PATH_CHARS
from secret_scanner.core.sanitize import sanitize

_SHOWN_PATH_CHARS = 80


class Flavour(StrEnum):
    POSIX = "posix"
    WINDOWS = "windows"


class PathRule(StrEnum):
    """Why a path was refused."""

    EMPTY = "empty"
    TOO_LONG = "too_long"
    CONTROL_CHARACTER = "control_character"
    URL_LIKE = "url_like"
    PARENT_REFERENCE = "parent_reference"
    UNC = "unc"
    DEVICE_NAMESPACE = "device_namespace"
    DRIVE_RELATIVE = "drive_relative"
    ROOTED_WITHOUT_DRIVE = "rooted_without_drive"
    ALTERNATE_STREAM = "alternate_stream"
    RESERVED_NAME = "reserved_name"
    TRAILING_DOT_OR_SPACE = "trailing_dot_or_space"


class PathRuleError(UsageError):
    """A user-supplied path the tool refuses. Carries the rule that refused it."""

    def __init__(self, rule: PathRule, path: str) -> None:
        shown = sanitize(path, max_chars=_SHOWN_PATH_CHARS)
        super().__init__(f"path refused ({rule.value}): {shown}")
        self.rule = rule


_SUPERSCRIPTS = (chr(0xB9), chr(0xB2), chr(0xB3))
_RESERVED_NAMES = frozenset(
    {"con", "prn", "aux", "nul", "conin$", "conout$"}
    | {f"com{n}" for n in "123456789"}
    | {f"lpt{n}" for n in "123456789"}
    | {f"com{s}" for s in _SUPERSCRIPTS}
    | {f"lpt{s}" for s in _SUPERSCRIPTS}
)


def native_flavour(platform: str) -> Flavour:
    """Flavour for a `sys.platform` value (the caller passes it, this layer reads no state)."""
    return Flavour.WINDOWS if platform == "win32" else Flavour.POSIX


def _has_control_character(path: str) -> bool:
    return any(ord(char) < 0x20 or ord(char) == 0x7F for char in path)


def _is_url_like(path: str) -> bool:
    head, sep, _ = path.partition("://")
    if not sep or not head:
        return False
    return head[0].isalpha() and all(char.isalnum() or char in "+.-" for char in head)


def _split_components(path: str, separators: str) -> list[str]:
    components: list[str] = []
    current: list[str] = []
    for char in path:
        if char in separators:
            components.append("".join(current))
            current = []
        else:
            current.append(char)
    components.append("".join(current))
    return components


def _check_windows(path: str) -> None:
    normalized = path.replace("\\", "/")
    if normalized.startswith("//"):
        rest = normalized[2:]
        if rest[:1] in {".", "?"} and rest[1:2] in {"", "/"}:
            raise PathRuleError(PathRule.DEVICE_NAMESPACE, path)
        raise PathRuleError(PathRule.UNC, path)
    body = normalized
    if len(normalized) >= 2 and normalized[0].isalpha() and normalized[1] == ":":
        if len(normalized) == 2 or normalized[2] != "/":
            raise PathRuleError(PathRule.DRIVE_RELATIVE, path)
        body = normalized[2:]
    elif normalized.startswith("/"):
        raise PathRuleError(PathRule.ROOTED_WITHOUT_DRIVE, path)
    if ":" in body:
        raise PathRuleError(PathRule.ALTERNATE_STREAM, path)
    for component in body.split("/"):
        if component in {"", ".", ".."}:
            continue
        if component[-1] in {".", " "}:
            raise PathRuleError(PathRule.TRAILING_DOT_OR_SPACE, path)
        stem = component.split(".", 1)[0].rstrip(" ").lower()
        if stem in _RESERVED_NAMES:
            raise PathRuleError(PathRule.RESERVED_NAME, path)


def validate_user_path(path: str, flavour: Flavour) -> str:
    """Return `path` unchanged if it is acceptable, else raise `PathRuleError`."""
    if not path:
        raise PathRuleError(PathRule.EMPTY, path)
    if len(path) > MAX_PATH_CHARS:
        raise PathRuleError(PathRule.TOO_LONG, path)
    if _has_control_character(path):
        raise PathRuleError(PathRule.CONTROL_CHARACTER, path)
    if _is_url_like(path):
        raise PathRuleError(PathRule.URL_LIKE, path)
    separators = "/\\" if flavour is Flavour.WINDOWS else "/"
    if ".." in _split_components(path, separators):
        raise PathRuleError(PathRule.PARENT_REFERENCE, path)
    if flavour is Flavour.WINDOWS:
        _check_windows(path)
    return path
