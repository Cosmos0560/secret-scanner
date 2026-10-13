"""Strict parsers for the output of the git commands the tool runs (PLAN.md D1, D2).

Pure: bytes in, plain values out. Nothing is run or read here. Everything git prints is hostile
until parsed (paths, object ids, even the version line), so the parsers accept one exact grammar
and fail closed: a truncated record, an unknown status or mode, an id of the wrong length, a
stray token or trailing bytes raise `GitOutputError` (exit code 3), never a guess.

The history walk is one `git log --raw -z` stream whose records are NUL-terminated tokens:

    <SOH><commit id> <parent ids> <committer time> NUL            one per commit
    [LF] :<old mode> <new mode> <old id> <new id> <status> NUL    one per changed path
    <path> NUL

The commit header carries a leading byte (0x01) that git itself never writes into an object id
or a number, and the first raw record after it a line feed; neither is trusted for anything but
framing. A path is read positionally, directly after its raw record, so no path can be mistaken
for a header whatever it contains.
"""

from __future__ import annotations

from collections.abc import Iterator
from dataclasses import dataclass
from enum import StrEnum

from secret_scanner.core.errors import GitError, UsageError
from secret_scanner.core.sanitize import sanitize

# git 2.32 added GIT_CONFIG_GLOBAL and GIT_CONFIG_SYSTEM (D2). Everything else the tool uses is
# older (`--diff-merges=first-parent` 2.31, `--end-of-options` 2.24, `--is-shallow-repository`
# 2.15). docs/git-hardening.md has the table.
MIN_GIT_VERSION = (2, 32, 0)

HEADER_MARK = 0x01
MAX_REVISION_CHARS = 255
MAX_TOKEN_BYTES = 1 << 20  # one NUL-terminated record; bounds the parser's buffer
MAX_VERSION_LINE_BYTES = 200
MAX_SIZE_DIGITS = 18

_HEX = frozenset(b"0123456789abcdef")
_OCTAL = frozenset(b"01234567")
_ALNUM = frozenset(b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789")
_REVISION_REST = _ALNUM | frozenset(b"._/-")
_ID_LENGTHS = (40, 64)  # SHA-1 and SHA-256 repositories
_SHOWN_CHARS = 80

GITLINK_MODE = "160000"
SYMLINK_MODE = "120000"
NO_MODE = "000000"
_ALLOWED_STATUSES = frozenset("AMT")  # --diff-filter=AMT --no-renames: nothing else may appear


class GitOutputError(GitError):
    """git printed something the strict parsers do not accept."""


def _fail(what: str) -> GitOutputError:
    return GitOutputError(f"unexpected git output: {what}")


# -- versions ------------------------------------------------------------------------------------


def parse_git_version(output: bytes) -> tuple[int, int, int]:
    """The `(major, minor, patch)` of `git version 2.54.0.windows.1`-style output."""
    line = output.split(b"\n", 1)[0].strip()
    prefix = b"git version "
    if len(line) > MAX_VERSION_LINE_BYTES or not line.startswith(prefix):
        raise _fail("the version line")
    words = line[len(prefix) :].split(b" ", 1)[0]
    numbers: list[int] = []
    for part in words.split(b".")[:3]:
        if not part.isdigit() or len(part) > 6:
            break
        numbers.append(int(part))
    if len(numbers) < 2:
        raise _fail("the version number")
    while len(numbers) < 3:
        numbers.append(0)
    return (numbers[0], numbers[1], numbers[2])


def version_is_supported(version: tuple[int, int, int]) -> bool:
    return version >= MIN_GIT_VERSION


def describe_version(version: tuple[int, int, int]) -> str:
    return ".".join(str(part) for part in version)


# -- revisions given by the user ------------------------------------------------------------------


def _refuse_revision(reason: str, text: str) -> UsageError:
    shown = sanitize(text, max_chars=_SHOWN_CHARS)
    return UsageError(f"revision refused ({reason}): {shown}")


def validate_revision(text: str) -> str:
    """Accept only `[A-Za-z0-9][A-Za-z0-9._/-]{0,254}` without `..`, `//` or a trailing `/`, `.`
    or `.lock` (PLAN.md D2). No `@{`, `:`, `^`, `~`, spaces or leading dash is possible."""
    if not text:
        raise _refuse_revision("empty", text)
    if len(text) > MAX_REVISION_CHARS:
        raise _refuse_revision("too long", text)
    if not text.isascii():
        raise _refuse_revision("not ASCII", text)
    data = text.encode("ascii")
    if data[0] not in _ALNUM:
        raise _refuse_revision("must start with a letter or digit", text)
    if any(byte not in _REVISION_REST for byte in data):
        raise _refuse_revision("character not allowed", text)
    if ".." in text or "//" in text:
        raise _refuse_revision("contains .. or //", text)
    if text.endswith(("/", ".", ".lock")):
        raise _refuse_revision("ends with /, . or .lock", text)
    return text


def split_range(text: str) -> tuple[str, str]:
    """`A..B` into its two validated sides. Exactly one `..`, and a side may not hold another."""
    left, separator, right = text.partition("..")
    if not separator:
        raise _refuse_revision("a range is written A..B", text)
    return validate_revision(left), validate_revision(right)


# -- object ids ----------------------------------------------------------------------------------


def is_object_id(data: bytes) -> bool:
    return len(data) in _ID_LENGTHS and all(byte in _HEX for byte in data)


def require_object_id(text: str) -> str:
    """A full object id (40 or 64 lower-case hex digits), else `GitOutputError`."""
    if not is_object_id(text.encode("ascii", "replace")):
        raise _fail("an object id")
    return text


def parse_rev_parse_id(output: bytes) -> str:
    """The single object id `rev-parse --verify` prints."""
    line = output.rstrip(b"\n")
    if b"\n" in line or not is_object_id(line):
        raise _fail("a resolved revision")
    return line.decode("ascii")


def parse_boolean_line(output: bytes) -> bool:
    """`true` or `false` (what `rev-parse --is-shallow-repository` prints)."""
    line = output.rstrip(b"\n")
    if line == b"true":
        return True
    if line == b"false":
        return False
    raise _fail("a true/false answer")


def parse_single_line_path(output: bytes) -> str:
    """The one path line of `rev-parse --absolute-git-dir`."""
    line = output.rstrip(b"\r\n")
    if not line or b"\n" in line or b"\x00" in line:
        raise _fail("a directory name")
    return line.decode("utf-8", errors="surrogateescape")


# -- the history stream ----------------------------------------------------------------------------


@dataclass(frozen=True, slots=True)
class CommitHeader:
    oid: str
    parents: tuple[str, ...]
    time: int


@dataclass(frozen=True, slots=True)
class DiffEntry:
    """One added, modified or type-changed path of a commit (against its first parent)."""

    status: str
    old_mode: str
    new_mode: str
    old_oid: str
    new_oid: str
    path: bytes


LogToken = CommitHeader | DiffEntry


def _decode_ascii(data: bytes, what: str) -> str:
    try:
        return data.decode("ascii")
    except UnicodeDecodeError:
        raise _fail(what) from None


def _parse_header(token: bytes, id_length: int | None) -> tuple[CommitHeader, int]:
    fields = token[1:].split(b" ")
    if len(fields) < 3 or not is_object_id(fields[0]):
        raise _fail("a commit header")
    length = len(fields[0])
    if id_length is not None and length != id_length:
        raise _fail("object ids of two different lengths")
    parents = fields[1:-1]
    # A root commit prints an empty parent field (two spaces), which splits into one empty entry.
    if parents == [b""]:
        parents = []
    if any(len(parent) != length or not is_object_id(parent) for parent in parents):
        raise _fail("a parent id")
    stamp = fields[-1]
    if not stamp.isdigit() or len(stamp) > 12:
        raise _fail("a commit time")
    return (
        CommitHeader(
            _decode_ascii(fields[0], "a commit id"),
            tuple(_decode_ascii(parent, "a parent id") for parent in parents),
            int(stamp),
        ),
        length,
    )


def _valid_mode(mode: bytes) -> bool:
    return len(mode) == 6 and all(byte in _OCTAL for byte in mode)


def _parse_raw(token: bytes, id_length: int | None) -> tuple[tuple[str, str, str, str, str], int]:
    body = token[1:]  # drop ':'
    fields = body.split(b" ")
    if len(fields) != 5:
        raise _fail("a raw diff record")
    old_mode, new_mode, old_oid, new_oid, status = fields
    if not _valid_mode(old_mode) or not _valid_mode(new_mode):
        raise _fail("a file mode")
    if not is_object_id(old_oid) or not is_object_id(new_oid):
        raise _fail("an object id in a diff record")
    length = len(new_oid)
    if len(old_oid) != length or (id_length is not None and length != id_length):
        raise _fail("object ids of two different lengths")
    if len(status) != 1 or status.decode("ascii", "replace") not in _ALLOWED_STATUSES:
        raise _fail("a change status")
    return (
        (
            _decode_ascii(old_mode, "a file mode"),
            _decode_ascii(new_mode, "a file mode"),
            _decode_ascii(old_oid, "an object id"),
            _decode_ascii(new_oid, "an object id"),
            status.decode("ascii"),
        ),
        length,
    )


class LogParser:
    """Incremental parser of the `log --raw -z` stream. Feed chunks, iterate the tokens; call
    `finish()` at the end of the stream to fail on a truncated record."""

    def __init__(self) -> None:
        self._buffer = bytearray()
        self._pending: tuple[str, str, str, str, str] | None = None  # raw record awaiting its path
        self._seen_header = False
        self._id_length: int | None = None

    def feed(self, chunk: bytes) -> Iterator[LogToken]:
        self._buffer += chunk
        start = 0
        while True:
            end = self._buffer.find(b"\x00", start)
            if end < 0:
                break
            yield from self._token(bytes(self._buffer[start:end]))
            start = end + 1
        del self._buffer[:start]
        if len(self._buffer) > MAX_TOKEN_BYTES:
            raise _fail("a record longer than the limit")

    def _token(self, token: bytes) -> Iterator[LogToken]:
        if self._pending is not None:
            old_mode, new_mode, old_oid, new_oid, status = self._pending
            self._pending = None
            if not token:
                raise _fail("an empty path")
            yield DiffEntry(status, old_mode, new_mode, old_oid, new_oid, token)
            return
        if token[:1] == b"\n":
            token = token[1:]
        if token[:1] == bytes([HEADER_MARK]):
            header, self._id_length = _parse_header(token, self._id_length)
            self._seen_header = True
            yield header
            return
        if token[:1] == b":" and self._seen_header:
            self._pending, self._id_length = _parse_raw(token, self._id_length)
            return
        raise _fail("a record in the history stream")

    def finish(self) -> None:
        if self._pending is not None or self._buffer:
            raise _fail("the history stream ended inside a record")


# -- cat-file ------------------------------------------------------------------------------------


@dataclass(frozen=True, slots=True)
class ObjectInfo:
    """One answer of `cat-file --batch-check` or the header of `--batch`. `size` is None and
    `kind` is `missing` when the object is not in the repository."""

    oid: str
    kind: str
    size: int | None


def parse_object_line(line: bytes, expected_oid: str) -> ObjectInfo:
    """`<oid> <type> <size>` or `<oid> missing`, for the object that was asked for."""
    fields = line.rstrip(b"\n").split(b" ")
    if not fields or _decode_ascii(fields[0], "an object id") != expected_oid:
        raise _fail("an object answer for another object")
    if len(fields) == 2 and fields[1] == b"missing":
        return ObjectInfo(expected_oid, "missing", None)
    if len(fields) != 3:
        raise _fail("an object answer")
    kind, size = fields[1], fields[2]
    if kind not in {b"blob", b"tree", b"commit", b"tag"}:
        raise _fail("an object type")
    if not size.isdigit() or len(size) > MAX_SIZE_DIGITS:
        raise _fail("an object size")
    return ObjectInfo(expected_oid, kind.decode("ascii"), int(size))


# -- ls-files ------------------------------------------------------------------------------------


def parse_nul_paths(output: bytes) -> list[bytes]:
    """The paths of `ls-files -z`: NUL-terminated, none empty, none containing a line feed that
    would show a broken record. Duplicates (a path listed once per merge stage) are kept out."""
    if output and not output.endswith(b"\x00"):
        raise _fail("a path list that ends inside a record")
    seen: dict[bytes, None] = {}
    for path in output.split(b"\x00")[:-1]:
        if not path:
            raise _fail("an empty path")
        seen[path] = None
    return list(seen)


# -- failures --------------------------------------------------------------------------------------


class FailureKind(StrEnum):
    DUBIOUS_OWNERSHIP = "dubious_ownership"
    NOT_A_REPOSITORY = "not_a_repository"
    OTHER = "other"


def classify_failure(stderr: bytes) -> FailureKind:
    """What git's error text says, from the few fixed phrases that matter. The text itself is
    never shown (it can hold paths); `summarize_stderr` is the display form."""
    text = stderr.lower()
    if b"dubious ownership" in text:
        return FailureKind.DUBIOUS_OWNERSHIP
    if b"not a git repository" in text:
        return FailureKind.NOT_A_REPOSITORY
    return FailureKind.OTHER


def summarize_stderr(stderr: bytes, max_chars: int = 200) -> str:
    """The first line of git's error output, escaped and bounded, for an error message."""
    first = stderr.decode("utf-8", errors="surrogateescape").strip().splitlines()
    return sanitize(first[0] if first else "(no error output)", max_chars=max_chars)
