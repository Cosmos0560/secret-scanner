"""The strict git output parsers (`core/gitparse.py`): grammar, framing, fail-closed cases."""

from __future__ import annotations

import pytest

from secret_scanner.core.errors import GitError, UsageError
from secret_scanner.core.gitparse import (
    HEADER_MARK,
    MAX_TOKEN_BYTES,
    MIN_GIT_VERSION,
    CommitHeader,
    DiffEntry,
    FailureKind,
    GitOutputError,
    LogParser,
    classify_failure,
    describe_version,
    is_object_id,
    parse_boolean_line,
    parse_git_version,
    parse_nul_paths,
    parse_object_line,
    parse_rev_parse_id,
    parse_single_line_path,
    require_object_id,
    split_range,
    summarize_stderr,
    validate_revision,
    version_is_supported,
)

NUL = b"\x00"
LF = chr(10).encode()
MARK = bytes([HEADER_MARK])
ZERO = "0" * 40


def oid(number: int, length: int = 40) -> str:
    return f"{number:0{length}x}"


def header(commit: str, parents: tuple[str, ...] = (), stamp: int = 1_767_225_600) -> bytes:
    return MARK + " ".join([commit, " ".join(parents), str(stamp)]).encode() + NUL


def raw(
    status: str, old: str, new: str, old_mode: str = "100644", new_mode: str = "100644"
) -> bytes:
    return f":{old_mode} {new_mode} {old} {new} {status}".encode()


def stream(*records: bytes) -> bytes:
    return b"".join(records)


def parse_all(data: bytes, chunk: int | None = None) -> list[object]:
    parser = LogParser()
    tokens: list[object] = []
    pieces = [data] if chunk is None else [data[i : i + chunk] for i in range(0, len(data), chunk)]
    for piece in pieces:
        tokens.extend(parser.feed(piece))
    parser.finish()
    return tokens


# -- versions ------------------------------------------------------------------------------------


@pytest.mark.parametrize(
    ("text", "expected"),
    [
        (b"git version 2.54.0.windows.1" + LF, (2, 54, 0)),
        (b"git version 2.43.0" + LF, (2, 43, 0)),
        (b"git version 2.32" + LF, (2, 32, 0)),
        (b"git version 2.39.5 (Apple Git-154)" + LF, (2, 39, 5)),
        (b"git version 2.50.1.vfs.0.0" + LF, (2, 50, 1)),
        (b"git version 10.0.0" + LF, (10, 0, 0)),
    ],
)
def test_version_lines(text: bytes, expected: tuple[int, int, int]) -> None:
    assert parse_git_version(text) == expected


@pytest.mark.parametrize(
    "text",
    [
        b"",
        b"git version" + LF,
        b"git version x.y.z" + LF,
        b"git version 2" + LF,
        b"git version 2.x" + LF,
        b"hg version 2.40.0" + LF,
        b"fatal: not a git repository" + LF,
        b"git version 2.40.0 " + b"x" * 300,
        b"\xff\xfegit version 2.40.0",
    ],
)
def test_version_lines_that_are_not_versions_fail_closed(text: bytes) -> None:
    with pytest.raises(GitError):
        parse_git_version(text)


def test_minimum_version_is_the_one_in_the_plan() -> None:
    assert MIN_GIT_VERSION == (2, 32, 0)  # PLAN.md D2
    assert version_is_supported((2, 32, 0))
    assert version_is_supported((2, 54, 1))
    assert version_is_supported((3, 0, 0))
    assert not version_is_supported((2, 31, 9))
    assert not version_is_supported((1, 99, 0))
    assert describe_version((2, 32, 0)) == "2.32.0"


# -- revisions given by the user ---------------------------------------------------------------


@pytest.mark.parametrize(
    "revision",
    ["main", "HEAD", "v1.2.3", "feature/x-1", "release_2026", "a", "refs/heads/main", "A" * 255],
)
def test_valid_revisions(revision: str) -> None:
    assert validate_revision(revision) == revision


INJECTION_TABLE = [
    ("--output=x", "leading dash"),
    ("-c x", "leading dash and space"),
    ("-", "dash"),
    ("--upload-pack=cmd", "option"),
    ("@{-1}", "reflog syntax"),
    ("HEAD@{1}", "reflog entry"),
    ("a:b", "colon"),
    ("main:path", "colon path"),
    (":/message", "commit message search"),
    ("HEAD~1", "ancestor"),
    ("HEAD^", "parent"),
    ("HEAD^{tree}", "peel"),
    ("a b", "space"),
    ("a\tb", "tab"),
    ("a" + chr(10) + "b", "newline"),
    ("a" + chr(0) + "b", "nul"),
    ("", "empty"),
    ("a" * 256, "over-long"),
    ("a..b", "inner range dots"),
    ("a//b", "double slash"),
    ("main/", "trailing slash"),
    ("main.", "trailing dot"),
    ("main.lock", "lock suffix"),
    ("/main", "leading slash"),
    (".hidden", "leading dot"),
    ("caf" + chr(0xE9), "non-ascii"),
    ("a*b", "glob"),
    ("a?b", "glob"),
    ("a[b]", "glob"),
    ("a\\b", "backslash"),
    ("$(x)", "substitution"),
    ("a;b", "semicolon"),
    ("a|b", "pipe"),
]


@pytest.mark.parametrize(
    ("revision", "label"), INJECTION_TABLE, ids=[row[1] for row in INJECTION_TABLE]
)
def test_revision_injection_table(revision: str, label: str) -> None:
    with pytest.raises(UsageError):
        validate_revision(revision)


def test_a_refused_revision_is_shown_escaped_and_bounded() -> None:
    hostile = chr(0x1B) + "[31m" + "x" * 500
    with pytest.raises(UsageError) as caught:
        validate_revision(hostile)
    assert chr(0x1B) not in str(caught.value)
    assert len(str(caught.value)) < 300


def test_ranges() -> None:
    assert split_range("v1..main") == ("v1", "main")
    assert split_range("a/b..c-d") == ("a/b", "c-d")


@pytest.mark.parametrize(
    "text",
    ["main", "a...b", "a..", "..b", "a..b..c", "-x..b", "a..-x", "a..b:c", "a b..c", ""],
)
def test_range_negatives(text: str) -> None:
    with pytest.raises(UsageError):
        split_range(text)


# -- object ids and small answers -----------------------------------------------------------------


def test_object_ids() -> None:
    assert is_object_id(oid(1).encode())
    assert is_object_id(oid(1, 64).encode())
    for bad in (b"", b"a" * 39, b"a" * 41, b"A" * 40, b"g" * 40, b"a" * 63, b"a" * 65):
        assert not is_object_id(bad)
    assert require_object_id(oid(7)) == oid(7)
    with pytest.raises(GitError):
        require_object_id("xyz")


def test_rev_parse_answers() -> None:
    assert parse_rev_parse_id(oid(5).encode() + LF) == oid(5)
    for bad in (b"", oid(5).encode() + LF + oid(6).encode() + LF, b"HEAD" + LF, b"a" * 41 + LF):
        with pytest.raises(GitError):
            parse_rev_parse_id(bad)


def test_boolean_lines() -> None:
    assert parse_boolean_line(b"true" + LF) is True
    assert parse_boolean_line(b"false" + LF) is False
    for bad in (b"", b"yes" + LF, b"True" + LF, b"true false" + LF):
        with pytest.raises(GitError):
            parse_boolean_line(bad)


def test_single_line_paths() -> None:
    assert parse_single_line_path(b"/a/b/.git" + LF) == "/a/b/.git"
    assert parse_single_line_path(b"C:/a/.git\r\n") == "C:/a/.git"
    assert parse_single_line_path(b"/caf\xc3\xa9/.git" + LF) == "/caf" + chr(0xE9) + "/.git"
    for bad in (b"", LF, b"/a" + LF + b"/b" + LF, b"/a" + NUL):
        with pytest.raises(GitError):
            parse_single_line_path(bad)


# -- the history stream: valid ------------------------------------------------------------


def test_a_simple_history() -> None:
    data = stream(
        header(oid(1)),
        LF + raw("A", ZERO, oid(11)) + NUL + b"a.txt" + NUL,
        raw("A", ZERO, oid(12)) + NUL + b"d/b c.txt" + NUL,
        header(oid(2), (oid(1),)),
        LF + raw("M", oid(11), oid(13)) + NUL + b"a.txt" + NUL,
    )
    tokens = parse_all(data)
    assert tokens == [
        CommitHeader(oid(1), (), 1_767_225_600),
        DiffEntry("A", "100644", "100644", ZERO, oid(11), b"a.txt"),
        DiffEntry("A", "100644", "100644", ZERO, oid(12), b"d/b c.txt"),
        CommitHeader(oid(2), (oid(1),), 1_767_225_600),
        DiffEntry("M", "100644", "100644", oid(11), oid(13), b"a.txt"),
    ]


def test_commits_without_changes_and_merges() -> None:
    data = stream(
        header(oid(1)),
        header(oid(2), (oid(1),)),
        header(oid(3), (oid(1), oid(2))),
        LF + raw("A", ZERO, oid(11)) + NUL + b"s.txt" + NUL,
    )
    tokens = parse_all(data)
    assert [t.oid for t in tokens if isinstance(t, CommitHeader)] == [oid(1), oid(2), oid(3)]
    assert tokens[2] == CommitHeader(oid(3), (oid(1), oid(2)), 1_767_225_600)
    assert isinstance(tokens[3], DiffEntry)


def test_an_empty_stream_is_a_valid_empty_history() -> None:
    assert parse_all(b"") == []


def test_sha256_repositories() -> None:
    zero = "0" * 64
    data = stream(header(oid(1, 64)), LF + raw("A", zero, oid(9, 64)) + NUL + b"x" + NUL)
    tokens = parse_all(data)
    assert tokens[0] == CommitHeader(oid(1, 64), (), 1_767_225_600)
    assert isinstance(tokens[1], DiffEntry)


@pytest.mark.parametrize("chunk", [1, 2, 3, 7, 16, 64])
def test_chunk_boundaries_do_not_matter(chunk: int) -> None:
    data = stream(
        header(oid(1)),
        LF + raw("A", ZERO, oid(11)) + NUL + b"a" + chr(0xE9).encode("utf-8") + b".txt" + NUL,
        header(oid(2), (oid(1),)),
        LF + raw("T", oid(11), oid(12), "100644", "100755") + NUL + b"b" + NUL,
    )
    assert parse_all(data, chunk) == parse_all(data)


def test_a_path_is_read_by_position_whatever_it_holds() -> None:
    hostile = [
        b":000000 100644 "
        + ZERO.encode()
        + b" "
        + oid(9).encode()
        + b" A",  # looks like a raw record
        MARK + b"fake header",
        LF + b":fake",
        b"with space",
        b"with" + LF + b"newline",
        b"\xff\xfe invalid utf-8",
        b"..",
    ]
    for path in hostile:
        data = stream(header(oid(1)), LF + raw("A", ZERO, oid(11)) + NUL + path + NUL)
        tokens = parse_all(data)
        assert tokens[1] == DiffEntry("A", "100644", "100644", ZERO, oid(11), path)


@pytest.mark.parametrize("status", ["A", "M", "T"])
def test_allowed_statuses(status: str) -> None:
    data = stream(header(oid(1)), LF + raw(status, oid(10), oid(11)) + NUL + b"p" + NUL)
    assert isinstance(parse_all(data)[1], DiffEntry)


@pytest.mark.parametrize("mode", ["100644", "100755", "120000", "160000", "100664", "000000"])
def test_modes_are_passed_through_for_the_scanner_to_decide(mode: str) -> None:
    data = stream(
        header(oid(1)), LF + raw("T", oid(10), oid(11), "100644", mode) + NUL + b"p" + NUL
    )
    entry = parse_all(data)[1]
    assert isinstance(entry, DiffEntry)
    assert entry.new_mode == mode


# -- the history stream: fail closed ---------------------------------------------------------------


def _fails(data: bytes) -> None:
    with pytest.raises(GitOutputError):
        parse_all(data)


def test_truncated_streams() -> None:
    full = stream(header(oid(1)), LF + raw("A", ZERO, oid(11)) + NUL + b"a.txt" + NUL)
    for cut in range(1, len(full)):
        prefix = full[:cut]
        if prefix.endswith(NUL) and prefix.count(NUL) in (1, 3):
            continue  # a complete header, or a complete header and entry, is a valid prefix
        _fails(prefix)


def test_a_raw_record_without_its_path_is_truncated() -> None:
    _fails(stream(header(oid(1)), LF + raw("A", ZERO, oid(11)) + NUL))


def test_a_header_where_the_path_belongs_is_a_path_not_a_header() -> None:
    # positional: the token after a raw record is the path, even when it looks like a header
    data = stream(header(oid(1)), LF + raw("A", ZERO, oid(11)) + NUL + MARK + b"x" + NUL)
    tokens = parse_all(data)
    assert isinstance(tokens[1], DiffEntry)
    assert tokens[1].path == MARK + b"x"


BAD_HEADERS = [
    ("short id", MARK + b"abc " + b" 1767225600"),
    ("upper-case id", MARK + b"A" * 40 + b"  1767225600"),
    ("no time", MARK + oid(1).encode() + b" "),
    ("non-numeric time", MARK + oid(1).encode() + b"  yesterday"),
    ("huge time", MARK + oid(1).encode() + b"  " + b"9" * 20),
    ("short parent", MARK + oid(1).encode() + b" abc 1767225600"),
    ("mixed lengths", MARK + oid(1).encode() + b" " + oid(2, 64).encode() + b" 1767225600"),
    ("only an id", MARK + oid(1).encode()),
    ("empty", MARK),
]


@pytest.mark.parametrize(("label", "token"), BAD_HEADERS, ids=[row[0] for row in BAD_HEADERS])
def test_bad_headers(label: str, token: bytes) -> None:
    _fails(token + NUL)


BAD_RAW = [
    ("bad old mode", b":10064 100644 %s %s A" % (ZERO.encode(), oid(1).encode())),
    ("non-octal mode", b":100649 100644 %s %s A" % (ZERO.encode(), oid(1).encode())),
    ("too few fields", b":100644 100644 %s A" % oid(1).encode()),
    ("too many fields", b":100644 100644 %s %s A extra" % (ZERO.encode(), oid(1).encode())),
    ("short old id", b":100644 100644 abc %s A" % oid(1).encode()),
    ("short new id", b":100644 100644 %s abc A" % ZERO.encode()),
    ("mixed id lengths", b":100644 100644 %s %s A" % (ZERO.encode(), oid(1, 64).encode())),
    ("deleted", b":100644 000000 %s %s D" % (oid(1).encode(), ZERO.encode())),
    ("renamed", b":100644 100644 %s %s R100" % (oid(1).encode(), oid(2).encode())),
    ("copied", b":100644 100644 %s %s C75" % (oid(1).encode(), oid(2).encode())),
    ("unmerged", b":100644 100644 %s %s U" % (oid(1).encode(), oid(2).encode())),
    ("unknown status", b":100644 100644 %s %s X" % (oid(1).encode(), oid(2).encode())),
    ("lower-case status", b":100644 100644 %s %s a" % (oid(1).encode(), oid(2).encode())),
    ("empty status", b":100644 100644 %s %s " % (oid(1).encode(), oid(2).encode())),
    ("combined status", b":100644 100644 %s %s AM" % (oid(1).encode(), oid(2).encode())),
]


@pytest.mark.parametrize(("label", "token"), BAD_RAW, ids=[row[0] for row in BAD_RAW])
def test_bad_raw_records(label: str, token: bytes) -> None:
    _fails(stream(header(oid(1)), LF + token + NUL + b"p" + NUL))


def test_a_raw_record_before_any_header() -> None:
    _fails(raw("A", ZERO, oid(1)) + NUL + b"p" + NUL)


def test_unexpected_tokens() -> None:
    _fails(stream(header(oid(1)), b"garbage" + NUL))
    _fails(stream(header(oid(1)), NUL))
    _fails(stream(header(oid(1)), b"commit " + oid(1).encode() + NUL))


def test_an_empty_path_is_refused() -> None:
    _fails(stream(header(oid(1)), LF + raw("A", ZERO, oid(11)) + NUL + NUL))


def test_a_record_longer_than_the_limit_is_refused_while_it_is_buffered() -> None:
    parser = LogParser()
    with pytest.raises(GitOutputError):
        for _ in parser.feed(b"x" * (MAX_TOKEN_BYTES + 1)):
            pass


def test_mixed_object_id_lengths_across_the_stream() -> None:
    _fails(stream(header(oid(1)), header(oid(2, 64))))


# -- cat-file ------------------------------------------------------------------------------------


def test_object_lines() -> None:
    wanted = oid(3)
    info = parse_object_line(f"{wanted} blob 12".encode() + LF, wanted)
    assert (info.kind, info.size) == ("blob", 12)
    missing = parse_object_line(f"{wanted} missing".encode() + LF, wanted)
    assert (missing.kind, missing.size) == ("missing", None)
    assert parse_object_line(f"{wanted} commit 0".encode() + LF, wanted).kind == "commit"


@pytest.mark.parametrize(
    "line",
    [
        b"",
        LF,
        b"%s blob" % oid(3).encode(),
        b"%s blob x" % oid(3).encode(),
        b"%s blob -1" % oid(3).encode(),
        b"%s blob 1 2" % oid(3).encode(),
        b"%s widget 1" % oid(3).encode(),
        b"%s ambiguous" % oid(3).encode(),
        b"%s blob %s" % (oid(3).encode(), b"9" * 40),
        b"%s blob 1" % oid(4).encode(),
        b"short blob 1",
    ],
)
def test_bad_object_lines(line: bytes) -> None:
    with pytest.raises(GitError):
        parse_object_line(line, oid(3))


# -- ls-files ------------------------------------------------------------------------------------


def test_nul_path_lists() -> None:
    assert parse_nul_paths(b"") == []
    assert parse_nul_paths(b"a" + NUL + b"d/b" + NUL) == [b"a", b"d/b"]
    assert parse_nul_paths(b"a" + NUL + b"a" + NUL) == [b"a"]
    assert parse_nul_paths(b"x" + LF + b"y" + NUL) == [b"x" + LF + b"y"]


@pytest.mark.parametrize("data", [b"a", b"a" + NUL + b"b", NUL, b"a" + NUL + NUL])
def test_bad_nul_path_lists(data: bytes) -> None:
    with pytest.raises(GitError):
        parse_nul_paths(data)


# -- failures ------------------------------------------------------------------------------------


def test_failure_classification() -> None:
    owner = b"fatal: detected dubious ownership in repository at 'C:/x'" + LF
    assert classify_failure(owner) is FailureKind.DUBIOUS_OWNERSHIP
    assert (
        classify_failure(b"fatal: not a git repository (or any of the parent directories): .git")
        is FailureKind.NOT_A_REPOSITORY
    )
    assert classify_failure(b"fatal: bad object HEAD") is FailureKind.OTHER
    assert classify_failure(b"") is FailureKind.OTHER


def test_stderr_summary_is_one_escaped_bounded_line() -> None:
    hostile = b"fatal: " + chr(0x1B).encode() + b"[31m" + b"y" * 400 + LF + b"second line" + LF
    shown = summarize_stderr(hostile)
    assert chr(0x1B) not in shown
    assert "second line" not in shown
    assert len(shown) <= 200
    assert summarize_stderr(b"") == "(no error output)"
    assert summarize_stderr(b"\xff\xfe bad bytes") != ""
