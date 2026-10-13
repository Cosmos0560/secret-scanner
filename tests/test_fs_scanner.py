"""The directory scanner service: findings with exact locations, every issue kind, the time
budget, the report cap, and the proof that scanning only reads (CLAUDE.md section 5, 1 and 3)."""

from __future__ import annotations

import hashlib
import os
import stat
from collections.abc import Callable
from dataclasses import replace
from pathlib import Path

import pytest

from secret_scanner.core.detect.entropy import EntropyConfig
from secret_scanner.core.entries import EntryKind, classify_stat
from secret_scanner.core.errors import UsageError
from secret_scanner.core.fakes import build_fake, fake_entropy_token, fake_private_key
from secret_scanner.core.fingerprint import fingerprint
from secret_scanner.core.limits import DEFAULT_LIMITS, Limits
from secret_scanner.core.models import Confidence, IssueKind, Rule, ScanStats, Severity
from secret_scanner.fs import walk
from secret_scanner.fs.walk import ReadFailure, SkipReason, read_regular_file
from secret_scanner.services import fs_scanner
from secret_scanner.services.fs_scanner import ScanResult, ScanSettings, scan_tree
from secret_scanner.services.loader import load_builtin_rules
from tests.helpers import FakeClock

RULES = {rule.id: rule for rule in load_builtin_rules().rules}
ALL_RULES = tuple(RULES.values())


def fake(rule_id: str, seed: str = "scan") -> str:
    return build_fake(RULES[rule_id], seed)


def scan(
    root: Path,
    *,
    limits: Limits = DEFAULT_LIMITS,
    entropy: bool = False,
    exclude: tuple[str, ...] = (),
    default_excludes: bool = True,
    clock: FakeClock | None = None,
    reader: Callable[[str, os.stat_result, int], bytes | ReadFailure] | None = None,
    rules: tuple[Rule, ...] = ALL_RULES,
) -> ScanResult:
    settings = ScanSettings(
        rules=rules,
        entropy=EntropyConfig(enabled=entropy),
        limits=limits,
        exclude_globs=exclude,
        default_excludes=default_excludes,
    )
    return scan_tree(str(root), settings, clock or FakeClock(), reader)


@pytest.fixture
def root(tmp_path: Path) -> Path:
    directory = tmp_path / "tree"
    directory.mkdir()
    return directory


def put(root: Path, relative: str, content: str | bytes) -> None:
    path = root / relative
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(content if isinstance(content, bytes) else content.encode("utf-8"))


# -- findings ---------------------------------------------------------------------------------


def test_findings_have_exact_locations_fingerprints_and_no_secret(
    root: Path, assert_not_leaked: Callable[..., None]
) -> None:
    token = fake("npm-token")
    aws = fake("aws-access-key-id")
    put(root, "src/app.py", f"x = 1\nTOKEN = '{token}'\n")
    put(root, "conf/.env", f"AWS={aws}\n")
    result = scan(root)
    assert result.complete
    assert result.truncated is False
    by_path = {f.location.path_key: f for f in result.findings}
    assert set(by_path) == {"src/app.py", "conf/.env"}
    npm = by_path["src/app.py"]
    assert (npm.rule_id, npm.severity, npm.confidence) == (
        "npm-token",
        Severity.HIGH,
        Confidence.HIGH,
    )
    assert (npm.location.line, npm.location.column) == (2, 10)
    assert npm.location.end_column == 10 + len(token)
    assert npm.fingerprint == fingerprint("npm-token", "src/app.py", token.encode())
    assert npm.redacted.length == len(token)
    for text in (repr(result), str(result.findings)):
        assert_not_leaked(text, token, allowed_shown=len("npm_"))
        assert_not_leaked(text, aws, allowed_shown=len("AKIA"))
    assert result.stats.files_scanned == 2
    assert result.stats.bytes_scanned == sum((root / p).stat().st_size for p in by_path)


def test_findings_are_sorted_by_path_line_column(root: Path) -> None:
    token = fake("npm-token")
    put(root, "b.txt", f"{token}\n")
    put(root, "a.txt", f"\n\n{token} {token}\n")
    result = scan(root)
    assert [(f.location.path_key, f.location.line, f.location.column) for f in result.findings] == [
        ("a.txt", 3, 1),
        ("a.txt", 3, 1 + len(token) + 1),
        ("b.txt", 1, 1),
    ]


def test_the_same_secret_in_two_files_has_two_fingerprints(root: Path) -> None:
    token = fake("npm-token")
    put(root, "a.txt", token)
    put(root, "b.txt", token)
    result = scan(root)
    assert len({f.fingerprint for f in result.findings}) == 2


def test_a_clean_tree_is_complete_with_statistics(root: Path) -> None:
    put(root, "readme.md", "# hello\n")
    put(root, "pkg/mod.py", "print('x')\n")
    put(root, "empty.txt", "")
    result = scan(root)
    assert result.findings == ()
    assert result.complete
    assert result.stats.files_seen == 3
    assert result.stats.files_scanned == 3


def test_private_key_and_entropy_detectors_run_through_the_service(root: Path) -> None:
    put(root, "key.pem.txt", fake_private_key("svc", label="RSA"))
    put(root, "app.cfg", f"api_token = {fake_entropy_token('svc')}\n")
    without = scan(root, entropy=False)
    assert {f.rule_id for f in without.findings} == {"private-key"}
    with_entropy = scan(root, entropy=True)
    assert {f.rule_id for f in with_entropy.findings} == {"private-key", "entropy-base64"}


def test_the_entropy_detector_skips_lockfiles_but_rules_still_apply(root: Path) -> None:
    token = fake_entropy_token("lock")
    npm = fake("npm-token", "lock")
    put(root, "package-lock.json", f'{{"api_token": "{token}", "x": "{npm}"}}\n')
    put(root, "settings.cfg", f"api_token = {token}\n")
    result = scan(root, entropy=True)
    pairs = {(f.location.path_key, f.rule_id) for f in result.findings}
    assert pairs == {
        ("package-lock.json", "npm-token"),
        ("settings.cfg", "entropy-base64"),
    }


# -- skips and kinds --------------------------------------------------------------------------


def test_binary_and_default_excluded_content_is_counted_not_scanned(root: Path) -> None:
    token = fake("npm-token")
    put(root, "blob.bin", b"\x00\x01" + token.encode())
    put(root, ".git/config", token)
    put(root, "node_modules/x.js", token)
    put(root, "ok.txt", "nothing")
    result = scan(root)
    assert result.findings == ()
    assert result.complete  # binary files and excluded trees are not issues
    assert result.stats.skipped_binary == 1
    assert result.stats.skipped_excluded == 2
    assert result.stats.files_seen == 2


_SKIP_FIELDS = {
    SkipReason.SYMLINK: "skipped_symlink",
    SkipReason.OFFLINE: "skipped_offline",
    SkipReason.SPECIAL: "skipped_special",
    SkipReason.EXCLUDED: "skipped_excluded",
}


@pytest.mark.parametrize("reason", list(SkipReason), ids=lambda reason: reason.value)
def test_each_skip_reason_increments_exactly_its_own_counter(reason: SkipReason) -> None:
    counted = fs_scanner._count_skip(ScanStats(), reason)
    expected = dict.fromkeys(_SKIP_FIELDS.values(), 0)
    expected[_SKIP_FIELDS[reason]] = 1
    assert {name: getattr(counted, name) for name in expected} == expected
    # nothing else moves, and the counter adds up across calls
    assert replace(counted, **{_SKIP_FIELDS[reason]: 0}) == ScanStats()
    assert getattr(fs_scanner._count_skip(counted, reason), _SKIP_FIELDS[reason]) == 2


def test_the_skip_reasons_are_all_counted_by_the_table() -> None:
    assert set(_SKIP_FIELDS) == set(SkipReason)


@pytest.mark.requires_symlinks
def test_links_are_counted_and_never_followed(
    root: Path, assert_not_leaked: Callable[..., None]
) -> None:
    token = fake("npm-token")
    put(root, "real/secret.txt", token)
    (root / "file-link").symlink_to(root / "real" / "secret.txt")
    (root / "dir-link").symlink_to(root / "real", target_is_directory=True)
    result = scan(root)
    assert [f.location.path_key for f in result.findings] == ["real/secret.txt"]
    assert result.stats.skipped_symlink == 2
    assert result.stats.files_scanned == 1
    assert result.complete  # a skipped link is counted, not an issue
    assert_not_leaked(repr(result), token, allowed_shown=len("npm_"))


def test_offline_and_special_entries_are_counted_and_never_opened(
    root: Path, monkeypatch: pytest.MonkeyPatch, assert_not_leaked: Callable[..., None]
) -> None:
    token = fake("npm-token")
    put(root, "offline.txt", "o" * 11)
    put(root, "special.txt", "s" * 7)
    put(root, "plain.txt", token)
    real = classify_stat

    def classify(info: os.stat_result, *, windows: bool) -> EntryKind:
        # Files are told apart by size; the root directory and `plain.txt` keep their real kind.
        if stat.S_ISREG(info.st_mode) and info.st_size == 11:
            return EntryKind.OFFLINE
        if stat.S_ISREG(info.st_mode) and info.st_size == 7:
            return EntryKind.SPECIAL
        return real(info, windows=windows)

    opened: list[str] = []

    def reader(path: str, info: os.stat_result, maximum: int) -> bytes | ReadFailure:
        opened.append(Path(path).name)
        return read_regular_file(path, info, maximum)

    monkeypatch.setattr(walk, "classify_stat", classify)
    result = scan(root, reader=reader)
    assert opened == ["plain.txt"]
    assert (result.stats.skipped_offline, result.stats.skipped_special) == (1, 1)
    assert result.stats.files_scanned == 1
    assert [f.location.path_key for f in result.findings] == ["plain.txt"]
    assert result.complete
    assert_not_leaked(repr(result), token, allowed_shown=len("npm_"))


def test_default_excludes_can_be_turned_off_and_config_excludes_apply(root: Path) -> None:
    token = fake("npm-token")
    put(root, "node_modules/x.js", token)
    put(root, "vendor/y.js", token)
    put(root, "src/z.js", token)
    assert {f.location.path_key for f in scan(root).findings} == {"vendor/y.js", "src/z.js"}
    assert {f.location.path_key for f in scan(root, exclude=("vendor/**",)).findings} == {
        "src/z.js"
    }
    everything = scan(root, default_excludes=False)
    assert {f.location.path_key for f in everything.findings} == {
        "node_modules/x.js",
        "vendor/y.js",
        "src/z.js",
    }


def test_utf16_with_a_byte_order_mark_is_decoded_and_scanned(root: Path) -> None:
    token = fake("npm-token")
    put(root, "wide.txt", b"\xff\xfe" + f"v = {token}\n".encode("utf-16-le"))
    result = scan(root)
    assert [(f.location.path_key, f.location.column) for f in result.findings] == [("wide.txt", 5)]


def test_an_undecodable_wide_file_is_an_issue_not_a_clean_result(root: Path) -> None:
    put(root, "broken.txt", b"\xff\xfe" + b"\x00\xd8")  # a lone high surrogate
    result = scan(root)
    assert not result.complete
    [issue] = result.issues
    assert (issue.kind, issue.path) == (IssueKind.UNDECODABLE, "broken.txt")


# -- issues and caps --------------------------------------------------------------------------


def test_a_too_long_line_is_cut_and_reported_but_its_start_is_scanned(root: Path) -> None:
    limits = replace(DEFAULT_LIMITS, max_line_bytes=200)
    token = fake("npm-token")
    put(root, "long.txt", f"{token}\n" + "x" * 500 + f"\n{token}\n")
    result = scan(root, limits=limits)
    assert [f.location.line for f in result.findings] == [1, 3]
    [issue] = result.issues
    assert (issue.kind, issue.path) == (IssueKind.LINE_TOO_LONG, "long.txt")
    assert "first is line 2" in issue.detail
    assert not result.complete


def test_the_per_file_match_cap_is_an_issue(root: Path) -> None:
    limits = replace(DEFAULT_LIMITS, max_findings_per_file=3)
    token = fake("npm-token")
    put(root, "many.txt", (token + "\n") * 10)
    result = scan(root, limits=limits)
    assert len(result.findings) == 3
    [issue] = result.issues
    assert (issue.kind, issue.path) == (IssueKind.FINDINGS_CAP, "many.txt")
    assert not result.complete


def test_the_report_cap_truncates_stops_and_marks_the_run_incomplete(root: Path) -> None:
    limits = replace(DEFAULT_LIMITS, max_findings=2)
    token = fake("npm-token")
    put(root, "a.txt", (token + "\n") * 5)
    put(root, "b.txt", token)
    result = scan(root, limits=limits)
    assert len(result.findings) == 2
    assert result.truncated
    assert not result.complete
    assert [i.kind for i in result.issues] == [IssueKind.FINDINGS_CAP]
    assert result.issues[0].path is None
    assert result.stats.files_scanned == 1  # the scan stopped; b.txt was never examined


def test_walker_problems_become_issues_and_the_rest_is_still_scanned(root: Path) -> None:
    limits = replace(DEFAULT_LIMITS, max_file_bytes=100)
    token = fake("npm-token")
    put(root, "big.txt", "x" * 101)
    put(root, "small.txt", token)
    result = scan(root, limits=limits)
    assert [f.location.path_key for f in result.findings] == ["small.txt"]
    [issue] = result.issues
    assert (issue.kind, issue.path) == (IssueKind.TOO_LARGE, "big.txt")
    assert not result.complete


def test_the_time_budget_stops_the_scan_with_an_issue_and_keeps_the_findings(root: Path) -> None:
    limits = replace(DEFAULT_LIMITS, max_run_seconds=100)
    clock = FakeClock()
    token = fake("npm-token")
    for name in ("a.txt", "b.txt", "c.txt", "d.txt"):
        put(root, name, token)

    def slow_reader(path: str, info: os.stat_result, maximum: int) -> bytes | ReadFailure:
        clock.advance(60)  # every file "takes" a minute
        return read_regular_file(path, info, maximum)

    result = scan(root, limits=limits, clock=clock, reader=slow_reader)
    assert [f.location.path_key for f in result.findings] == ["a.txt"]
    [issue] = result.issues
    assert issue.kind is IssueKind.TIME_BUDGET
    assert issue.path is None
    assert "100 seconds" in issue.detail
    assert not result.complete


def test_a_root_that_is_not_a_directory_is_refused(root: Path) -> None:
    put(root, "file.txt", "x")
    with pytest.raises(UsageError, match="not a directory"):
        scan(root / "file.txt")


# -- hostile names ----------------------------------------------------------------------------


def test_hostile_names_are_exact_in_the_key_and_escaped_for_display(root: Path) -> None:
    name = "a" + chr(0x202E) + "b" + chr(0x200B) + "c.txt"
    put(root, name, fake("npm-token"))
    [finding] = scan(root).findings
    assert finding.location.path_key == name
    assert finding.location.path == "a\\u202eb\\u200bc.txt"
    assert finding.fingerprint == fingerprint("npm-token", name, fake("npm-token").encode())


@pytest.mark.posix_only
def test_posix_only_hostile_names_are_escaped(root: Path) -> None:
    for name in ("new\nline.txt", "esc" + chr(0x1B) + "[31m.txt", os.fsdecode(b"bad\xff.txt")):
        put(root, name, fake("npm-token"))
    shown = sorted(f.location.path for f in scan(root).findings)
    assert shown == ["bad\\udcff.txt", "esc\\x1b[31m.txt", "new\\nline.txt"]


# -- read-only ----------------------------------------------------------------------------------


def snapshot(root: Path) -> dict[str, tuple[int, int, str]]:
    state: dict[str, tuple[int, int, str]] = {}
    for current, directories, files in os.walk(root):
        directories.sort()
        for name in sorted(files) + sorted(directories):
            path = Path(current) / name
            info = path.lstat()
            digest = "" if path.is_dir() else hashlib.sha256(path.read_bytes()).hexdigest()
            state[str(path.relative_to(root))] = (info.st_size, info.st_mtime_ns, digest)
    return state


def test_scanning_changes_nothing_in_the_tree(root: Path) -> None:
    token = fake("npm-token")
    put(root, "a.txt", token)
    put(root, "d/b.txt", "plain")
    put(root, ".git/HEAD", "ref")
    put(root, "blob.bin", b"\x00\x01\x02")
    (root / "empty-dir").mkdir()
    before = snapshot(root)
    first = scan(root, entropy=True)
    second = scan(root, entropy=True, default_excludes=False)
    assert snapshot(root) == before  # paths, sizes, mtimes and bytes
    assert first.findings
    assert second.findings
    assert sorted(os.listdir(root)) == sorted(
        [".git", "a.txt", "blob.bin", "d", "empty-dir"]
    )  # nothing was created, e.g. no cache or lock file
