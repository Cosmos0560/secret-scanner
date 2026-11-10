"""The `scan` use case: configuration merge, confidence filter, baseline round trip, staleness,
output safety and the exit-code decision (PLAN.md D9, D10; CLAUDE.md section 5)."""

from __future__ import annotations

import json
import os
import sys
from collections.abc import Callable
from pathlib import Path
from typing import Any

import pytest
import yaml

from secret_scanner.app.scan import ScanOutcome, ScanRequest, run_scan
from secret_scanner.core.errors import ConfigError, ExitCode, ScanIOError, UsageError
from secret_scanner.core.fakes import build_fake, fake_entropy_token
from secret_scanner.core.models import Confidence, IssueKind, OutputFormat, Severity, SuppressedBy
from secret_scanner.core.sanitize import sanitize_path
from secret_scanner.fs.walk import ReadFailure
from secret_scanner.services.config import load_config
from secret_scanner.services.loader import dump_yaml, load_builtin_rules
from tests.helpers import FakeClock

RULES = {rule.id: rule for rule in load_builtin_rules().rules}
BUILTIN_IDS = set(RULES)


def display(path: str, max_chars: int | None = None) -> str:
    """The display form of a path the way the application builds it (PLAN.md v0.9)."""
    return sanitize_path(path, windows=sys.platform == "win32", max_chars=max_chars)


def fake(rule_id: str, seed: str = "app") -> str:
    return build_fake(RULES[rule_id], seed)


@pytest.fixture
def root(tmp_path: Path) -> Path:
    directory = tmp_path / "tree"
    directory.mkdir()
    return directory


@pytest.fixture
def work(tmp_path: Path) -> Path:
    """A directory outside the scanned tree for configuration, baselines and reports."""
    directory = tmp_path / "work"
    directory.mkdir()
    return directory


def put(root: Path, relative: str, content: str | bytes) -> None:
    path = root / relative
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(content if isinstance(content, bytes) else content.encode("utf-8"))


def run(root: Path, **options: Any) -> ScanOutcome:
    request = ScanRequest(path=str(root), **options)
    return run_scan(request, FakeClock())


def write_yaml(path: Path, document: dict[str, Any]) -> str:
    path.write_bytes(dump_yaml(document).encode("ascii"))
    return str(path)


# -- exit codes and the confidence filter -----------------------------------------------------


def test_a_clean_tree_exits_zero(root: Path) -> None:
    put(root, "readme.md", "nothing here\n")
    outcome = run(root)
    assert outcome.exit_code is ExitCode.OK
    assert outcome.report.complete
    assert outcome.report.findings == ()
    assert outcome.notices == ()


def test_a_finding_at_or_above_fail_on_exits_one(root: Path) -> None:
    put(root, "a.txt", fake("npm-token"))  # severity high
    assert run(root).exit_code is ExitCode.FINDINGS
    assert run(root, fail_on=Severity.HIGH).exit_code is ExitCode.FINDINGS
    below = run(root, fail_on=Severity.CRITICAL)
    assert below.exit_code is ExitCode.OK
    assert len(below.report.findings) == 1  # still reported, it just does not fail the run


def test_low_confidence_findings_are_hidden_by_default_and_shown_on_request(root: Path) -> None:
    put(root, "cfg.txt", f"value = {fake_entropy_token('app')}\n")  # bare token: confidence low
    assert run(root).report.findings == ()
    assert run(root).exit_code is ExitCode.OK
    shown = run(root, min_confidence=Confidence.LOW)
    assert [f.rule_id for f in shown.report.findings] == ["entropy-base64"]
    assert shown.report.findings[0].confidence is Confidence.LOW
    assert shown.exit_code is ExitCode.FINDINGS


def test_an_incomplete_run_exits_four_even_with_findings(root: Path) -> None:
    put(root, "a.txt", fake("npm-token"))
    put(root, "b.txt", "plain")

    def failing(path: str, info: os.stat_result, limit: int) -> bytes | ReadFailure:
        if Path(path).name == "b.txt":
            return ReadFailure(IssueKind.UNREADABLE, "read: permission denied")
        return Path(path).read_bytes()

    outcome = run_scan(ScanRequest(path=str(root)), FakeClock(), reader=failing)
    assert outcome.exit_code is ExitCode.INCOMPLETE  # 4 beats 1
    assert not outcome.report.complete
    assert len(outcome.report.findings) == 1  # findings found so far are still reported
    assert outcome.report.stale is None
    assert any("incomplete" in notice for notice in outcome.notices)


def test_an_incomplete_run_without_findings_is_not_clean(root: Path) -> None:
    put(root, "b.txt", "plain")

    def failing(path: str, info: os.stat_result, limit: int) -> bytes | ReadFailure:
        return ReadFailure(IssueKind.VANISHED, "read: no longer exists")

    outcome = run_scan(ScanRequest(path=str(root)), FakeClock(), reader=failing)
    assert outcome.exit_code is ExitCode.INCOMPLETE
    assert "RESULT: INCOMPLETE" in outcome.text


def test_the_report_carries_version_rules_hash_and_clock_time(root: Path) -> None:
    from secret_scanner import __version__

    outcome = run(root)
    assert outcome.report.tool_version == __version__
    assert outcome.report.generated_at == "2026-01-01T00:00:00Z"
    assert outcome.report.rules_sha256 == load_builtin_rules().sha256
    assert outcome.report.target_display == display(str(root))


# -- configuration ----------------------------------------------------------------------------


def test_config_values_apply_and_cli_options_override_them(root: Path, work: Path) -> None:
    put(root, "a.txt", fake("npm-token"))
    config = write_yaml(work / "c.yaml", {"version": 1, "fail_on": "critical"})
    assert run(root, config=config).exit_code is ExitCode.OK
    assert run(root, config=config, fail_on=Severity.LOW).exit_code is ExitCode.FINDINGS

    cfg_conf = write_yaml(work / "d.yaml", {"version": 1, "min_confidence": "high"})
    put(root, "e.txt", f"token = {fake_entropy_token('cfg')}\n")  # low confidence
    low = run(root, config=cfg_conf, min_confidence=Confidence.LOW)
    assert {f.rule_id for f in low.report.findings} == {"npm-token", "entropy-base64"}
    assert {f.rule_id for f in run(root, config=cfg_conf).report.findings} == {"npm-token"}


def test_config_can_disable_rules_add_rules_exclude_paths_and_turn_entropy_off(
    root: Path, work: Path
) -> None:
    rule = {
        "id": "custom-demo",
        "name": "Demo",
        "description": "A demo rule.",
        "regex": "demo_(?P<secret>[A-Za-z0-9]{24})",
        "keywords": ["demo_"],
        "severity": "medium",
        "confidence": "high",
        "shown_chars": 0,
        "min_secret_bits": 100,
        "fake": [{"parts": ["demo", "_"]}, {"charset": "base62", "length": 24}],
    }
    parsed = load_config(
        dump_yaml({"version": 1, "extra_rules": [rule]}).encode("ascii"),
        builtin_rule_ids=BUILTIN_IDS,
    )
    custom = build_fake(parsed.extra_rules[0], "app")
    put(root, "src/a.txt", f"{fake('npm-token')}\n{custom}\n")
    put(root, "vendor/b.txt", fake("npm-token", "other"))
    config = write_yaml(
        work / "c.yaml",
        {
            "version": 1,
            "disable_rules": ["npm-token"],
            "extra_rules": [rule],
            "exclude": ["vendor/**"],
            "entropy": {"enabled": False},
        },
    )
    outcome = run(root, config=config)
    assert [(f.rule_id, f.location.path_key) for f in outcome.report.findings] == [
        ("custom-demo", "src/a.txt")
    ]
    assert outcome.report.stats.skipped_excluded == 1


def test_config_limits_make_the_run_incomplete(root: Path, work: Path) -> None:
    put(root, "big.txt", "x" * 2_000)
    config = write_yaml(work / "c.yaml", {"version": 1, "limits": {"max_file_bytes": 1_000}})
    outcome = run(root, config=config)
    assert outcome.exit_code is ExitCode.INCOMPLETE
    assert [issue.kind for issue in outcome.report.issues] == [IssueKind.TOO_LARGE]


def test_too_many_active_rules_are_refused(root: Path, work: Path) -> None:
    config = write_yaml(
        work / "c.yaml", {"version": 1, "limits": {"max_rules": 5}, "disable_rules": []}
    )
    with pytest.raises(ConfigError, match="more than 5 rules are active"):
        run(root, config=config)


@pytest.mark.parametrize(
    ("name", "content", "reason"),
    [
        ("unknown.yaml", b"version: 1\nsurprise: true\n", "unknown key"),
        ("version.yaml", b"version: 2\n", "version must be 1"),
        ("dup.yaml", b"version: 1\nversion: 1\n", "duplicate key"),
        ("anchor.yaml", b"version: &a 1\n", "anchors are not allowed"),
    ],
)
def test_a_malformed_configuration_is_refused(
    root: Path, work: Path, name: str, content: bytes, reason: str
) -> None:
    (work / name).write_bytes(content)
    with pytest.raises(ConfigError, match=reason):
        run(root, config=str(work / name))


def test_a_missing_configuration_or_baseline_is_an_io_error(root: Path, work: Path) -> None:
    with pytest.raises(ScanIOError, match="does not exist"):
        run(root, config=str(work / "missing.yaml"))
    with pytest.raises(ScanIOError, match="does not exist"):
        run(root, baseline=str(work / "missing.yaml"))


# -- baseline ---------------------------------------------------------------------------------


def test_baseline_round_trip_suppresses_exactly_what_was_written(root: Path, work: Path) -> None:
    put(root, "a.txt", fake("npm-token"))
    baseline = str(work / "baseline.yaml")
    first = run(root, write_baseline=baseline)
    assert first.exit_code is ExitCode.FINDINGS  # writing a baseline does not excuse the run
    assert first.notices == (
        f"baseline with 1 entries written to {display(baseline, max_chars=120)}",
    )
    second = run(root, baseline=baseline)
    assert second.exit_code is ExitCode.OK
    assert second.report.findings == ()
    assert (second.report.suppressed_by_fingerprint, second.report.suppressed_by_path) == (1, 0)
    assert second.report.stale == 0
    # a new secret is not covered by the old baseline
    put(root, "b.txt", fake("aws-access-key-id"))
    third = run(root, baseline=baseline)
    assert third.exit_code is ExitCode.FINDINGS
    assert [f.rule_id for f in third.report.findings] == ["aws-access-key-id"]


def test_suppressed_findings_are_listed_only_on_request(root: Path, work: Path) -> None:
    put(root, "a.txt", fake("npm-token"))
    baseline = str(work / "b.yaml")
    run(root, write_baseline=baseline)
    hidden = run(root, baseline=baseline)
    listed = run(root, baseline=baseline, show_suppressed=True)
    assert hidden.report.findings == ()
    assert [f.suppressed_by for f in listed.report.findings] == [SuppressedBy.FINGERPRINT]
    assert listed.exit_code is ExitCode.OK  # a listed suppressed finding does not fail the run
    assert "[suppressed: fingerprint]" in listed.text


def test_stale_entries_are_counted_only_for_a_complete_run(root: Path, work: Path) -> None:
    put(root, "a.txt", fake("npm-token"))
    baseline = str(work / "b.yaml")
    run(root, write_baseline=baseline)
    (root / "a.txt").write_text("secret removed\n", encoding="utf-8")
    assert run(root, baseline=baseline).report.stale == 1

    def failing(path: str, info: os.stat_result, limit: int) -> bytes | ReadFailure:
        return ReadFailure(IssueKind.UNREADABLE, "read: permission denied")

    incomplete = run_scan(
        ScanRequest(path=str(root), baseline=baseline), FakeClock(), reader=failing
    )
    assert incomplete.report.stale is None  # an unread file could hold the finding


def test_a_low_confidence_finding_hidden_by_the_filter_keeps_its_entry_fresh(
    root: Path, work: Path
) -> None:
    put(root, "cfg.txt", f"value = {fake_entropy_token('app')}\n")
    baseline = str(work / "b.yaml")
    run(root, write_baseline=baseline, min_confidence=Confidence.LOW)
    # the default filter hides the finding, but it is still detected, so its entry is not stale
    assert run(root, baseline=baseline).report.stale == 0


def test_the_written_baseline_is_a_valid_strict_file_with_a_header(root: Path, work: Path) -> None:
    put(root, "a.txt", fake("npm-token"))
    baseline = work / "b.yaml"
    run(root, write_baseline=str(baseline))
    text = baseline.read_text(encoding="ascii")
    assert text.startswith("# secret-scanner baseline")
    assert "fingerprint:" in text
    assert "TODO: review" in text


def test_refreshing_a_baseline_keeps_reviewed_reasons_and_path_globs(
    root: Path, work: Path
) -> None:
    put(root, "a.txt", fake("npm-token"))
    put(root, "vendor/v.txt", fake("npm-token", "vendored"))
    baseline = work / "b.yaml"
    run(root, write_baseline=str(baseline))
    document = yaml.safe_load(baseline.read_text("ascii"))
    document["suppress"] = [e for e in document["suppress"] if e["path"] == "a.txt"]
    document["suppress"][0]["reason"] = "reviewed by the owner"
    document["paths"] = ["vendor/**"]
    baseline.write_bytes(dump_yaml(document).encode("ascii"))

    put(root, "new.txt", fake("aws-access-key-id"))
    refreshed = work / "refreshed.yaml"
    outcome = run(root, baseline=str(baseline), write_baseline=str(refreshed))
    parsed = yaml.safe_load(refreshed.read_text("ascii"))
    reasons = {entry["path"]: entry["reason"] for entry in parsed["suppress"]}
    # the reviewed reason survives, the new finding gets the default, and the finding that the
    # path glob already covers is not duplicated as a fingerprint entry
    assert reasons == {"a.txt": "reviewed by the owner", "new.txt": "TODO: review"}
    assert parsed["paths"] == ["vendor/**"]
    assert outcome.report.suppressed_by_path == 1


def test_path_globs_suppress_and_are_counted(root: Path, work: Path) -> None:
    put(root, "tests/fixtures/k.txt", fake("npm-token"))
    put(root, "src/a.txt", fake("aws-access-key-id"))
    baseline = write_yaml(work / "b.yaml", {"version": 1, "paths": ["tests/fixtures/**"]})
    outcome = run(root, baseline=baseline)
    assert [f.location.path_key for f in outcome.report.findings] == ["src/a.txt"]
    assert outcome.report.suppressed_by_path == 1


def test_a_malformed_baseline_is_refused(root: Path, work: Path) -> None:
    for name, content, reason in [
        ("short.yaml", b"version: 1\nsuppress:\n  - fingerprint: abc\n", "32 lower-case hex"),
        ("unknown.yaml", b"version: 1\nextra: 1\n", "unknown key"),
        ("version.yaml", b"version: 9\n", "version must be 1"),
    ]:
        (work / name).write_bytes(content)
        with pytest.raises(ConfigError, match=reason):
            run(root, baseline=str(work / name))


# -- outputs ----------------------------------------------------------------------------------


def test_the_report_is_written_atomically_and_not_over_an_existing_file(
    root: Path, work: Path
) -> None:
    put(root, "a.txt", fake("npm-token"))
    out = work / "report.json"
    outcome = run(root, output_format=OutputFormat.JSON, output=str(out), host_label="ci")
    assert json.loads(out.read_text("ascii"))["host"] == "ci"
    assert outcome.text == out.read_text("ascii")
    assert f"report written to {display(str(out), max_chars=120)}" in outcome.notices
    with pytest.raises(ScanIOError, match="already exists"):
        run(root, output_format=OutputFormat.JSON, output=str(out))
    assert out.read_text("ascii") == outcome.text  # untouched
    run(root, output_format=OutputFormat.JSON, output=str(out), force=True, host_label="ci2")
    assert json.loads(out.read_text("ascii"))["host"] == "ci2"
    assert sorted(p.name for p in work.iterdir()) == ["report.json"]  # no temporary files


def test_an_output_that_cannot_be_written_is_refused_before_scanning(
    root: Path, work: Path
) -> None:
    out = work / "report.txt"
    out.write_text("keep me", encoding="utf-8")

    def boom(path: str, info: os.stat_result, limit: int) -> bytes | ReadFailure:
        raise AssertionError("the tree must not be read when the output is refused")

    with pytest.raises(ScanIOError, match="already exists"):
        run_scan(ScanRequest(path=str(root), output=str(out)), FakeClock(), reader=boom)
    put(root, "a.txt", "x")
    with pytest.raises(ScanIOError, match="already exists"):
        run_scan(ScanRequest(path=str(root), write_baseline=str(out)), FakeClock(), reader=boom)
    assert out.read_text("utf-8") == "keep me"


def test_outputs_inside_the_scanned_tree_are_refused(root: Path, work: Path) -> None:
    put(root, "a.txt", "x")
    for option in ("output", "write_baseline"):
        with pytest.raises(UsageError, match="must not be inside the scanned tree"):
            run(root, **{option: str(root / "sub" / "out.txt")})
        with pytest.raises(UsageError, match="must not be inside the scanned tree"):
            run(root, **{option: str(root / "out.txt")})
    assert sorted(p.name for p in root.iterdir()) == ["a.txt"]


def test_an_output_may_not_overwrite_the_configuration_or_baseline_it_reads(
    root: Path, work: Path
) -> None:
    config = write_yaml(work / "c.yaml", {"version": 1})
    baseline = write_yaml(work / "b.yaml", {"version": 1})
    with pytest.raises(UsageError, match="would overwrite the file given as --config"):
        run(root, config=config, output=config, force=True)
    with pytest.raises(UsageError, match="would overwrite the file given as --baseline"):
        run(root, baseline=baseline, output=baseline, force=True)
    with pytest.raises(UsageError, match="would overwrite the file given as --config"):
        run(root, config=config, write_baseline=config, force=True)
    # refreshing the baseline in place is the intended use of --write-baseline --force
    put(root, "a.txt", fake("npm-token"))
    outcome = run(root, baseline=baseline, write_baseline=baseline, force=True)
    assert outcome.exit_code is ExitCode.FINDINGS
    assert "fingerprint:" in Path(baseline).read_text("ascii")


def test_output_and_write_baseline_must_differ(root: Path, work: Path) -> None:
    target = str(work / "same.out")
    with pytest.raises(UsageError, match="name the same file"):
        run(root, output=target, write_baseline=target)


@pytest.mark.requires_symlinks
def test_an_output_that_is_a_link_is_refused(root: Path, work: Path) -> None:
    real = work / "real.txt"
    real.write_text("original", encoding="utf-8")
    link = work / "link.txt"
    link.symlink_to(real)
    with pytest.raises(ScanIOError, match="link or reparse point"):
        run(root, output=str(link), force=True)
    assert real.read_text("utf-8") == "original"


def test_the_scanned_tree_is_never_changed(root: Path, work: Path) -> None:
    put(root, "a.txt", fake("npm-token"))
    put(root, "d/b.txt", "plain")
    before = {
        p.relative_to(root): (p.stat().st_size, p.stat().st_mtime_ns, p.read_bytes())
        for p in root.rglob("*")
        if p.is_file()
    }
    run(
        root,
        output=str(work / "r.json"),
        output_format=OutputFormat.JSON,
        write_baseline=str(work / "b.yaml"),
    )
    after = {
        p.relative_to(root): (p.stat().st_size, p.stat().st_mtime_ns, p.read_bytes())
        for p in root.rglob("*")
        if p.is_file()
    }
    assert after == before
    assert sorted(p.name for p in root.iterdir()) == ["a.txt", "d"]


# -- path and option validation ---------------------------------------------------------------


@pytest.mark.parametrize(
    "path",
    ["", "https://example.invalid/x", "a/../b", "with\x1bescape", "x\ny"],
    ids=["empty", "url", "parent", "escape", "newline"],
)
def test_refused_scan_paths(path: str) -> None:
    with pytest.raises(UsageError):
        run_scan(ScanRequest(path=path), FakeClock())


def test_a_missing_or_file_root_is_a_usage_error(tmp_path: Path) -> None:
    with pytest.raises(UsageError, match="does not exist"):
        run_scan(ScanRequest(path=str(tmp_path / "nope")), FakeClock())
    (tmp_path / "f.txt").write_text("x", encoding="utf-8")
    with pytest.raises(UsageError, match="not a directory"):
        run_scan(ScanRequest(path=str(tmp_path / "f.txt")), FakeClock())


def test_output_paths_are_validated_like_the_scan_path(root: Path) -> None:
    with pytest.raises(UsageError):
        run(root, output="a/../b.txt")
    with pytest.raises(UsageError):
        run(root, write_baseline="")


def test_a_bad_host_label_is_refused(root: Path) -> None:
    with pytest.raises(UsageError, match="host-label"):
        run(root, host_label="  ")
    with pytest.raises(UsageError, match="control characters"):
        run(root, host_label="a\x1b[31m")


def test_the_json_host_defaults_to_an_escaped_node_name(
    root: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    import platform

    monkeypatch.setattr(platform, "node", lambda: "build-\x1bhost")
    outcome = run(root, output_format=OutputFormat.JSON)
    assert json.loads(outcome.text)["host"] == "build-\\x1bhost"


def test_default_excludes_can_be_turned_off(root: Path) -> None:
    put(root, "node_modules/x.js", fake("npm-token"))
    assert run(root).report.findings == ()
    assert len(run(root, default_excludes=False).report.findings) == 1


def test_rules_hash_is_the_built_in_files_even_with_a_configuration(root: Path, work: Path) -> None:
    config = write_yaml(work / "c.yaml", {"version": 1, "disable_rules": ["npm-token"]})
    assert run(root, config=config).report.rules_sha256 == load_builtin_rules().sha256


def test_both_formats_render_the_same_findings(
    root: Path, assert_not_leaked: Callable[..., None]
) -> None:
    token = fake("npm-token")
    put(root, "a.txt", token)
    table = run(root).text
    document = json.loads(run(root, output_format=OutputFormat.JSON).text)
    assert document["counts"]["findings"] == 1
    assert "npm-token" in table
    for text in (table, json.dumps(document)):
        assert_not_leaked(text, token, allowed_shown=len("npm_"))


def test_a_baseline_written_by_an_incomplete_run_says_so(root: Path, work: Path) -> None:
    put(root, "a.txt", fake("npm-token"))
    put(root, "b.txt", "plain")

    def failing(path: str, info: os.stat_result, limit: int) -> bytes | ReadFailure:
        if Path(path).name == "b.txt":
            return ReadFailure(IssueKind.UNREADABLE, "read: permission denied")
        return Path(path).read_bytes()

    baseline = str(work / "b.yaml")
    outcome = run_scan(
        ScanRequest(path=str(root), write_baseline=baseline), FakeClock(), reader=failing
    )
    assert outcome.exit_code is ExitCode.INCOMPLETE
    assert "the run was incomplete" in outcome.notices[0]
    assert Path(baseline).exists()


# -- nothing is discovered: configuration, rules and baselines come from the command line only ----

# Every name a tool of this kind might look for by itself, here or in another scanner.
DISCOVERABLE_NAMES = (
    ".secret-scanner.yaml",
    ".secret-scanner.yml",
    "secret-scanner.yaml",
    "secret-scanner.yml",
    ".secret-scanner/config.yaml",
    ".secret-scanner-baseline.yaml",
    "secret-scanner-baseline.yaml",
    "baseline.yaml",
    ".secrets.baseline",
    "config.yaml",
    "rules.yaml",
    "builtin.yaml",
    "rules/builtin.yaml",
    ".config/secret-scanner/config.yaml",
)


def plant_discoverable_files(directory: Path, fingerprint: str) -> None:
    """In `directory`: under every such name a configuration that would switch every rule off and
    exclude every file, a baseline that would suppress `fingerprint` and every path, and a
    `pyproject.toml` section with the same wishes."""
    config = {
        "version": 1,
        "exclude": ["**"],
        "disable_rules": sorted(BUILTIN_IDS),
        "entropy": {"enabled": False},
        "min_confidence": "high",
        "fail_on": "critical",
    }
    baseline = {"version": 1, "suppress": [{"fingerprint": fingerprint}], "paths": ["**"]}
    for number, name in enumerate(DISCOVERABLE_NAMES):
        document = baseline if "baseline" in name or number % 2 else config
        put(directory, name, dump_yaml(document))
    put(
        directory,
        "pyproject.toml",
        '[tool.secret-scanner]\nexclude = ["**"]\nbaseline = "baseline.yaml"\n',
    )


def test_configuration_rules_and_baselines_are_never_discovered(
    root: Path, isolated_home: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """CLAUDE.md section 5, invariant 10: a scanned tree (which may be an attacker's pull request)
    cannot switch the scan off or excuse its own secret. Files that ask for it are planted in the
    scanned tree, in the current directory and in the user's home; the result is the one of a run
    without them, and they are scanned like any other file."""
    put(root, "src/app.txt", f"token = {fake('npm-token')}\n")
    expected = run(root)
    assert [f.rule_id for f in expected.report.findings] == ["npm-token"]
    fingerprint = expected.report.findings[0].fingerprint

    plant_discoverable_files(root, fingerprint)
    plant_discoverable_files(isolated_home, fingerprint)
    try:
        monkeypatch.chdir(root)
        for request_root in (root, Path(".")):
            outcome = run(request_root)
            assert outcome.exit_code is ExitCode.FINDINGS
            assert outcome.report.findings == expected.report.findings
            assert (
                outcome.report.suppressed_by_fingerprint,
                outcome.report.suppressed_by_path,
            ) == (
                0,
                0,
            )
            assert outcome.report.complete
            # the planted files are content, not settings: every one of them was read and scanned
            assert outcome.report.stats.files_scanned == 1 + len(DISCOVERABLE_NAMES) + 1
            assert outcome.report.stats.skipped_excluded == 0
    finally:
        for name in (*DISCOVERABLE_NAMES, "pyproject.toml"):
            (isolated_home / name).unlink()
        for leftover in sorted(isolated_home.rglob("*"), reverse=True):
            leftover.rmdir()
