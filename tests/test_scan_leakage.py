"""No full secret, and no run of more than the allowed shown characters of it, in anything the
`scan` command emits: stdout, stderr, warnings, written reports and baselines, error messages and
exception text (CLAUDE.md section 5, invariant 1; PLAN.md D7, D16).

Every built-in rule, the private key detector and the entropy detector are exercised through
every output path of `scan`: the four formats (table, JSON, JSONL, SARIF) on stdout and in files,
with findings suppressed and hidden or listed, and every error path. The full matrix (every rule
through every format and every error path) is the slow run, which the full gate and CI execute; the
default gate runs one representative of each detector kind through the whole matrix, and every rule
through all four renderers in-process. `scan-git` is covered in tests/test_git_scan.py and
tests/test_output_formats.py."""

from __future__ import annotations

import warnings
from collections.abc import Callable
from dataclasses import dataclass
from pathlib import Path
from typing import Any

import pytest

from secret_scanner.app import scan as scan_module
from secret_scanner.cli import main as cli_main
from secret_scanner.core.fakes import build_fake, fake_entropy_token, fake_private_key
from secret_scanner.core.models import Confidence, Detector, OutputFormat
from secret_scanner.services.loader import dump_yaml, load_builtin_rules
from tests.conftest import leak_check
from tests.helpers import FakeClock, public_prefix_length

SEED = "leak"
ENTROPY_SHOWN = 4
# One representative per detector kind (rule, private key, entropy) runs the whole matrix in the
# default gate; the other rules run it as `slow` tests.
REPRESENTATIVES = frozenset({"aws-access-key-id", "private-key", "entropy-base64"})


@dataclass(frozen=True)
class Planted:
    """One fake secret: the file text that contains it, what must never appear, and how many of
    its leading characters the redacted form is allowed to show."""

    name: str
    file_text: str
    needle: str
    allowed_shown: int


def _planted() -> list[Planted]:
    planted: list[Planted] = []
    for rule in load_builtin_rules().rules:
        if rule.detector is Detector.RULE:
            secret = build_fake(rule, SEED)
            # one line that carries the context words the context-gated rules need
            text = f"aws_secret_access_key = {secret}\n"
            planted.append(Planted(rule.id, text, secret, public_prefix_length(rule)))
    key = fake_private_key(SEED, label="RSA")
    body = "".join(line for line in key.splitlines() if not line.startswith("-----"))
    planted.append(Planted("private-key", key, body, 0))
    token = fake_entropy_token(SEED)
    planted.append(Planted("entropy-base64", f"api_token = {token}\n", token, ENTROPY_SHOWN))
    return planted


PLANTED = _planted()


def test_every_rule_has_a_planted_secret() -> None:
    names = {p.name for p in PLANTED}
    rule_ids = {
        r.id
        for r in load_builtin_rules().rules
        if r.detector in {Detector.RULE, Detector.PRIVATE_KEY}
    }
    assert rule_ids <= names
    assert "entropy-base64" in names
    assert names >= REPRESENTATIVES


def _matrix_cases() -> list[Any]:
    return [
        pytest.param(
            planted,
            id=planted.name,
            marks=() if planted.name in REPRESENTATIVES else pytest.mark.slow,
        )
        for planted in PLANTED
    ]


class Capture:
    """Everything one scenario emitted, with a label for each piece."""

    def __init__(self) -> None:
        self.pieces: list[tuple[str, str]] = []

    def add(self, label: str, text: str) -> None:
        self.pieces.append((label, text))


@pytest.fixture
def run_cli(capsys: pytest.CaptureFixture[str]) -> Callable[..., tuple[int, str, str]]:
    def invoke(*argv: str) -> tuple[int, str, str]:
        code = cli_main.main(list(argv))
        captured = capsys.readouterr()
        return code, captured.out, captured.err

    return invoke


def _write(path: Path, document: dict[str, Any]) -> str:
    path.write_bytes(dump_yaml(document).encode("ascii"))
    return str(path)


@pytest.mark.parametrize("planted", _matrix_cases())
def test_nothing_that_scan_emits_contains_the_secret(
    tmp_path: Path,
    run_cli: Callable[..., tuple[int, str, str]],
    monkeypatch: pytest.MonkeyPatch,
    planted: Planted,
) -> None:
    root = tmp_path / "tree"
    work = tmp_path / "work"
    root.mkdir()
    work.mkdir()
    (root / "settings.txt").write_text(planted.file_text, encoding="utf-8", newline="\n")
    capture = Capture()

    def cli(label: str, *argv: str) -> int:
        code, out, err = run_cli(*argv)
        capture.add(f"{label}: stdout", out)
        capture.add(f"{label}: stderr", err)
        return code

    # a detection must actually happen, or the test proves nothing
    code = cli("table", "scan", str(root), "--min-confidence", "low")
    assert code == 1
    assert "settings.txt" in capture.pieces[0][1]

    cli("json", "scan", str(root), "--format", "json", "--min-confidence", "low")
    cli("jsonl", "scan", str(root), "--format", "jsonl", "--min-confidence", "low")
    cli("sarif", "scan", str(root), "--format", "sarif", "--min-confidence", "low")
    report = work / "report.json"
    events = work / "events.jsonl"
    sarif_file = work / "scan.sarif"
    baseline = work / "baseline.yaml"
    cli(
        "write",
        "scan",
        str(root),
        "--format",
        "json",
        "--min-confidence",
        "low",
        "--output",
        str(report),
        "--write-baseline",
        str(baseline),
    )
    capture.add("report file", report.read_text("utf-8"))
    capture.add("baseline file", baseline.read_text("utf-8"))
    for label, target, fmt in (("jsonl", events, "jsonl"), ("sarif", sarif_file, "sarif")):
        cli(
            f"{label} file",
            "scan",
            str(root),
            "--format",
            fmt,
            "--min-confidence",
            "low",
            "--output",
            str(target),
        )
    assert (
        cli(
            "suppressed",
            "scan",
            str(root),
            "--baseline",
            str(baseline),
            "--min-confidence",
            "low",
            "--show-suppressed",
        )
        == 0
    )
    cli(
        "suppressed-json",
        "scan",
        str(root),
        "--baseline",
        str(baseline),
        "--min-confidence",
        "low",
        "--show-suppressed",
        "--format",
        "json",
    )
    for fmt in ("jsonl", "sarif"):
        for shown in (True, False):
            argv = ["scan", str(root), "--baseline", str(baseline), "--format", fmt]
            argv += ["--min-confidence", "low"] + (["--show-suppressed"] if shown else [])
            assert cli(f"suppressed-{fmt}-{'shown' if shown else 'hidden'}", *argv) == 0

    # error paths with the secret in the files the tool reads
    secret = planted.needle
    bad_config = _write(work / "bad-config.yaml", {"version": 1, secret: True})
    assert cli("config-key", "scan", str(root), "--config", bad_config) == 2
    bad_nested = _write(work / "bad-nested.yaml", {"version": 1, "entropy": {secret: True}})
    assert cli("config-nested", "scan", str(root), "--config", bad_nested) == 2
    bad_limit = _write(work / "bad-limit.yaml", {"version": 1, "limits": {secret: 1}})
    assert cli("config-limit", "scan", str(root), "--config", bad_limit) == 2
    bad_rule = _write(work / "bad-rule.yaml", {"version": 1, "disable_rules": [secret]})
    assert cli("config-disable", "scan", str(root), "--config", bad_rule) == 2
    bad_glob = _write(work / "bad-glob.yaml", {"version": 1, "exclude": [secret + "/../x"]})
    cli("config-glob", "scan", str(root), "--config", bad_glob)
    bad_baseline = _write(
        work / "bad-baseline.yaml",
        {"version": 1, "suppress": [{"fingerprint": secret, "rule": secret}], secret: 1},
    )
    assert cli("baseline", "scan", str(root), "--baseline", bad_baseline) == 2
    bad_entry = _write(
        work / "bad-entry.yaml", {"version": 1, "suppress": [{"fingerprint": "a" * 32, secret: 1}]}
    )
    assert cli("baseline-entry", "scan", str(root), "--baseline", bad_entry) == 2
    garbage = work / "garbage.yaml"
    garbage.write_bytes(b"version: 1\nsuppress: [" + secret.encode("ascii") + b"\n")
    assert cli("baseline-yaml", "scan", str(root), "--baseline", str(garbage)) == 2
    assert cli("output-exists", "scan", str(root), "--output", str(report)) == 2
    for fmt in ("jsonl", "sarif"):
        as_format = ["scan", str(root), "--format", fmt]
        assert cli(f"config-key {fmt}", *as_format, "--config", bad_config) == 2
        assert cli(f"baseline {fmt}", *as_format, "--baseline", bad_baseline) == 2
        assert cli(f"output-exists {fmt}", *as_format, "--output", str(report)) == 2

    # an internal failure that carries the secret in its message must print its type only
    def explode(*args: object, **kwargs: object) -> object:
        raise RuntimeError(secret)

    monkeypatch.setattr(scan_module, "scan_tree", explode)
    assert cli("internal-error", "scan", str(root)) == 2

    # Everything the tool wrote: its report and baseline, and nothing else (no temporary files).
    # The test's own input files hold the secret by construction and are not checked.
    inputs = {path.name for path in work.glob("bad-*.yaml")} | {"garbage.yaml"}
    written = sorted(path.name for path in work.iterdir() if path.name not in inputs)
    assert written == ["baseline.yaml", "events.jsonl", "report.json", "scan.sarif"]
    for name in written:
        capture.add(f"file {name}", (work / name).read_bytes().decode("utf-8", "replace"))

    for label, text in capture.pieces:
        problem = leak_check(text, planted.needle, allowed_shown=planted.allowed_shown)
        if problem is not None:
            pytest.fail(f"{planted.name} / {label}: {problem}", pytrace=False)
    # the tool never touched the tree: only the planted file is there
    assert [p.name for p in root.iterdir()] == ["settings.txt"]


@pytest.mark.parametrize("planted", PLANTED, ids=lambda p: p.name)
def test_every_format_of_every_rule_carries_no_secret(tmp_path: Path, planted: Planted) -> None:
    """Every rule's fake through the four renderers, with the finding reported, suppressed and
    hidden, and suppressed and listed, in-process (the CLI matrix above covers the other output
    paths for one representative of each detector kind)."""
    root = tmp_path / "tree"
    root.mkdir()
    (root / "settings.txt").write_text(planted.file_text, encoding="utf-8", newline="\n")
    baseline = tmp_path / "baseline.yaml"
    first = scan_module.ScanRequest(
        path=str(root), min_confidence=Confidence.LOW, write_baseline=str(baseline)
    )
    assert scan_module.run_scan(first, FakeClock()).report.findings, planted.name
    for output_format in OutputFormat:
        for suppressed in (None, "hidden", "shown"):
            request = scan_module.ScanRequest(
                path=str(root),
                output_format=output_format,
                min_confidence=Confidence.LOW,
                baseline=None if suppressed is None else str(baseline),
                show_suppressed=suppressed == "shown",
            )
            outcome = scan_module.run_scan(request, FakeClock())
            label = f"{planted.name} / {output_format.value} / {suppressed}"
            if suppressed is None:
                assert outcome.report.findings, f"{label}: nothing detected"
            elif suppressed == "shown":
                assert [f.suppressed_by for f in outcome.report.findings], f"{label}: none listed"
            problem = leak_check(outcome.text, planted.needle, allowed_shown=planted.allowed_shown)
            if problem is not None:
                pytest.fail(f"{label}: {problem}", pytrace=False)


@pytest.mark.parametrize("planted", PLANTED[:3], ids=lambda p: p.name)
def test_no_warning_is_emitted_and_none_carries_content(
    tmp_path: Path, run_cli: Callable[..., tuple[int, str, str]], planted: Planted
) -> None:
    root = tmp_path / "tree"
    root.mkdir()
    (root / "settings.txt").write_text(planted.file_text, encoding="utf-8")
    with warnings.catch_warnings(record=True) as caught:
        warnings.simplefilter("always")
        run_cli("scan", str(root))
        run_cli("scan", str(root), "--format", "json")
    assert [str(w.message) for w in caught] == []


def test_the_leak_check_itself_catches_a_leak() -> None:
    secret = PLANTED[0].needle
    assert leak_check("prefix " + secret + " suffix", secret) is not None
    assert leak_check("short " + secret[:7] + " only", secret) is None  # below the run threshold
    assert leak_check("ok", secret) is None
