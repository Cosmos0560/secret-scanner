"""`scripts/bench.py`: the generated input is deterministic and harmless, every run checks itself
(found == planted), and the report it prints holds counts and times only: no secret, no redacted
value, no path of this machine. Sizes here are tiny; the real numbers are in docs/performance.md.
"""

from __future__ import annotations

import argparse
import dataclasses
import re
import tempfile
from collections.abc import Callable
from pathlib import Path

import pytest

from scripts import bench
from secret_scanner import __version__
from secret_scanner.app.common import ScanOutcome, resolve_git_program
from secret_scanner.app.scan import ScanRequest, run_scan
from secret_scanner.core import limits
from secret_scanner.core.clock import Clock
from secret_scanner.core.fakes import build_fake, fake_entropy_token
from secret_scanner.services.loader import load_builtin_rules
from tests.helpers import PROJECT_ROOT, local_traces


def planted_fakes(prefix: str, indexes: range) -> list[str]:
    rules = bench.planted_rules()
    return [
        build_fake(rules[number % len(rules)], f"{prefix}-{index}")
        for number, index in enumerate(indexes)
    ]


# -- generated input ------------------------------------------------------------------------------


def test_the_text_is_deterministic_plain_ascii_and_matches_no_rule_keyword() -> None:
    block = bench.text_block("seed", 50)
    assert block == bench.text_block("seed", 50)
    assert block != bench.text_block("other", 50)
    assert block.isascii()
    assert len(block.splitlines()) == 50
    keywords = {keyword for rule in load_builtin_rules().rules for keyword in rule.keywords}
    text = " ".join(bench.WORDS) + bench.text_block("keywords", 400)
    assert not [keyword for keyword in keywords if keyword in text.lower()]


def test_the_tree_has_the_files_asked_for_and_one_fake_per_hundred(tmp_path: Path) -> None:
    written, planted = bench.make_tree(tmp_path / "tree", 201, bench.planted_rules(), lines=3)
    files = sorted(path for path in (tmp_path / "tree").rglob("*.txt"))
    assert len(files) == 201
    assert planted == 3
    assert written == sum(path.stat().st_size for path in files)
    assert len(list((tmp_path / "tree").iterdir())) == 3, "one directory per hundred files"
    assert files[0].read_text(encoding="ascii").count("\n") == 4, "three lines and the fake"
    assert files[1].read_text(encoding="ascii").count("\n") == 3


def test_the_history_stream_names_no_address_literal_and_counts_its_fakes() -> None:
    stream, total, planted = bench.history_stream(251, bench.planted_rules())
    assert planted == 2
    assert stream.count(b"commit refs/heads/main\n") == 251
    assert stream.count(b"M 100644 inline src/module_") == 251 * bench.FILES_PER_COMMIT
    assert total > 251 * bench.FILES_PER_COMMIT * 1_000
    assert b"from :250\n" in stream
    assert b"from :0\n" not in stream, "the first commit has no parent"
    assert stream.count(b"example.invalid>") == 251, "the identity is the generated one"


def test_sizes_are_whole_positive_numbers() -> None:
    assert bench._sizes("10, 200,3000") == [10, 200, 3000]
    assert bench._sizes("") == []
    for bad in ("ten", "1,x", "0", "5,-1"):
        with pytest.raises(argparse.ArgumentTypeError):
            bench._sizes(bad)


def test_a_rate_without_any_megabyte_is_not_a_number() -> None:
    assert bench._per_mib(3, 0.0) == "n/a"
    assert bench._per_mib(3, 1.5) == "2.00"


# -- measured runs (tiny) -------------------------------------------------------------------------


def test_a_tree_run_finds_exactly_the_planted_fakes(tmp_path: Path) -> None:
    row = bench.bench_tree(tmp_path, 101, lines=5, repeat=1, memory=True)
    assert row.ok
    assert row.cells[0] == "101"
    assert row.cells[-2] == "2 of 2"
    assert re.fullmatch(r"\d+\.\d", row.cells[-1]), "a traced peak in MiB"
    unmeasured = bench.bench_tree(tmp_path / "again", 5, lines=5, repeat=0, memory=False)
    assert unmeasured.ok
    assert unmeasured.cells[-1] == "not measured"


def test_a_run_that_does_not_find_its_fakes_is_not_ok(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(bench, "planted_line", lambda rules, index, seed: "nothing = here\n")
    row = bench.bench_tree(tmp_path, 3, lines=2, repeat=0, memory=False)
    assert not row.ok
    assert row.cells[-2] == "0 of 1"
    assert bench._check(1, 1, False) == ("1 of 1 (incomplete run)", False)


@pytest.mark.slow
@pytest.mark.requires_git
def test_a_history_run_finds_exactly_the_planted_fakes(tmp_path: Path) -> None:
    git = resolve_git_program(git=None, root=str(tmp_path))
    row = bench.bench_history(tmp_path, git, 12, repeat=1, memory=False)
    assert row.ok
    assert row.cells[0] == "12"
    assert row.cells[1] == str(12 * bench.FILES_PER_COMMIT)
    assert row.cells[-2] == "1 of 1"
    assert bench.git_version(git, tmp_path).startswith("git version ")


def test_the_corpus_row_counts_entropy_findings_by_confidence(tmp_path: Path) -> None:
    corpus = tmp_path / "corpus"
    corpus.mkdir()
    with_context, bare = fake_entropy_token("bench-a"), fake_entropy_token("bench-c")
    (corpus / "settings.txt").write_text(f"api_token = {with_context}\nplain {bare}\n")
    row = bench.bench_corpus("corpus", corpus)
    assert row.ok
    assert row.cells[0] == "`corpus`"
    assert row.cells[1] == "1"
    assert row.cells[4] == "1", "one entropy finding at the default confidence (it has context)"
    assert row.cells[6] == "1", "one bare base64 token, reported only at low confidence"
    assert row.cells[7] == "0"
    assert row.cells[9] == "0", "no rule or key finding"
    assert row.cells[-1] == "complete"
    empty = tmp_path / "empty"
    empty.mkdir()
    assert bench.bench_corpus("empty", empty).cells[5] == "n/a"


def test_a_capped_or_incomplete_corpus_run_says_so(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:

    def capped(request: ScanRequest, clock: Clock) -> ScanOutcome:
        outcome = run_scan(request, clock)
        report = dataclasses.replace(outcome.report, complete=False, truncated=True)
        return dataclasses.replace(outcome, report=report)

    monkeypatch.setattr("scripts.bench.run_scan", capped)
    (tmp_path / "file.txt").write_text("nothing\n")
    note = bench.bench_corpus("x", tmp_path).cells[-1]
    assert note == "incomplete run, 0 issue(s); report limit reached: the counts are a lower bound"


def test_a_corpus_alone_needs_no_git_and_prints_one_table(
    tmp_path: Path, capsys: pytest.CaptureFixture[str], monkeypatch: pytest.MonkeyPatch
) -> None:
    (tmp_path / "corpus").mkdir()
    (tmp_path / "corpus" / "note.txt").write_text("nothing here\n")
    monkeypatch.chdir(tmp_path)
    assert bench.main(["--corpus", "corpus", "--work-dir", str(tmp_path)]) == 0
    out = capsys.readouterr().out
    assert "### Entropy detector on existing files" in out
    assert "### Directory tree" not in out
    assert "- git: not used" in out
    assert local_traces(out, tmp_path) == []


# -- the command ----------------------------------------------------------------------------------


@pytest.mark.slow
@pytest.mark.requires_git
def test_the_report_holds_counts_only_no_secret_and_no_local_path(
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
    monkeypatch: pytest.MonkeyPatch,
    assert_not_leaked: Callable[..., None],
) -> None:
    corpus = tmp_path / "corpus"
    corpus.mkdir()
    (corpus / "note.txt").write_text("nothing here\n")
    monkeypatch.chdir(tmp_path)
    work = tmp_path / "work"
    work.mkdir()
    arguments = ["--files", "101,3", "--lines", "4", "--commits", "3", "--repeat", "1", "--memory"]
    code = bench.main([*arguments, "--corpus", "corpus", "--work-dir", str(work)])
    out = capsys.readouterr().out
    assert code == 0
    assert list(work.iterdir()) == [], "the temporary directory is removed"
    assert f"- Command: `python scripts/bench.py {' '.join(arguments)} --corpus corpus`" in out
    for heading in ("## Run", "### Directory tree", "### Git history", "### Entropy detector"):
        assert heading in out
    assert "- git: git version " in out
    assert "| 101 |" in out
    assert "2 of 2" in out
    assert "did not find exactly" not in out
    assert local_traces(out, tmp_path, work) == []
    assert "sha256:" not in out, "not even a redacted value is printed"
    fakes = planted_fakes("bench-tree", range(0, 101, 100)) + planted_fakes(
        "bench-history", range(0, 3, bench.PLANT_EVERY_COMMITS)
    )
    for fake in fakes:
        assert_not_leaked(out, fake, allowed_shown=0)


def test_a_failed_check_is_reported_and_exits_one(
    tmp_path: Path, capsys: pytest.CaptureFixture[str], monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(bench, "planted_line", lambda rules, index, seed: "nothing = here\n")
    monkeypatch.setattr(tempfile, "tempdir", str(tmp_path))  # the default place, kept in tmp_path
    assert bench.main(["--files", "2", "--repeat", "0"]) == 1
    out = capsys.readouterr().out
    assert "**A run did not find exactly the planted fakes, or was incomplete.**" in out
    assert "- git: not used" in out
    assert "### Git history" not in out
    assert list(tmp_path.iterdir()) == []


# -- docs/performance.md ---------------------------------------------------------------------------

PERFORMANCE = (PROJECT_ROOT / "docs" / "performance.md").read_text(encoding="utf-8")


def test_every_command_in_the_performance_document_is_one_the_script_accepts() -> None:
    commands = re.findall(r"^- Command: `python scripts/bench\.py ([^`]+)`$", PERFORMANCE, re.M)
    assert len(commands) == 4
    parser = bench.build_parser()
    for command in commands:
        args = parser.parse_args(command.split())
        assert args.files or args.commits or args.corpus
    for fact in ("- Date: ", "- secret-scanner: ", "- Operating system: ", "- Python: ", "- git: "):
        assert PERFORMANCE.count(fact) == len(commands), fact
    assert f"- secret-scanner: {__version__}" in PERFORMANCE


def test_the_tables_of_the_performance_document_have_the_scripts_columns() -> None:
    for headers in (bench.TREE_HEADERS, bench.HISTORY_HEADERS, bench.CORPUS_HEADERS):
        assert "| " + " | ".join(headers) + " |" in PERFORMANCE
    found = re.findall(r"\| (\d+) of (\d+)(?: \(incomplete run\))? \|", PERFORMANCE)
    assert len(found) == 11
    assert all(left == right for left, right in found), "every run found exactly what was planted"


def test_the_performance_document_names_no_local_path_and_quotes_the_real_limits() -> None:
    assert PERFORMANCE.isascii()
    assert local_traces(PERFORMANCE, PROJECT_ROOT, absolute_paths=False) == []
    flat = " ".join(PERFORMANCE.split())
    assert f"default time budget of {limits.MAX_RUN_SECONDS} seconds" in flat
    assert f"| `MAX_RUN_SECONDS` | {limits.MAX_RUN_SECONDS} |" in flat
    assert f"hard ceiling of {limits.MAX_RUN_SECONDS_CEILING:,} seconds" in flat
    assert f"| `MAX_FILES` | {limits.MAX_FILES:,} |" in flat
    assert f"the limit of {limits.MAX_FINDINGS_PER_FILE} findings per file" in flat
    assert f"larger than the {limits.MAX_FILE_BYTES // limits.MIB} MiB file limit" in flat
    assert "**No default was changed.**" in flat
