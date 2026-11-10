#!/usr/bin/env python
"""Measure the scanner on generated input and print the numbers (PLAN.md Phase 6, D5, D18).

    python scripts/bench.py --files 1000,10000,100000 --commits 5000 --memory
    python scripts/bench.py --corpus . --corpus .venv/Lib/site-packages

Three measurements, each through the real application code (`run_scan`, `run_scan_git`):

* a generated directory tree of N small text files, one planted fake secret per 100 files;
* a generated git history of N commits (written with `git fast-import`), a planted fake per 250
  commits;
* the entropy detector's findings per MiB on directories you name (`--corpus`), by confidence.

Everything generated lives in one temporary directory that is removed at the end (`--work-dir`
puts it somewhere else). The fakes come from the generator of PLAN.md D16 and exist only there.
The output is a Markdown report for `docs/performance.md`: counts and times only, never a secret,
not even a redacted one, and no path of this machine. Each run checks itself: the number of
findings must be the number of planted fakes, or the report says so and the exit code is 1.

Time is `time.perf_counter` around one call. The first scan of the files just written is reported
apart from the `--repeat` scans that follow (their median gives the rates): the first open of a
new file costs the operating system more, which is not the scanner's time. Memory is the peak that
`tracemalloc` reports for one more call (`--memory`): Python allocations only, and that call is
not timed, because tracing slows it down.
"""

from __future__ import annotations

import argparse
import datetime
import gc
import hashlib
import io
import os
import platform
import statistics
import subprocess
import sys
import tempfile
import time
import tracemalloc
from collections import Counter
from collections.abc import Callable, Sequence
from dataclasses import dataclass
from pathlib import Path

from secret_scanner import __version__
from secret_scanner.app.common import ScanOutcome, resolve_git_program
from secret_scanner.app.scan import ScanRequest, run_scan
from secret_scanner.app.scan_git import GitScanRequest, run_scan_git
from secret_scanner.core.fakes import build_fake
from secret_scanner.core.models import Confidence, Rule
from secret_scanner.host.clock import SystemClock
from secret_scanner.services.loader import load_builtin_rules

MIB = 1024 * 1024
FILES_PER_DIRECTORY = 100
LINES_PER_FILE = 40
PLANT_EVERY_FILES = 100
PLANT_EVERY_COMMITS = 250
HISTORY_PATHS = 200
FILES_PER_COMMIT = 2
FIRST_COMMIT_EPOCH = 1_767_225_600  # 2026-01-01T00:00:00Z
PLANTED_RULES = ("aws-access-key-id", "github-token", "npm-token", "stripe-secret-key")
ENTROPY_RULES = ("entropy-base64", "entropy-hex")
HOST_LABEL = "bench"
# Plain words: no rule keyword is a part of any of them, so only planted fakes are found.
WORDS = (
    "amber", "bridge", "candle", "delta", "ember", "forest", "garden", "harbor", "island",
    "jungle", "kettle", "ladder", "meadow", "needle", "orchard", "pebble", "quartz", "river",
    "saddle", "timber", "umbrella", "valley", "window", "yonder", "zenith", "anchor", "basket",
    "copper", "dragon", "engine", "falcon", "glacier",
)  # fmt: skip


@dataclass(frozen=True, slots=True)
class Measurement:
    """One measured call: the first run, the repeat runs, the traced peak (or `None`) and the last
    outcome. The first scan of files that were just written is timed apart: the operating system
    makes the first open of a new file cost more, and that is not the scanner's time."""

    first: float
    first_complete: bool
    repeats: tuple[float, ...]
    peak_bytes: int | None
    outcome: ScanOutcome

    @property
    def median(self) -> float:
        """The median of the repeat runs (of the first run when there was no repeat)."""
        return statistics.median(self.repeats or (self.first,))

    @property
    def first_shown(self) -> str:
        return f"{self.first:.2f}" + ("" if self.first_complete else " (incomplete)")


@dataclass(frozen=True, slots=True)
class Row:
    """One line of a result table: the cells, and whether the run checked out."""

    cells: tuple[str, ...]
    ok: bool


def text_block(seed: str, lines: int = LINES_PER_FILE) -> str:
    """Deterministic, harmless text that looks a little like a settings file."""
    out = []
    for number in range(lines):
        digest = hashlib.sha256(f"{seed}/{number}".encode()).digest()
        words = [WORDS[byte % len(WORDS)] for byte in digest[:6]]
        out.append(
            f"{words[0]}_{words[1]} = {words[2]} {words[3]} {words[4]} {digest[6]}  # {words[5]}"
        )
    return "\n".join(out) + "\n"


def planted_line(rules: Sequence[Rule], index: int, seed: str) -> str:
    """A line that holds one generated fake; `index` picks the rule in turn."""
    rule = rules[index % len(rules)]
    return f'token_{index} = "{build_fake(rule, seed)}"\n'


def planted_rules() -> tuple[Rule, ...]:
    by_id = {rule.id: rule for rule in load_builtin_rules().rules}
    return tuple(by_id[rule_id] for rule_id in PLANTED_RULES)


def make_tree(
    root: Path, files: int, rules: Sequence[Rule], lines: int = LINES_PER_FILE
) -> tuple[int, int]:
    """Write `files` text files of `lines` lines under `root`; returns (bytes written, fakes
    planted)."""
    total = planted = 0
    for index in range(files):
        directory = root / f"dir_{index // FILES_PER_DIRECTORY:05d}"
        if index % FILES_PER_DIRECTORY == 0:
            directory.mkdir(parents=True)
        text = text_block(f"tree/{index}", lines)
        if index % PLANT_EVERY_FILES == 0:
            text += planted_line(rules, planted, f"bench-tree-{index}")
            planted += 1
        data = text.encode("ascii")
        (directory / f"file_{index:06d}.txt").write_bytes(data)
        total += len(data)
    return total, planted


def history_stream(commits: int, rules: Sequence[Rule]) -> tuple[bytes, int, int]:
    """A `git fast-import` stream of `commits` commits on `main`; returns it with the number of
    bytes in its blobs and the number of fakes planted. The identity is built from fragments, so
    no file holds an address (PLAN.md D17)."""
    identity = "Bench <bench" + chr(64) + "example" + "." + "invalid>"
    stream = io.BytesIO()
    total = planted = 0
    for commit in range(commits):
        message = f"Change {commit}\n".encode("ascii")
        stream.write(b"commit refs/heads/main\n")
        stream.write(f"mark :{commit + 1}\n".encode("ascii"))
        stream.write(f"committer {identity} {FIRST_COMMIT_EPOCH + commit * 60} +0000\n".encode())
        stream.write(b"data %d\n%b" % (len(message), message))
        if commit:
            stream.write(f"from :{commit}\n".encode("ascii"))
        for slot in range(FILES_PER_COMMIT):
            path = f"src/module_{(commit * FILES_PER_COMMIT + slot) % HISTORY_PATHS:03d}.txt"
            text = text_block(f"history/{commit}/{slot}")
            if slot == 0 and commit % PLANT_EVERY_COMMITS == 0:
                text += planted_line(rules, planted, f"bench-history-{commit}")
                planted += 1
            data = text.encode("ascii")
            stream.write(f"M 100644 inline {path}\n".encode("ascii"))
            stream.write(b"data %d\n%b\n" % (len(data), data))
            total += len(data)
        stream.write(b"\n")
    return stream.getvalue(), total, planted


def git_environment(git: str, home: Path) -> dict[str, str]:
    """A from-scratch environment for the two git commands that build the repository: no user or
    system configuration, nothing inherited."""
    environment = {
        "PATH": os.path.dirname(git),
        "HOME": str(home),
        "GIT_CONFIG_NOSYSTEM": "1",
        "GIT_CONFIG_GLOBAL": os.devnull,
        "GIT_TERMINAL_PROMPT": "0",
        "LC_ALL": "C",
    }
    if sys.platform == "win32":
        environment["SYSTEMROOT"] = os.environ.get("SYSTEMROOT", "")
        environment["TEMP"] = environment["TMP"] = str(home)
    return environment


def make_history(git: str, repo: Path, home: Path, commits: int, rules: Sequence[Rule]) -> int:
    """Create a repository at `repo` with `commits` generated commits; returns the fakes planted."""
    repo.mkdir(parents=True)
    home.mkdir(parents=True)
    environment = git_environment(git, home)
    stream, _, planted = history_stream(commits, rules)
    for argv, data in (
        ([git, "init", "--quiet", "--template=", "--initial-branch=main", str(repo)], None),
        ([git, "fast-import", "--quiet"], stream),
    ):
        subprocess.run(  # an argument list, never a shell; the program is an absolute path
            argv,
            input=data,
            cwd=repo,
            env=environment,
            check=True,
            capture_output=True,
            timeout=600,
        )
    return planted


def git_version(git: str, home: Path) -> str:
    done = subprocess.run(
        [git, "version"],
        env=git_environment(git, home),
        check=True,
        capture_output=True,
        timeout=60,
    )
    return done.stdout.decode("ascii", errors="replace").strip()


def measure(action: Callable[[], ScanOutcome], *, repeat: int, memory: bool) -> Measurement:
    """Time `action` once, then `repeat` more times; with `memory`, run it once more under
    `tracemalloc`."""

    def timed() -> tuple[float, ScanOutcome]:
        gc.collect()
        started = time.perf_counter()
        result = action()
        return time.perf_counter() - started, result

    first, outcome = timed()
    first_complete = outcome.report.complete
    repeats = []
    for _ in range(repeat):
        again, outcome = timed()
        repeats.append(again)
    peak = None
    if memory:
        gc.collect()
        tracemalloc.start()
        try:
            outcome = action()
            peak = tracemalloc.get_traced_memory()[1]
        finally:
            tracemalloc.stop()
    return Measurement(first, first_complete, tuple(repeats), peak, outcome)


def _mib(count: int) -> str:
    return f"{count / MIB:.1f}"


def _rate(amount: float, seconds: float) -> str:
    return f"{amount / seconds:,.0f}"


def _per_mib(count: int, megabytes: float) -> str:
    return f"{count / megabytes:.2f}" if megabytes else "n/a"


def _peak(measured: Measurement) -> str:
    return "not measured" if measured.peak_bytes is None else _mib(measured.peak_bytes)


def _check(found: int, planted: int, complete: bool) -> tuple[str, bool]:
    ok = complete and found == planted
    return f"{found} of {planted}" + ("" if complete else " (incomplete run)"), ok


def bench_tree(work: Path, files: int, *, lines: int, repeat: int, memory: bool) -> Row:
    """Generate a tree of `files` files of `lines` lines, scan it, and return the table row."""
    root = work / f"tree-{files}"
    _, planted = make_tree(root, files, planted_rules(), lines)
    request = ScanRequest(path=str(root), host_label=HOST_LABEL)
    measured = measure(lambda: run_scan(request, SystemClock()), repeat=repeat, memory=memory)
    report = measured.outcome.report
    stats = report.stats
    found, ok = _check(len(report.findings), planted, report.complete)
    cells = (
        f"{files:,}",
        _mib(stats.bytes_scanned),
        measured.first_shown,
        f"{measured.median:.2f}",
        _rate(stats.files_scanned, measured.median),
        f"{stats.bytes_scanned / MIB / measured.median:.1f}",
        found,
        _peak(measured),
    )
    return Row(cells, ok and stats.files_scanned == files)


def bench_history(work: Path, git: str, commits: int, *, repeat: int, memory: bool) -> Row:
    """Generate a history of `commits` commits, scan it, and return the table row."""
    repo = work / f"history-{commits}"
    planted = make_history(git, repo, work / f"home-{commits}", commits, planted_rules())
    request = GitScanRequest(path=str(repo), git=git, host_label=HOST_LABEL)
    measured = measure(lambda: run_scan_git(request, SystemClock()), repeat=repeat, memory=memory)
    report = measured.outcome.report
    stats = report.stats
    found, ok = _check(len(report.findings), planted, report.complete)
    cells = (
        f"{stats.commits:,}",
        f"{stats.blobs_scanned:,}",
        _mib(stats.bytes_scanned),
        measured.first_shown,
        f"{measured.median:.2f}",
        _rate(stats.commits, measured.median),
        _rate(stats.blobs_scanned, measured.median),
        f"{stats.bytes_scanned / MIB / measured.median:.1f}",
        found,
        _peak(measured),
    )
    return Row(cells, ok and stats.commits == commits)


def bench_corpus(label: str, path: Path) -> Row:
    """Scan an existing directory at the lowest confidence and count the entropy detector's
    findings by confidence (PLAN.md D5). Only counts leave this function."""
    request = ScanRequest(path=str(path), min_confidence=Confidence.LOW, host_label=HOST_LABEL)
    started = time.perf_counter()
    report = run_scan(request, SystemClock()).report
    seconds = time.perf_counter() - started
    entropy = [f for f in report.findings if f.rule_id in ENTROPY_RULES]
    counts = Counter((f.rule_id, f.confidence) for f in entropy)
    reported = sum(1 for f in entropy if f.confidence.at_least(Confidence.MEDIUM))
    megabytes = report.stats.bytes_scanned / MIB
    notes = [] if report.complete else [f"incomplete run, {len(report.issues)} issue(s)"]
    if report.truncated:
        notes.append("report limit reached: the counts are a lower bound")
    cells = (
        f"`{label}`",
        f"{report.stats.files_scanned:,}",
        f"{megabytes:.1f}",
        f"{seconds:.1f}",
        str(reported),
        _per_mib(reported, megabytes),
        str(counts[("entropy-base64", Confidence.LOW)]),
        str(counts[("entropy-hex", Confidence.LOW)]),
        _per_mib(len(entropy), megabytes),
        str(len(report.findings) - len(entropy)),
        "; ".join(notes) or "complete",
    )
    return Row(cells, True)


def table(headers: Sequence[str], rows: Sequence[Row]) -> list[str]:
    lines = ["| " + " | ".join(headers) + " |", "|" + "---|" * len(headers)]
    lines += ["| " + " | ".join(row.cells) + " |" for row in rows]
    return lines


TREE_HEADERS = (
    "Files",
    "MiB scanned",
    "First scan, s",
    "Repeat scan, s",
    "Files/s",
    "MiB/s",
    "Findings (found of planted)",
    "Peak MiB (tracemalloc)",
)
HISTORY_HEADERS = (
    "Commits",
    "Blobs scanned",
    "MiB scanned",
    "First scan, s",
    "Repeat scan, s",
    "Commits/s",
    "Blobs/s",
    "MiB/s",
    "Findings (found of planted)",
    "Peak MiB (tracemalloc)",
)
CORPUS_HEADERS = (
    "Directory",
    "Files scanned",
    "MiB scanned",
    "Seconds",
    "Entropy findings at the default",
    "per MiB",
    "base64, low confidence",
    "hex, low confidence",
    "All entropy findings per MiB",
    "Rule and key findings",
    "Run",
)


def machine_lines(git: str | None, home: Path, arguments: Sequence[str], repeat: int) -> list[str]:
    """Where and how the numbers were taken. No path, host name or account name is included."""
    return [
        f"- Date: {datetime.date.today().isoformat()}",
        f"- Command: `{' '.join(['python', 'scripts/bench.py', *arguments])}`",
        f"- secret-scanner: {__version__}",
        f"- Operating system: {platform.system()} {platform.release()} ({platform.version()})",
        f"- Machine: {platform.machine()}, {os.cpu_count()} logical processors"
        + (f", {platform.processor()}" if platform.processor() else ""),
        f"- Python: {platform.python_implementation()} {platform.python_version()}",
        f"- git: {'not used' if git is None else git_version(git, home)}",
        f"- Timing: one first scan, then {repeat} repeat scan(s); rates use the repeat median",
    ]


def _sizes(text: str) -> list[int]:
    try:
        sizes = [int(part) for part in text.split(",") if part.strip()]
    except ValueError:
        raise argparse.ArgumentTypeError("a comma-separated list of whole numbers") from None
    if any(size < 1 for size in sizes):
        raise argparse.ArgumentTypeError("every size must be at least 1")
    return sizes


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="bench.py",
        description="Measure secret-scanner on generated input.",
        allow_abbrev=False,
    )
    parser.add_argument("--files", type=_sizes, default=[], metavar="N[,N...]")
    parser.add_argument(
        "--lines", type=int, default=LINES_PER_FILE, metavar="N", help="lines per generated file"
    )
    parser.add_argument("--commits", type=_sizes, default=[], metavar="N[,N...]")
    parser.add_argument("--corpus", action="append", default=[], metavar="DIR")
    parser.add_argument(
        "--repeat", type=int, default=3, metavar="N", help="timed scans after the first (median)"
    )
    parser.add_argument("--memory", action="store_true", help="one more run under tracemalloc")
    parser.add_argument("--work-dir", metavar="DIR", help="where the temporary directory is made")
    return parser


def run(args: argparse.Namespace, arguments: Sequence[str], work: Path) -> tuple[list[str], bool]:
    """Do every measurement asked for; returns the report lines and whether all checked out."""
    git = resolve_git_program(git=None, root=str(work)) if args.commits else None
    home = work / "home"
    home.mkdir()
    lines = ["## Run", "", *machine_lines(git, home, arguments, args.repeat), ""]
    rows: list[Row] = []
    if args.files:
        trees = [
            bench_tree(work, n, lines=args.lines, repeat=args.repeat, memory=args.memory)
            for n in args.files
        ]
        lines += ["### Directory tree", "", *table(TREE_HEADERS, trees), ""]
        rows += trees
    if git is not None:
        histories = [
            bench_history(work, git, n, repeat=args.repeat, memory=args.memory)
            for n in args.commits
        ]
        lines += ["### Git history", "", *table(HISTORY_HEADERS, histories), ""]
        rows += histories
    if args.corpus:
        corpora = [bench_corpus(label, Path(label).resolve()) for label in args.corpus]
        lines += ["### Entropy detector on existing files", "", *table(CORPUS_HEADERS, corpora), ""]
    ok = all(row.ok for row in rows)
    if not ok:
        lines += ["**A run did not find exactly the planted fakes, or was incomplete.**", ""]
    return lines, ok


def main(argv: Sequence[str] | None = None) -> int:
    arguments = list(sys.argv[1:] if argv is None else argv)
    args = build_parser().parse_args(arguments)
    with tempfile.TemporaryDirectory(
        prefix="secret-scanner-bench-", dir=args.work_dir
    ) as directory:
        shown = [a for a in arguments if a not in ("--work-dir", args.work_dir)]
        lines, ok = run(args, shown, Path(directory).resolve())
    print("\n".join(lines))
    return 0 if ok else 1


if __name__ == "__main__":  # pragma: no cover - the entry point; tests call main()
    sys.exit(main())
