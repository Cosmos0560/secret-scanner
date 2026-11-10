# Performance

Measured numbers only. Every table below is the output of `scripts/bench.py`, pasted as printed,
with the machine, the versions, the date and the exact command above it. Nothing here is an
estimate; where a figure is derived from a measured one, the arithmetic is shown. No other
document quotes a number that is not here. `tests/test_bench.py` checks
that the script's self-check works (it must find exactly the fake secrets it planted) and that
every command quoted here is one the script accepts.

What is measured: the real application code (`run_scan`, `run_scan_git`) inside one Python
process, on generated input. Not measured: the start of the interpreter, other hardware, real
repositories.

## The machine

| | |
|---|---|
| Processor | Intel Core Ultra 7 155U, 12 cores, 14 logical processors |
| Memory | 31.5 GiB |
| Disk | NVMe SSD |
| Operating system | Windows 11 Pro, version 10.0.26300; real-time antivirus protection on |
| Python | CPython 3.13.14 |
| git | 2.54.0.windows.1 |
| Date | 2026-11-10 |

These are the Windows values; the Linux run further down states its own.

Processor, memory, disk and the antivirus state were read with `Get-CimInstance`,
`Get-PhysicalDisk` and `Get-MpComputerStatus`; the rest is printed by the script. The scanner is
single-threaded, so the number of processors does not matter to it.

## How to read the tables

- **First scan** is the first scan of files the script has just written. **Repeat scan** is the
  median of the three scans that follow. The two differ a lot on this machine, see below.
- **Files/s, MiB/s, Commits/s, Blobs/s** are computed from the repeat median.
- **Findings (found of planted)**: the script plants one fake secret per 100 files, or per 250
  commits, and the scan must find exactly those. Every run below did.
- **Peak MiB (tracemalloc)** is the peak of the Python allocations made during one more scan,
  which is not timed. It does not include the interpreter, the loaded rules or memory that git
  uses.

## Directory tree: many small files

Generated text files of 40 lines (about 2 KiB each), 100 per directory.

- Date: 2026-11-10
- Command: `python scripts/bench.py --files 1000,10000,100000 --commits 1000,5000 --memory`
- secret-scanner: 1.0.0
- Operating system: Windows 11 (10.0.26300)
- Machine: AMD64, 14 logical processors, Intel64 Family 6 Model 170 Stepping 4, GenuineIntel
- Python: CPython 3.13.14
- git: git version 2.54.0.windows.1
- Timing: one first scan, then 3 repeat scan(s); rates use the repeat median

| Files | MiB scanned | First scan, s | Repeat scan, s | Files/s | MiB/s | Findings (found of planted) | Peak MiB (tracemalloc) |
|---|---|---|---|---|---|---|---|
| 1,000 | 1.9 | 7.14 | 0.41 | 2,447 | 4.7 | 10 of 10 | 1.0 |
| 10,000 | 19.3 | 200.10 | 4.35 | 2,299 | 4.4 | 100 of 100 | 1.1 |
| 100,000 | 193.0 | 600.01 (incomplete) | 600.05 | 167 | 0.3 | 1000 of 1000 | 1.8 |

**The 100,000-file row is not a throughput number.** Its first scan ran into the default time
budget of 600 seconds and ended as an incomplete run, which is what the tool is designed to do
(exit code 4, never a clean result). The repeat median is 600.05 seconds too, so at least two of
the three repeat scans also ran into the budget: each scan got further into files that no scan
had opened before. Only the last scan, the one under `tracemalloc`, was complete and found all
1,000 planted fakes. The 167 files per second in that row is the budget divided into the tree, not
the speed of the scanner. The 1,000 and 10,000 rows are the scanner's speed on files that have
been opened before: about 2,300 to 2,450 small files per second.

**The first scan of freshly written files is slow on this machine**: 7 ms per file for 1,000
files, 20 ms per file for 10,000, against 0.4 ms per file on a repeat scan. The scanner does the
same work both times, so the difference is the cost of opening a new file for the first time on
this system, where real-time antivirus protection is on. What exactly takes the time was not
investigated further, and no run was made with the protection off. It matters in practice: a
directory that was just written (a fresh checkout, a build output) is the slow case.

## Directory tree: larger files

The same generator with 4,000 lines per file (about 190 KiB each), to measure the detectors
rather than the cost per file.

- Date: 2026-11-10
- Command: `python scripts/bench.py --files 500 --lines 4000 --memory`
- secret-scanner: 1.0.0
- Operating system: Windows 11 (10.0.26300)
- Machine: AMD64, 14 logical processors, Intel64 Family 6 Model 170 Stepping 4, GenuineIntel
- Python: CPython 3.13.14
- git: not used
- Timing: one first scan, then 3 repeat scan(s); rates use the repeat median

| Files | MiB scanned | First scan, s | Repeat scan, s | Files/s | MiB/s | Findings (found of planted) | Peak MiB (tracemalloc) |
|---|---|---|---|---|---|---|---|
| 500 | 96.5 | 29.11 | 22.97 | 22 | 4.2 | 5 of 5 | 1.4 |

About 4.2 MiB of text per second through the rules, the private key detector and the entropy
detector, on one core. The generated text holds no rule keyword, so the keyword pre-filter skips
the rule patterns on almost every line; the entropy detector looks at every line.

## Git history

A generated history written with `git fast-import`: every commit changes 2 of 200 files of about
2 KiB. The numbers are in the first run above (same command, same machine):

| Commits | Blobs scanned | MiB scanned | First scan, s | Repeat scan, s | Commits/s | Blobs/s | MiB/s | Findings (found of planted) | Peak MiB (tracemalloc) |
|---|---|---|---|---|---|---|---|---|---|
| 1,000 | 2,000 | 3.9 | 2.58 | 2.00 | 499 | 998 | 1.9 | 4 of 4 | 1.3 |
| 5,000 | 10,000 | 19.3 | 6.53 | 7.92 | 631 | 1,263 | 2.4 | 20 of 20 | 3.2 |

The time includes starting git several times (version check, discovery, the history walk and the
two `cat-file` processes), so a short history has a lower rate than a long one. For the 5,000
commits the first scan was faster than the repeat median. `git fast-import` writes the objects
into one pack file, so a history scan does not open thousands of new files the way a directory
scan does.

## The same measurement on Linux (WSL 2, same hardware)

The same script and command in WSL 2 Ubuntu on the same computer, from a clone of commit
`9c9ea00`. The generated files were in `/tmp`, which is a `tmpfs` there: they were in memory, so
no disk is part of these numbers. Python is 3.14.4 here (outside the CI matrix) and 3.13.14 on
Windows, so the two tables differ in operating system, file system and Python version at once.

- Date: 2026-11-10
- Command: `python scripts/bench.py --files 1000,10000,100000 --commits 1000,5000 --memory`
- secret-scanner: 1.0.0
- Operating system: Linux 6.18.33.2-microsoft-standard-WSL2 (#1 SMP PREEMPT_DYNAMIC Thu Jun 18 21:54:43 UTC 2026)
- Machine: x86_64, 14 logical processors
- Python: CPython 3.14.4
- git: git version 2.53.0
- Timing: one first scan, then 3 repeat scan(s); rates use the repeat median

| Files | MiB scanned | First scan, s | Repeat scan, s | Files/s | MiB/s | Findings (found of planted) | Peak MiB (tracemalloc) |
|---|---|---|---|---|---|---|---|
| 1,000 | 1.9 | 0.18 | 0.17 | 5,882 | 11.3 | 10 of 10 | 1.0 |
| 10,000 | 19.3 | 1.79 | 1.70 | 5,874 | 11.3 | 100 of 100 | 1.1 |
| 100,000 | 193.0 | 29.71 | 33.48 | 2,987 | 5.8 | 1000 of 1000 | 1.7 |

| Commits | Blobs scanned | MiB scanned | First scan, s | Repeat scan, s | Commits/s | Blobs/s | MiB/s | Findings (found of planted) | Peak MiB (tracemalloc) |
|---|---|---|---|---|---|---|---|---|---|
| 1,000 | 2,000 | 3.9 | 1.10 | 1.26 | 793 | 1,586 | 3.1 | 4 of 4 | 2.3 |
| 5,000 | 10,000 | 19.3 | 5.85 | 6.12 | 818 | 1,635 | 3.2 | 20 of 20 | 4.4 |

Here the first scan costs the same as a repeat scan, and 100,000 files are scanned completely in
about 30 seconds, far inside the time budget. The rate for 100,000 files is about half the rate
for 10,000; why was not investigated.

## The entropy detector on real files (PLAN.md D5)

How many findings the entropy detector produces at its default thresholds, on this repository's
working tree (default excluded directories skipped) and on the packages installed in the
project's virtual environment. Only counts are printed.

- Date: 2026-11-10
- Command: `python scripts/bench.py --corpus . --corpus .venv/Lib/site-packages`
- secret-scanner: 1.0.0
- Operating system: Windows 11 (10.0.26300)
- Machine: AMD64, 14 logical processors, Intel64 Family 6 Model 170 Stepping 4, GenuineIntel
- Python: CPython 3.13.14
- git: not used
- Timing: one first scan, then 3 repeat scan(s); rates use the repeat median

| Directory | Files scanned | MiB scanned | Seconds | Entropy findings at the default | per MiB | base64, low confidence | hex, low confidence | All entropy findings per MiB | Rule and key findings | Run |
|---|---|---|---|---|---|---|---|---|---|---|
| `.` | 167 | 1.5 | 4.6 | 0 | 0.00 | 15 | 0 | 10.24 | 0 | complete |
| `.venv/Lib/site-packages` | 2,426 | 23.7 | 59.0 | 0 | 0.00 | 1185 | 0 | 49.95 | 0 | incomplete run, 5 issue(s) |

- At the default (`--min-confidence medium`) the entropy detector reported **nothing** in either
  corpus: 0 findings in 25.2 MiB. A high-entropy string is reported at the default only when its
  line assigns it to a name such as `token` or `secret`.
- With `--min-confidence low` it reported 15 strings in this repository and at least 1,185 in the
  installed packages (about 50 per MiB): hashes, encoded data and identifiers, none of them next
  to a suggestive name. This is why bare high-entropy strings are not reported by default.
- The second run was incomplete, so its counts are lower bounds. A separate `--format json` scan
  of the same directory showed the five issues: four files reached the limit of 200 findings per
  file, and one file is larger than the 8 MiB file limit and was not scanned.
- The "Seconds" column of this table is one scan, not a repeat median (the timing line printed by
  the script applies to the generated trees only).
- The corpus is whatever was installed on 2026-11-10 (the development dependencies of this
  project); it is a sanity check of the default thresholds, not a benchmark others can repeat
  exactly.

## The limits of PLAN.md D18 against these measurements

D18 says that a default changes only with a measured reason. Checked against the numbers above:

| Limit | Default | What was measured | Result |
|---|---|---|---|
| `MAX_RUN_SECONDS` | 600 | 4.2 to 4.7 MiB/s and about 2,300 small files per second on files opened before; 7 to 20 ms per file on files just written | 600 s x 4.2 MiB/s = 2,520 MiB: at the measured rate the time budget is reached before `MAX_TOTAL_BYTES`. A first scan of 100,000 freshly written files did not finish inside it. |
| `MAX_TOTAL_BYTES` | 4 GiB | not reached in any run (largest: 193 MiB) | On this machine the time budget stops a scan first. |
| `MAX_FILES` | 200,000 | 100,000 files and 1,000 directories scanned completely (the traced run on Windows, every run on Linux) | Not reached. |
| `MAX_FILE_BYTES` | 8 MiB | largest generated file about 190 KiB; one real file above the limit was skipped and reported | Memory for a file near the limit was not measured. |
| `MAX_GIT_COMMITS`, `MAX_GIT_BLOBS` | 200,000 / 1,000,000 | 5,000 commits and 10,000 blobs in 7.9 s | Not reached. Nothing larger than 5,000 commits was measured. |
| `MAX_FINDINGS_PER_FILE` | 200 | reached by four files of the installed packages at low confidence | Works as designed: recorded as an issue, run incomplete. |

**No default was changed.** The one limit the measurements put in question is `MAX_RUN_SECONDS`:
a configuration file can lower a limit but not raise it, so a tree that needs more than 600
seconds cannot be scanned completely in one run. On Windows with real-time protection that was a
first scan of 100,000 new files; on Linux the same tree took 30 seconds. Decided for 1.0.0
(2026-11-11): the default stays 600 seconds and a configuration file still only lowers limits.
The ways around it are to scan the tree in parts, or to scan again: a second scan of the same
files is fast. A possible later addition, not built: a command-line option for the person running
the tool (never a setting in a repository's configuration) that raises the time budget up to its
hard ceiling of 3,600 seconds.

## What these numbers do not say

- One computer and one day: Windows on its disk, and Linux inside WSL 2 on a memory file system.
  Other hardware, a real disk under Linux, another antivirus product or none will give other
  numbers.
- Generated text is not a real repository. Real files have longer lines, more keyword hits (each
  one runs a rule's pattern) and other size distributions.
- Peak memory is Python's own allocations during a scan of small files. A scan reads one file at a
  time, up to the file limit, so a tree with files near 8 MiB needs more; that was not measured.
- Nothing was measured near the hard ceilings of D18.
