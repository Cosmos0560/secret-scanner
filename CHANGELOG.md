# Changelog

Format: newest first, one section per released version (`## <version> - <date>`). The version has
one source, `src/secret_scanner/__init__.py`; `tests/test_release_metadata.py` checks that the
newest section here names it.

## 1.0.0 - 2026-11-10

First public release. Everything below was built in the six phases of PLAN.md; the phase reports
with the measured numbers are in `docs/phase-reports.md`.

### Added

- `secret-scanner scan PATH`: scans the files of a directory tree with 13 token-format rules, a
  private key detector and an entropy detector. Read-only on the scanned tree;
  symbolic links, junctions and other reparse points are never followed; only regular files are
  opened.
- `scan --gitignore`: scans only the files git lists (tracked, plus untracked and not ignored).
- `secret-scanner scan-git REPO`: scans every blob added or modified in the history of a git
  repository (all refs, `--rev` or `--range`) through a hardened git runner and names the commit
  that introduced each secret (`docs/git-hardening.md`).
- Findings are shown redacted only: a fixed public prefix, the length and an 8-hex-digit display
  hash, plus a 128-bit fingerprint. No output format, error message or file ever holds a whole
  secret.
- Baselines: `--write-baseline FILE` and `--baseline FILE` (fingerprints and path globs),
  `--show-suppressed`, and a count of stale entries.
- Output formats: `table`, `json` (`secret-report/1`, `docs/report-schema.md`), `jsonl`
  (`secret-event/1`, shaped for mini-siem's generic JSON parser and ingested with the real
  mini-siem 1.0.0, `docs/siem-mapping.md`) and `sarif` (SARIF 2.1.0, `docs/sarif.md`).
- Exit codes for CI: 0 clean, 1 findings, 2 usage or file error, 3 git unavailable or refused,
  4 incomplete run; Ctrl-C ends any command with 130.
- `secret-scanner rules`: the built-in rules and detectors as a table or JSON (`secret-rules/1`);
  it prints no example secret.
- `secret-scanner demo`: fake secrets planted in a temporary directory and a throw-away
  repository, scanned through the real code, shown redacted and removed again, also on failure and
  on Ctrl-C. Exit code 3 without git (the history part is skipped).
- Documentation: `README.md` with real output, a claim-to-evidence table and the Limitations,
  `docs/rules.md` (generated rule table), `docs/threat-model.md`, `docs/performance.md` (measured
  with `scripts/bench.py`), `SECURITY.md` and `CONTRIBUTING.md`.

### Security

- Windows binary planting through the current directory and relative `PATH` entries, caught by
  CI run 5 before any release (details: `docs/threat-model.md`, finding F-1). git is resolved only
  from fully qualified `PATH` entries, never from the current directory itself, the system
  temporary directory tree or the scanned tree; on Windows only `git.exe` is accepted (never
  `git.cmd`, `git.bat` or other script types); `--git PATH` must be fully qualified, an existing
  regular file and, on Windows, called `git.exe`; the resolved path is normalised and always
  started by absolute name. Tests: `tests/test_git_program_resolution.py`, `tests/test_git_fs.py`.
- `secret-scanner demo` does not print the path of its temporary directory (it is random, it is
  removed at the end, and on Windows it names the user's account). The introduction and the two
  report headers show the fixed label `<temporary directory>`.

### Known, deliberate refusals

- `scan-git` refuses a `.git` that is a file or a link (worktrees, submodule checkouts), object
  stores that use alternates, and repositories with grafts (exit code 3). PLAN.md v0.10, accepted
  by the owner on 2026-11-08.

### Fixed

- `docs/siem-mapping.md` showed a command (`scan . --output events.jsonl`) that the tool refuses,
  because the output would be inside the scanned tree. The document now shows a command that
  runs, and a test runs it as written.

### Known gaps

- The SARIF output is not validated against the official schema and has not been uploaded to
  GitHub code scanning.
- A first scan of a very large, freshly written tree can run into the default time budget of 600
  seconds and end as an incomplete run (exit code 4); a configuration file cannot raise the
  budget (`docs/performance.md`).
- The full list is the Limitations section of `README.md`.
