# Changelog

Format: newest first. Versions follow the PLAN.md phases until the first release.

## Unreleased

### Security

- Windows binary planting through the current directory and relative `PATH` entries, caught by
  CI run 5 (details: `docs/threat-model.md`, finding F-1). git is now resolved only from fully
  qualified `PATH` entries, never from the current directory itself, the system temporary
  directory tree or the scanned tree; on Windows only `git.exe` is accepted (never `git.cmd`,
  `git.bat` or other script types); `--git PATH` must be fully qualified, an existing regular file
  and, on Windows, called `git.exe`; the resolved path is normalised and always started by
  absolute name. New tests in `tests/test_git_program_resolution.py` and `tests/test_git_fs.py`.

### Added

- `scan-git` and `scan --gitignore` (Phase 4): git history scanning through the hardened runner
  (`docs/git-hardening.md`).
- `--format jsonl` (Phase 5): one finding per line and a final summary line, schema
  `secret-event/1`, shaped for mini-siem's generic JSON parser; ingested with the real mini-siem
  1.0.0 (`docs/siem-mapping.md`).
- `--format sarif` (Phase 5): SARIF 2.1.0 with the rule list, severity levels, `security-severity`,
  percent-encoded artifact URIs, fingerprints, suppressions and notifications for scan issues
  (`docs/sarif.md`). Not validated against the official schema and not uploaded to GitHub code
  scanning: both are listed known gaps.
- `secret-scanner rules` (Phase 5): the built-in rules and detectors as a table or JSON
  (`secret-rules/1`, `docs/report-schema.md`); it prints no example secret.
- `secret-scanner demo` (Phase 5): fake secrets planted in a temporary directory and a throw-away
  repository, scanned through the real code, shown redacted and removed again, also on failure and
  on Ctrl-C. Exit code 3 without git (the history part is skipped).
- Ctrl-C ends any command with exit code 130 and the message `interrupted`.

### Known, deliberate refusals

- `scan-git` refuses a `.git` that is a file or a link (worktrees, submodule checkouts), object
  stores that use alternates, and repositories with grafts (exit code 3). PLAN.md v0.10, accepted
  by the owner on 2026-11-08.
