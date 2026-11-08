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

### Known, deliberate refusals

- `scan-git` refuses a `.git` that is a file or a link (worktrees, submodule checkouts), object
  stores that use alternates, and repositories with grafts (exit code 3). PLAN.md v0.10, accepted
  by the owner on 2026-11-08.
