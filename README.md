# secret-scanner

A defensive secret scanner in Python for repositories and directories you own.

Status: under construction (Phase 1 of 6). The detection engine and the `scan`,
`scan-git` and `demo` commands do not exist yet. This file makes no claims about
behaviour that has not been built and measured; see PLAN.md for the design.

Currently available:

```
secret-scanner --version
```

## Limitations (known so far)

This section grows with the phases; Phase 6 completes it.

- `scan-git` refuses, deliberately and with exit code 3, a repository whose `.git` is a file or a
  link (a worktree or a submodule checkout: scan the main repository), whose object store uses
  alternates (`git repack -a -d` makes it self-contained), or that has an `info/grafts` file. Git
  would follow these silently and read objects or parents the scan cannot account for, so the
  tool stops instead of reporting a history that might be incomplete (PLAN.md v0.10, accepted by
  the owner on 2026-11-08; details in `docs/git-hardening.md`).
- git must be trusted and at least version 2.32. On Windows it must be `git.exe`, found on a fully
  qualified `PATH` entry or given as `--git PATH`; it is never taken from the current directory.
