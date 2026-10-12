# Phase reports

One entry per phase, appended in order. Each entry ends with the exact 5-line report required by
CLAUDE.md section 2, step 5. The last entry is the one a new session reads first.

## In progress

Nothing. Phase 1 is complete; Phase 2 (detection engine) has not started. CI has not run yet: the
owner adds the remote, pushes, and reports the Actions result.

## Phase 1 - Foundation, gate, hook, CI, pure core (2026-10-12)

Measured on this machine (Windows 11, Python 3.13.14, git 2.54.0.windows.1):

- Default gate (`python scripts/gate.py`): 17 s in total (pytest 14 s), 701 tests.
- Full gate (`python scripts/gate.py --full`): 68 s in total, 702 tests. The one `slow` test, the
  exhaustive sanitiser sweep over every code point, needs about 7 s alone and about 50 s under
  coverage tracing; it is chunked for that reason.
- WSL Ubuntu (Python 3.14.4, git 2.53.0, outside the CI matrix as CLAUDE.md allows): full gate
  7 s in total, 702 tests, 100.00% coverage, run on the committed code.
- Commits of the phase went through `python scripts/gate.py && git commit`, one per slice: skeleton
  and gate, hook, core modules, hygiene and CI policy, sanitiser sweep, this report.

Deviations (all also in the PLAN.md changelog, v0.3, awaiting acceptance):

1. `Rule` is not in `core/models.py`: it needs the guarded pattern type from `regex_guard`
   (Phase 2). `Match` stays in `core/detect/match.py` as the plan says.
2. `ScanStats` keeps the skip counters as flat integer fields, not a mapping.
3. `Limits.with_overrides` is lower-only (D19: "lower only"); the D18 ceilings are a separate hard
   bound that is also checked.
4. The architecture checker enforces two things CLAUDE.md states as style: core purity (`core/`
   imports no `os`, `sys`, `io`, `pathlib`, `time`, `shutil`, `tempfile`, `glob`, `subprocess`) and
   the `sys.platform` guard rule (no `os.name`, no `platform.system`).
5. Coverage is measured over `src/secret_scanner` and `scripts` (the scripts are security-relevant).
6. `authors` in `pyproject.toml` and the LICENSE holder are the placeholder
   "secret-scanner authors": the owner's name is not known to the session. Replace it.
7. The type-walk test ("nothing reachable from `Report` can hold a secret") was written now,
   because the models exist; the plan lists it under Phase 2.

Decisions taken inside the plan's room (not deviations, recorded so they can be challenged):

- The hook treats quoted text as data, analyses nested `bash -c`, `sh -c`, `powershell -Command`,
  `cmd /c`, `wsl ... -e` and `$(...)` up to 4 levels, skips here-document bodies, and blocks every
  `git tag` command (including listing) and every `git add` of `.`, `./`, `*`, `:/`, `-A`, `--all`.
- `git config` is blocked for any key starting with `user.` (read or write).
- A commit command whose text (or `-F` file) contains `Co-Authored-By:` is blocked, also when the
  text only discusses the trailer with a colon.

Known gaps are listed in the 5-line report below.

```
Built: git repository on main, .venv (3.13), pyproject (hatchling, PyYAML, dev extras, ruff, mypy strict for linux and win32, pytest markers, branch coverage floor 85), CLI with --version only, six-step gate (scripts/gate.py, --full, --log), architecture checker (25 rule ids, fails closed), PreToolUse hook for Bash and PowerShell (gate must run alone plus the D20 b machine rules) registered in .claude/settings.json and seen blocking live, CI workflow (ubuntu-24.04 and windows-latest x 3.11/3.12/3.13), pure core (limits, errors and exit codes, models, sanitize, pathrules, redact, fingerprint, clock), test infrastructure (environment isolation, socket blocker, assert_not_leaked, tests/gitrepo.py with the D17 identity, hygiene checks with positive controls)
Tests added: 702 (701 in the default gate, 1 slow): hook 199, architecture checker 170 (every rule id has planted violations and allowed counterexamples; real tree passes; cycle; syntax error fails closed), pathrules 94 (both OS flavours), hygiene 65 (characters, secret files, emails, minimal fake-secret set with temporary-repository controls), sanitiser 50, redact 19, test infrastructure 19, limits 16 and exit-code drift against PLAN.md, fingerprint 13 (golden vectors), errors 13, CLI 12, gate 10, CI policy 9, models 9 (incl. type-walk), clock 4
Real coverage: 100.00% (branch, src/secret_scanner and scripts) in the full gate on Windows and in the full gate on WSL Ubuntu; floor 85
Known gaps: CI not yet run (workflow is only parsed by tests; action versions cannot be checked offline); Python 3.11 and 3.12 not run locally (CI matrix covers them); hook is a text analysis and cannot see aliases, variables, -EncodedCommand or scripts, does not block git commit -a, -c user.* or --author (not in D20 b), and fails open if the venv interpreter it names is missing; architecture checker's same-layer table lists only Phase 1 modules and must be extended by each phase; hygiene uses the minimal format set until Phase 2 switches it to the engine; sanitize with max_chars=None is unbounded, callers must pass a bound for untrusted input; full gate takes 68 s because of the exhaustive sweep; author name is a placeholder
Deviations from PLAN.md: Rule not yet in core/models.py (needs Phase 2 regex_guard); ScanStats skip counters are flat fields; Limits overrides are lower-only with ceilings as a separate bound; checker enforces core purity and the sys.platform guard rule; coverage also covers scripts; placeholder authors/LICENSE holder; type-walk test written in Phase 1 (all marked awaiting acceptance in the PLAN.md changelog)
```
