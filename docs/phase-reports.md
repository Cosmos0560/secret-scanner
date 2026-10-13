# Phase reports

One entry per phase, appended in order. Each entry ends with the exact 5-line report required by
CLAUDE.md section 2, step 5. The last entry is the one a new session reads first.

## In progress

Nothing. Phase 3 is complete (entry at the end of this file). Phase 4 (git history scan) is next;
its decisions D1, D2, D13 (`--gitignore`) and D17 are approved in PLAN.md section 0.

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

## Phase 2 - Detection engine (2026-10-12)

### Step 0 - Phase 1 follow-ups (own commits, each through the gate)

- (a) Author: `pyproject.toml` and `LICENSE` now name the owner (copyright 2026). No test pinned
  the placeholder.
- (b) Hook gaps closed in `scripts/hooks/guard_gate.py`: `git commit -a` / `--all` (also inside
  short-flag clusters such as `-am`, with option values read as values, so `-m -a` is a message),
  `git commit --author` (also abbreviated, as git accepts unambiguous prefixes), any git command
  with `-c user.*`, `--config user.*` or `--config-env user.*`, and (a small addition, because
  CLAUDE.md section 1 names them) `GIT_AUTHOR_*` / `GIT_COMMITTER_*` assignments in front of a
  commit-like command. `git tag` stays blocked entirely. Planted violations and allowed
  counterexamples for each family are in `tests/test_hook_guard_gate.py`; the live hook was seen
  blocking `git commit -a` in this session.
- (c) Hook robustness: `.claude/settings.json` now runs
  `sh "$CLAUDE_PROJECT_DIR/scripts/hooks/run_guard.sh"`. The launcher tries `py -3`, `python3`,
  `python`, then the venv interpreters, uses the first that passes a version probe (skipping a
  Microsoft Store stub or a Python older than 3.10), and **exits 2 with a message when none
  runs**, so a missing interpreter blocks instead of silently allowing everything (exit 127 is a
  non-blocking error in Claude Code's hook protocol). The choice is explained in CLAUDE.md
  section 3. Tested with the real launcher, a copy in a tree with no `.venv`, a copy with no
  interpreter at all, and stand-in interpreters (`requires_sh` marker, which fails CI when `sh`
  is missing there). Residual risk: if `sh` itself cannot start, the guard is not in force
  (documented).
- (d) No file named `file` exists, is tracked, or ever existed in the history of any ref
  (`git log --all --name-only`). I cannot tell what produced that entry in the earlier edit list
  (nothing in this repository did); no action was needed.

### Measured on this machine (Windows 11, Python 3.13.14, git 2.54.0.windows.1)

- Default gate (`python scripts/gate.py`): 56 s to 60 s in total (pytest 52 s to 56 s), 1417
  tests (17 `slow` deselected), 100.00% branch coverage. It was 17 s to 20 s at the end of
  Phase 1; the growth is the per-rule table (150 tests) and the guard's grammar table (166). The
  CLAUDE.md target is under 60 s, so this is at the target.
- Full gate (`python scripts/gate.py --full`): 140 s in total, 1434 tests, 100.00%. The slow tests
  take about 80 s under coverage tracing, about 50 s of it the Phase 1 code-point sweep.
- WSL Ubuntu (Python 3.14.4, outside the CI matrix as CLAUDE.md allows): full gate 13 s in total,
  1434 tests, 100.00%, run on the committed code.
- Python 3.11 and 3.12 interpreters exist locally but CLAUDE.md allows no further venv, so only a
  read-only syntax parse of `src`, `tests` and `scripts` was done with them (no errors). The CI
  matrix is the real check.
- ReDoS tripwire (`slow`): every rule, the entropy detector and the private key scanner over
  adversarial lines of 256 KiB (runs of the charset, repeated near misses, alternating near
  misses, repeated whole fakes, printable ASCII, a secret at the end of a maximum-length line):
  at most 0.15 s per line for the whole engine, against a ceiling of 20 s.

### What the tripwire and the tests found (bugs fixed in this phase)

1. The first tripwire run took 12 s for one 256 KiB line: columns were recomputed from the start
   of the line for every match (quadratic), overlap resolution compared every hit with every
   other, and the entropy context lookup scanned all key ends per token. Fixed with a
   `ColumnCursor`, a bisect-based interval check and a nearest-key lookup; a randomized test
   compares the resolution with a naive reference.
2. A control character in a YAML file escaped as an uncaught `ReaderError` raised in the loader's
   constructor; it is now a `ConfigError` with a position and no content.
3. A rule with a checksum and a too-short fake raised `ValueError`; it is now a `ConfigError`.
4. Disabling the keyword pre-filter also disabled the rule's context words, so the result was
   not identical with the filter off; the context is now enforced always (the consistency test
   caught it).
5. `AccountKey=` and `hooks.slack.com` had no left boundary (a glued prefix still matched); both
   have one now.
6. `API_KEY=value` was one token because `=` is in D5's alphabet, so env-style lines never got
   context; `=` is now padding only at the end of a token.
7. A secret group wrapped in a quantified non-capturing group was accepted by the first guard
   draft; it is refused.

### Deviations and interpretations (also in the PLAN.md changelog v0.5; accepted by the owner on 2026-10-12, PLAN.md v0.6)

1. `Rule`, `FakeSegment` and `Checksum` are in `core/models.py` (resolves v0.3 deviation 1).
2. `context` is a list of 1 to 4 lower-case keywords that must all appear on the line (D4 says "a
   keyword"); `aws-secret-access-key` uses `[aws, secret]`, which is what D4's table describes.
3. The `fake` spec is a list of segments (`parts` joined at runtime, or `charset` + `length`),
   because multi-segment formats (GitHub fine-grained, Slack, SendGrid) need more than one prefix
   and body. The fake is the full matched text, so it may include a non-secret prefix
   (`AccountKey=`, `hooks.slack.com/services/`); the loader checks that it matches its own rule.
4. The regex guard has one rule that D3 does not list, needed for its stated guarantee: two
   variable-width items that follow each other must not be able to match the same byte (an
   optional item does not separate them). Without it three adjacent `[a-z]{1,200}` items pass
   width and cost yet cost 200^3 steps per start position. The cost is the maximum width times
   the number of alternation paths (equal to D3's formula when no group holds an alternation).
   Also: patterns compile as byte patterns, are ASCII only, refuse anchors, and `\xHH` and `\t`
   are the only non-punctuation literal escapes besides `\d \w \s \b`.
5. Entropy: `=` is base64 padding only at the end of a token (see bug 6); the minimum length
   setting applies to base64 and the hex minimum is the larger of 32 and that setting; the 64-bit
   floor of D7 is enforced at run time (length times measured entropy must reach 64 bits), which
   matters once thresholds are lowered inside the D5 bounds.
6. Entropy context: the key must end within 8 blank or quote characters before the token and
   allow at most 4 blanks before `:` or `=`; `Authorization: Bearer <token>` therefore has no
   context (low confidence).
7. A key block that reaches `MAX_KEY_LINES` is reported at confidence medium and is not an issue;
   D6 does not say which. A `Match` carries `severity` and `shown_chars`, because the encrypted
   key variant has another severity than the rule and D7's shown prefix is per rule.
8. Columns: "each invalid byte counts as one" is implemented with Python's replacement rule (one
   per maximal invalid subpart), which is the same for isolated bytes.
9. The engine result flags `capped` (more than `MAX_FINDINGS_PER_FILE` matches) and lists
   over-long lines; mapping these to `findings_cap` and `line_too_long` issues is Phase 3.
10. A new test marker `requires_sh` and a hook launcher script (Step 0 c), neither in the plan.

### Known gaps and limits recorded

- Token formats come from knowledge, not from live checks (no network): the GitHub checksum
  (CRC32 of the 30 entropy characters, base62, 6 characters), the PyPI macaroon header, the
  Slack and Azure shapes could be wrong in detail.
- Package data (`rules/builtin.yaml`) inclusion in the built wheel is checked only in the Phase 6
  release checks (hatchling is not in the venv).
- The entropy detector flags near-miss tokens at confidence low; the default report level
  (medium) hides them. Documented in the negative-corpus test.
- Recorded on 2026-10-12 as known limitations for the README: token formats come from knowledge,
  not from live checks; the Claude Code hook (a development control) cannot see shell aliases,
  variables or PowerShell `-EncodedCommand`, and is not in force if `sh` cannot start.

```
Built: core/regex_guard.py (restricted grammar, named refusals, width and cost accounting, neighbour-ambiguity rule), Rule model, core/rules.py (schema), core/checksums.py (GitHub CRC32), core/fakes.py (runtime fake generator), services/loader.py (strict YAML: no duplicate keys, aliases, anchors, tags or merge keys; size cap; package data), rules/builtin.yaml (13 rules with fake specs), core/lines.py (binary, BOMs, UTF-16/32, lines, columns), core/detect (pre-filter, rule detector with checksum, entropy, private key state machine, engine with overlap resolution), core/findings.py (Match to redacted Finding), hygiene secret check switched to the engine; Step 0: owner name, hook gaps, blocking hook launcher
Tests added: 732 (1434 total, 17 slow): regex guard 166 (every refusal reason, the D3 hostile table, CPython width cross-check, 1500 generated patterns), per-rule table 150 (13 rules x 8 contexts, near misses, placeholders, pre-filter consistency, checksum), loader and schema 99, entropy 67, fakes and checksums 36, private key 34, engine 31 (mixed and negative corpus, overlap reference), lines 28, hygiene +6, hook +68, launcher 8, slow tripwire 16
Real coverage: 100.00% (branch, src/secret_scanner and scripts) in the full gate on Windows and in the full gate on WSL Ubuntu; floor 85
Known gaps: CI has not run the Phase 2 code (Python 3.11 and 3.12 only parsed locally); token formats unverified against live services; wheel package-data inclusion unchecked until Phase 6; entropy flags near-miss tokens at low confidence; engine result flags (capped, long lines) are not yet issues; hook still cannot see aliases, variables or -EncodedCommand and fails open if sh cannot start; default gate 56 s to 60 s, at the 60 s target
Deviations from PLAN.md: Rule in core/models.py; context is a keyword list; fake spec is a segment list; guard adds the neighbour-ambiguity rule and defines cost as width times alternation paths; entropy treats = as trailing padding only and enforces the 64-bit floor at run time; MAX_KEY_LINES gives medium not an issue; Match carries severity and shown_chars; requires_sh marker and hook launcher (all accepted by the owner on 2026-10-12, PLAN.md v0.6)
```

## Phase 3 - Directory scan, suppression, `scan` with table and JSON (2026-10-12 to 2026-10-13)

The phase ran over two sessions; the first stopped at commit e1d2368 (usage limit), the second
continued from the "In progress" list and finished it. Owner decisions of 2026-10-13 (PLAN.md v0.7,
accepted): the v0.3 Phase 1 deviations; `--write-baseline` in Phase 3; the `rules` command in
Phase 5 with the demo; `_count_skip` tests with platform-only lines left to the combined
Windows + WSL Linux coverage.

### What was built

- `core/globs.py` (segment-wise matcher, no regex), `core/suppress.py` (baseline schema, matching,
  stale counting, written document with reason carry-over), `core/entries.py` (entry classification),
  display-safety validation on `Location`, `ScanIssue`, `Report` and `require_display_safe`.
- `fs/walk.py` (the only reader of scanned files: no-follow, regular files only, limits),
  `fs/safe_files.py` (own files: strict read, atomic no-clobber write, `is_inside`, `is_same_path`),
  the temporary-path guard in `tests/conftest.py`.
- `host/clock.py`, `host/hostinfo.py`, `services/config.py` (configuration and baseline),
  `services/fs_scanner.py` (issues, caps, time budget), `services/loader.py` (`dump_yaml`, cached
  built-in rules).
- `render/table.py`, `render/json_out.py`, `app/scan.py`, the CLI `scan` command with `--format`,
  `--output`, `--force`, `--config`, `--baseline`, `--write-baseline`, `--show-suppressed`,
  `--min-confidence`, `--fail-on`, `--no-default-excludes` and `--host-label`.
- `docs/report-schema.md` with drift tests; end-to-end tests for the exit-code table, leakage on
  every output and error path, and hostile names.

### Measured on this machine (Windows 11, Python 3.13.14, git 2.54.0.windows.1; WSL Ubuntu, Python 3.14.4, git 2.53.0)

| Run | Commit | Result |
|---|---|---|
| Windows default gate | 5c50f1b | 1803 passed, 14 skipped, 99.79% branch coverage, 62.5 s total (pytest 57.9 s) |
| Windows full gate | 5c50f1b | 1820 passed, 14 skipped (`posix_only`), 99.79%, 120.7 s |
| WSL Ubuntu full gate | 5c50f1b | 1833 passed, 1 skipped (`windows_only`), 99.94%, 14.6 s |

The Windows default gate varied between 48 s and 110 s over the session on this machine (the 110 s
run was before the built-in rules were parsed once per process; the leakage matrix alone cost 27 s
under coverage then and costs about 5 s now). The 60 s target is exceeded slightly; the 90 s
threshold for moving tests to `slow` is not. The uncovered lines on each OS are the other OS's
branches of `fs/safe_files.py` (POSIX: directory flush, `os.link`; Windows: `os.rename`); together
the two runs cover every line and branch.

### What the tests found (fixed in this phase)

1. Error messages echoed up to 40 characters of an unknown key, a limit name or a glob pattern from
   a configuration or baseline file; a pasted token as a key would have been printed whole. They now
   list the allowed keys or the position of the entry (PLAN.md v0.8, item 3).
2. `--output` could name the configuration or baseline file being read and destroy it with
   `--force`; refused (item 4).
3. Refreshing a baseline with `--write-baseline` would have lost reasons a person had written;
   they are carried over (item 2).
4. argparse echoes a bad option value verbatim; its messages now go through the sanitiser.
5. The first version of the leak matrix scanned the test's own input files (which hold the fake by
   construction); it now checks only what the tool wrote and asserts that nothing else was left
   behind (no temporary files).

### Deviations and interpretations (also in the PLAN.md changelog v0.8; awaiting acceptance)

1. `--write-baseline` does not change the exit code (D10 unchanged): a run that finds something
   still exits 1.
2. A written baseline holds the reported findings plus those already suppressed by fingerprint,
   after the confidence filter; reasons and path globs are carried over; path-only suppressions
   are not duplicated (D9 says "every current finding").
3. Error messages no longer echo keys, limit names or glob patterns from files the tool reads.
4. Output safety rules beyond the plan: `--output` may not be the `--config` or `--baseline` file;
   `--output` and `--write-baseline` may not be the same file; `--write-baseline` may replace the
   `--baseline` it read (with `--force`).
5. The host label reaches JSON through the application, not through `Report`; notices go to
   stderr, the report to stdout (nothing on stdout with `--output`).
6. `OutputFormat` is a core model; the built-in rules are cached per process.
7. Escaped output doubles backslashes (Phase 1 sanitiser), so a Windows path shows `\\`.

### Known gaps and limits recorded

- `scan` refuses a PATH, `--output`, `--config` or `--baseline` with a `..` component (Phase 1
  path rules); pass an absolute path or run from the parent directory.
- `scan --gitignore`, `scan-git`, `--write-baseline` for git targets: Phase 4. JSONL, SARIF, the
  demo and the `rules` command: Phase 5. The README, threat model and measured performance:
  Phase 6.
- Hostile names with control characters (newline, ESC, CR LF, invalid UTF-8) can only be created
  on POSIX; their tests (`posix_only`) ran in the WSL check, not on Windows. Windows runs cover
  bidi, zero-width, separator and non-BMP names.
- The cp1252 console test uses an in-memory stream with the same encoding, not a real console.
- CI has run only up to commit e1d2368 (CI #3, green on all six jobs); the commits after it are
  checked locally on Windows and WSL only until the owner pushes.
- A secret passed on the command line (argv) is echoed by argparse errors like any other value;
  the leak tests cover content the tool reads, not what the user types.

```
Built: directory scan end to end: globs, baseline (schema, matching, stale counting, writer), read-only walker, safe own-file I/O, host label, configuration, fs scanner service, table and JSON renderers, scan use case, CLI scan (all options except --gitignore), docs/report-schema.md with drift tests
Tests added: 419 in 13 new test files (suite: 1834 collected, 17 slow; Windows 1820 passed + 14 posix-only skipped, WSL 1833 passed + 1 windows-only skipped): walker and limits, globs, baseline, config bounds, scanner issues and skip counters, renderers, exit-code table, leakage on every output and error path for every rule, hostile names, output safety, schema drift
Real coverage: 99.79% (branch, full gate, Windows, commit 5c50f1b); 99.94% in the WSL Linux full gate; the lines each OS misses are the other OS's branches in fs/safe_files.py; floor 85
Known gaps: no git scanning yet (Phase 4); JSONL, SARIF, demo and rules command in Phase 5; PATH with .. refused; control-character names tested only on POSIX; default gate 62.5 s against a 60 s target (48 s to 110 s observed); CI has not run the commits after e1d2368
Deviations from PLAN.md: --write-baseline in Phase 3 (accepted, v0.7); awaiting acceptance (v0.8): exit code unchanged by --write-baseline, written baseline content, no echo of keys or globs in errors, extra output-file refusals, host label and notices wiring, OutputFormat model and rules cache, doubled backslashes in escaped output
```
