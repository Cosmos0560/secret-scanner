# Phase reports

One entry per phase, appended in order. Each entry ends with the exact 5-line report required by
CLAUDE.md section 2, step 5. The last entry is the one a new session reads first.

## In progress

Nothing. Phase 6 (hardening, measurement, docs, release) is done and reported at the end of this
file. All six phases are built. What is left is the owner's: push, check the Actions run, tag
`v1.0.0`, publish the release, make the repository public. Open for the owner (PLAN.md v0.15,
awaiting acceptance): the Phase 6 interpretations, and the decision about `MAX_RUN_SECONDS` that
the measurements raised (docs/performance.md). The commits after `13b772a` are local.

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

## Phase 4 - Git history scan (2026-10-13)

### Owner decisions at the start of the session (PLAN.md v0.9, accepted)

1. The Phase 3 interpretations (PLAN.md v0.8, items 1 to 6) are accepted. Item 7 (doubled
   backslashes in escaped output) is replaced by a decision: in the table and every other
   human-readable output, paths are shown relative to the scan root with `/` separators and
   escaped per component, so a Windows path never shows doubled backslashes; JSON keeps standard
   JSON string encoding.
   Done with `core/sanitize.sanitize_path`. A path the user gave (scan root, `--output`,
   `--write-baseline`) is shown as given with `/` on Windows; finding and issue paths were
   relative `/` keys already; on POSIX a backslash is a name character and stays escaped. The JSON
   `target.path` carries the same display form (no schema change). Tests: `sanitize_path` unit
   tests, refused-path messages for both flavours, and a CLI test that the table holds no doubled
   backslash (on Windows the scan root and output path really hold backslashes).
2. Default gate time. Measured on this machine (Windows 11, Python 3.13.14, git 2.54.0.windows.1)
   with the gate's own `--durations` option (added; it changes no check):

   | Default gate | Total | pytest step | Tests | Coverage |
   |---|---|---|---|---|
   | before (commit f2e26fd) | 58.8 s (58.8 to 63.0 s over three runs) | 53 s to 55 s | 1811 passed, 14 skipped, 17 deselected | 99.79% |
   | after | 33.1 s | 27.7 s | 1819 passed, 14 skipped, 31 deselected | 99.79% |

   What the durations showed: the slowest single tests were 3 s or less, and the top 45 together
   were about 17 s of 53 s. Per-phase totals under coverage were setup 19.6 s and call 16.5 s: the
   autouse fixtures (a fresh `tmp_path`, a home directory, five `setenv` and eight `setattr` calls
   per test) cost about 10 ms per test, 1 800 times. What changed, behaviour covered the same:
   - isolation (`HOME` and the other per-user variables) and the socket blocker are applied once
     per session; after each test a check fails the test if it wrote into the isolated home
     (`check_isolated_home_is_empty`, with its own test). Setup fell from 19.6 s to 3.0 s.
   - the leakage matrix (`tests/test_scan_leakage.py`): one representative of each detector kind
     (`aws-access-key-id`, `private-key`, `entropy-base64`) runs every output format and every
     error path in the default gate; the other 12 rules run the same matrix as `slow` tests (full
     gate and CI). All rules also run through the table and JSON renderers in the default gate.
   - generated patterns: 300 of the seeded 1 500 in the default gate, all 1 500 as `slow`; deep
     YAML nesting: 600 levels in the default gate, 3 000 as `slow`.
   The slow tests added by this are run in the full gate (see the end of this entry).

### Slices and commits

| Commit | What |
|---|---|
| `f2e26fd` | step 0a: paths shown relative with `/` and escaped per component (PLAN.md v0.9 item 1) |
| `ec93f7a` | step 0b: environment isolation once per session, heaviest tests split into default and slow cases (v0.9 item 2) |
| `4ee2dc1` | strict git output parsers (`core/gitparse.py`), the hardened runner (`gitio/runner.py`), repository inspection |
| `ce8cf35` | `scan-git` and `scan --gitignore`, hostile-repository, history and bounds tests, `docs/git-hardening.md` with drift tests |
| `38f6979` | runner pipe, writer and cleanup edge tests |
| `89513f3` | fix for the Windows binary-planting finding F-1 (below), after CI run 5 went red on `38f6979` |

### Resumption after a four-week pause (2026-11-08)

Nothing from the earlier session was assumed. State found: `main` at `38f6979`, the only local
change the "In progress" edit of this file, git **2.54.0.windows.1**, Python 3.13.14, the packages
in `.venv` matching `pyproject.toml` (ruff 0.17.0, mypy 2.4.0, pytest 9.1.1, pytest-cov 7.1.0,
PyYAML 6.0.3). The default gate passed on the untouched tree (2143 passed, 17 skipped, 80
deselected, 99.60%; 65.2 s in total on a cold start). Owner answers recorded: the two stopped bash
processes were the earlier session's own gate and WSL runs, interrupted when it ended; PLAN.md
v0.10 is accepted (the refusals of worktree and submodule `.git` files, alternates and grafts),
and is now listed in the README under Limitations as a known, deliberate refusal.

### Finding F-1: Windows binary planting (caught by CI run 5)

CI run 5 on `38f6979`: every Windows job failed in
`tests/test_git_hostile.py::test_a_planted_git_program_is_never_chosen` (WinError 216 while
starting a planted `git.exe`), every Linux job passed. Full write-up, controls and test names:
`docs/threat-model.md`, finding F-1.

- Reproduced locally by removing `NoDefaultCurrentDirectoryInExePath` from the test's environment:
  this machine sets it to `1`, the CI runners do not. That is why the local gate was green.
- Root cause, verified and not as first suspected: the product's search already skipped empty and
  relative `PATH` entries. The planted program was chosen because the test helper
  `tests/gitrepo.py::git_binary()` called `shutil.which("git")` after the test had changed into the
  directory holding the plant; on Windows `which` searches the current directory first, so the
  helper returned the plant as "the real git", and the test passed that directory to `open_runner`
  as an absolute `PATH` entry. The product trusted it. Real hardening gap: an absolute entry equal
  to the current directory, or inside the system temporary directory, was trusted.
- Fix: absolute, normalised, fully qualified entries only; the scanned tree, the system temporary
  tree and the current directory itself are refused; Windows accepts only `git.exe` (also for
  `--git`); `Popen(executable=...)`; the test helper uses the product's search. The original test
  is unchanged. 47 collected tests in the new `tests/test_git_program_resolution.py` (one is
  `slow`: it plants a real, harmless executable, compiled with the C# compiler that ships with
  Windows, proves with a control run that it writes its marker, and shows the marker is absent
  after the search) and further tests in `tests/test_git_fs.py`. Each rule was mutation-checked:
  switching it off fails tests.

### Measured (this machine: Windows 11, Python 3.13.14, git 2.54.0.windows.1, 2026-11-08)

- Full gate, committed code `89513f3`: 2292 passed, 21 skipped (posix-only), 177.0 s pytest,
  184.1 s in total, **99.72%** branch coverage (the lines it misses are POSIX branches in
  `fs/safe_files.py` and platform branches of the runner).
- Default gate on `89513f3`: 2214 passed, 18 skipped, 81 deselected, 99.61%, **53.6 s in total**
  (pytest 46.9 s). On the untouched resumption tree it was 65.2 s (cold start) with 2143 tests.
- WSL Ubuntu, git 2.53.0, Python 3.14.4 (outside the CI matrix, as CLAUDE.md allows), full gate on
  the committed `89513f3`: 2288 passed, 25 skipped (windows-only), 17.6 s pytest, 24.8 s in total,
  **99.81%**. This is the first Linux run of the POSIX-only tests of Phase 4 (hostile names with
  control characters, exec-bit tests, `find_program` exec bit); all passed.
- The default gate is above the roughly 40 s of PLAN.md v0.9 (it was 33.1 s with 1819 tests; there
  are now 2214) and inside the 60 s target of CLAUDE.md. The "In progress" note proposed moving
  the real-git tests of `test_git_hostile.py` to `slow` in that case. Not done: they are about 7 s
  of the 35 s of test time and are the proof that every execution vector stays closed; moving them
  would save about 5 s and weaken the gate that runs before every commit. The owner can overrule.

`pytest -q` summary lines: Windows full `2292 passed, 21 skipped in 177.02s (0:02:57)`; Windows
default `2214 passed, 18 skipped, 81 deselected in 46.07s`; WSL full
`2288 passed, 25 skipped in 16.82s`.

`git log --oneline -15` before this report was committed:

```
89513f3 fix: never run a git program found in the current directory, a relative PATH entry or a temp tree (Windows binary planting, CI run 5)
38f6979 test: cover the runner's pipe, writer and cleanup edges
ce8cf35 feat: add scan-git and scan --gitignore with hostile-repository, history and bounds tests
4ee2dc1 feat: add the strict git output parsers, the hardened git runner and repository inspection
ec93f7a perf: apply environment isolation once per session and split the heaviest tests into default and slow cases (PLAN.md v0.9)
f2e26fd feat: show paths with forward slashes and per-component escaping in human output (PLAN.md v0.9)
eb63d7e docs: add the Phase 3 report and record interpretations awaiting acceptance (PLAN.md v0.8)
5c50f1b perf: parse the built-in rules once per process; keep the default gate near its target
2161090 docs: add the secret-report/1 schema, exit codes and table layout with drift tests
b9956ba test: prove no output path of scan carries a planted secret; stop echoing glob patterns
752742f feat: add the scan command with table and JSON output, baseline options and exit codes
cac5586 fix: never echo a key name from a configuration, rules or baseline file in an error
ad66416 feat: add the scan use case with config merge, baseline round trip and safe outputs
0570021 feat: add the table and JSON renderers, display-safety checks and baseline reason carry-over
9e51e0d test: cover the directory scanner's skip counters for links, offline and special entries
```

`git status --short` before this report was committed: only `docs/phase-reports.md` modified.

```
Built: scan-git and scan --gitignore: strict git parsers (core/gitparse.py), the only git runner (gitio/runner.py: absolute binary, from-scratch environment, pinned config, command allowlist, bounded output, timeouts), repository inspection (refuses .git files and links, alternates, grafts), history walk with blob cache and first-commit attribution, shallow and partial-clone handling, docs/git-hardening.md with drift tests, docs/threat-model.md (finding F-1), CHANGELOG.md; git resolved only from fully qualified PATH entries outside the scanned tree, the temporary tree and the current directory, git.exe only on Windows
Tests added: 479 (suite 2313 collected, 81 slow): git parsers 144, runner 67 and 20 edge, scanner service 26, repository inspection and program search 59, scan-git and --gitignore end to end 48 and 19, hostile repository with a marker for every execution vector 6, program resolution and binary planting 47, doc drift 10, self-history scan 1, plus the path display and gate-time work of the two step-0 slices
Real coverage: 99.72% (branch, full gate, Windows, commit 89513f3); 99.81% in the WSL Linux full gate (git 2.53.0); floor 85
Known gaps: default gate 53.6 s against the roughly 40 s of v0.9 (inside the 60 s of CLAUDE.md); the fix 89513f3 has not run on CI yet (the owner pushes), nor Python 3.11 and 3.12 (local 3.13, WSL 3.14); a time-of-check to time-of-use gap between finding git and starting it; the Windows planted-executable test needs csc.exe from Windows and fails, not skips, without it; not read in v1: commit messages, tag messages, reflog, unreachable objects, submodule contents, LFS objects; refused with exit code 3: worktree and submodule .git files, alternates, grafts
Deviations from PLAN.md: v0.10 (accepted by the owner 2026-11-08); v0.11 (accepted by the owner 2026-11-08; D2 Binary made precise: temp tree and current directory refused, git.exe only, --git must be named git.exe on Windows, executable= passed to Popen); docs/threat-model.md and CHANGELOG.md started in Phase 4 instead of Phase 6; default gate time above the v0.9 target
```

## Phase 5 - JSONL, SARIF, demo, rules, cross-format leak proof (2026-11-09)

### Owner decisions at the start of the session (PLAN.md v0.12, accepted 2026-11-09)

CI run 6 on `090df20` is green on all six jobs, so the F-1 fix is confirmed on the CI runners.

1. The default gate at 53 s to 66 s is accepted for now. The real-git hostile tests stay in the
   default run: they prove on every commit that each execution vector stays closed. The gap
   "default gate above the v0.9 target" of the Phase 4 report is closed by this decision; the time is
   measured again at the end of this phase.
2. The README Limitations section (Phase 6) will list: the time-of-check to time-of-use gap between
   resolving git and starting it; that commit messages, tag messages, the reflog, unreachable
   objects, submodule contents and LFS objects are not scanned in v1; the deliberate refusals of
   worktree and submodule `.git` files, alternates and grafts (exit code 3); that the Windows
   planted-executable test needs `csc.exe`. Nothing is added to the README in this phase.

### Slices and commits

| Commit | What |
|---|---|
| `9357ac6` | step 0: the owner's decisions (PLAN.md v0.12) |
| `8be925c` | `--format jsonl` (`secret-event/1`), `clip_display` in the sanitiser |
| `9fe0fea` | `rules` (table and JSON, `secret-rules/1`), `core/ruleinfo.py`, drift tests |
| `cda8a74` | `--format sarif`, `docs/sarif.md`, the structural checker, drift tests |
| `0631ca6` | `demo`: `fs/sandbox.py`, `gitio/demo_git.py`, `app/demo.py`, audit-hook guard tests |
| `2710930` | cross-format leak matrix, hostile names per format, `docs/siem-mapping.md` with the real mini-siem ingest |
| `5ae388b` | a custom rule's name and description are escaped; PLAN.md v0.13 |
| `fa248b5` | the audit helper resolves descriptor-relative paths and accepts git's own `posix_spawn` (found by the Linux run) |

### Real mini-siem check

mini-siem 1.0.0 (commit `6adc008`) was used read-only, from its own virtual environment, as the
owner asked. Done on 2026-11-09:

- Input: a five-line JSONL file made by the tool from generated fakes: `scan . --format jsonl` over
  the sample project (2 findings and the summary line) and `scan-git` over a throw-away repository
  (1 finding with its commit and the summary line). Everything (the file, the data directory, the
  working directory, `TEMP`) was in a temporary folder outside both repositories.
- The program was started as `python -B -m mini_siem --data-dir <temp>/data ingest
  <temp>/secret-events.jsonl --format json` with `PYTHONDONTWRITEBYTECODE=1` and a scrubbed
  environment, so it could not write byte code into its own folder.
- Proof that nothing in the mini-siem folder changed: a fingerprint of all 15 332 entries (path,
  mode, size, modification time of each; no file opened) was taken before the first command and after
  the last (an ingest, a repeated ingest, `search`, `search --json`, `stats`, `--version`). Both were
  the same, `a6b78a42eb0f...` (first 12 digits).

Real output:

```
<temp>/secret-events.jsonl: format json, 5 line(s), 5 record(s), 0 blank, 0 over-long
events: 5 parsed, 5 newly stored, 0 already stored
parse failures: 0 (dead-letter file: <temp>/data/deadletter.jsonl), over-long lines: 0
alerts: 0 stored (0 allowlisted), 0 duplicate(s) suppressed by cooldown
```

The same file ingested again: `events: 5 parsed, 0 newly stored, 5 already stored`. `mini-siem stats`:
`events: 5`, `alerts: 0`, `parse failures: 0.00% (0 dead-lettered / 5 seen)`. `search` listed the five
events newest first, all `json_event`, with the host and the message of each line; `search --json`
showed the attributes `declared_event_type` (`secret.finding` or `secret.scan_summary`) and
`secret.*` for every other value. The full search output and one stored event are in
`docs/siem-mapping.md`. Observed limits of mini-siem 1.0.0 (recorded there as known gaps): a query
cannot name a `secret.*` attribute (free text finds the message), and no detection rule was written
for these events.

### What the phase found

1. **The tool's own history scan caught a documentation hex value (full gate, Windows).**
   `tests/test_self_history.py` reported two `entropy-hex` findings at `docs/siem-mapping.md:193:28`
   (64 digits, `ea0a...`) and `:195:28` (32 digits, `357a...`) in commit `7b112f2`: the stored-event
   example listed a file hash and a fingerprint under the key names `secret.file_sha256` and
   `secret.fingerprint`, and a long hex value next to a key that contains `secret` is exactly what the
   D5 detector reports. They are hashes of generated fakes, not secrets, but CLAUDE.md section 4 item
   5 says to remove the string and never to allowlist it. The two values are now cut to their first 12
   digits in the document (the drift test accepts exactly those two as cut). Because the commit was
   local and unpushed, the two unpushed commits (`7b112f2`, `2fad516`) were redone from `0631ca6`
   with the same messages and the same split of files (`git reset --mixed`, a backup of the diff kept
   outside the repository); the old commits are no longer reachable from any branch or tag. The scan of the final
   history: `scan-git .` reports 52 commits, 312 blobs, no findings.
2. **The Linux run found two bugs in the new guard tests (WSL).** On Linux `shutil.rmtree` works
   relative to open directory descriptors, so the audit events held bare names (49 "outside"
   paths), and Python 3.14's `subprocess` starts a child with `os.posix_spawn`, which the guard counted
   as a process change. `tests/audit.py` now resolves a descriptor's directory through
   `/proc/self/fd` at event time (and records `<fd N>/name`, which no test accepts, where that is
   impossible) and the test checks that every `posix_spawn` target is the resolved git. Four tests of
   the helper itself were added. The product code was not affected.
3. **A configuration file can put any text in a custom rule's name and description.** The SARIF
   renderer refused the whole report (an internal error, exit code 2) when it met a control character
   there. `info_for_rule` now escapes both with the single sanitiser; a test runs a rule whose name
   holds an ESC, a bidirectional override and a zero-width space through SARIF, JSON and JSONL.
4. **The file-writing tool decodes unicode escapes.** A test file written with a backslash-u escape
   for a bidirectional override contained the raw character, and the repository hygiene test refused
   it. Tests build such characters with `chr()`.
5. One command that joined `gate.py` with a `grep` was blocked by the Claude Code hook, as designed;
   nothing ran. Commands were split afterwards.

### Measured (this machine: Windows 11, Python 3.13.14, git 2.54.0.windows.1, 2026-11-09)

- Full gate, committed code `fa248b5`: 2508 passed, 23 skipped (POSIX-only), **225.2 s** pytest,
  **231.8 s** in total, **99.72%** branch coverage (the lines it misses are POSIX branches of
  `fs/safe_files.py`, `fs/sandbox.py`, `gitio/demo_git.py` and the runner).
- Default gate, same code: 2427 passed, 20 skipped, 84 deselected, **74.8 s** pytest, **82.1 s** in
  total, 99.61%. The other runs of this tree: 72.7 s, 74.9 s, 77.8 s in total; one run took 95.5 s
  while the machine was busy (mypy took twice as long in that run). End of Phase 4: 53.6 s with 2214
  tests. Phase 5's own test files cost about 12 s of the default run (219 tests, measured alone,
  without coverage): the real-git cases (4.6 s for `scan-git` through JSONL and SARIF, 1.4 s for the
  demo run, 1.4 s for the demo variant with a history that lacks the secret), the cross-format
  matrix and the 44 sandbox tests. The rest of the increase is variance on this machine. The default
  gate is above the 60 s of CLAUDE.md and below the 90 s at which tests must move to `slow`; the
  owner decides (see Known gaps).
- WSL Ubuntu, git 2.53.0, Python 3.14.4 (outside the CI matrix, as CLAUDE.md allows), full gate on
  the committed `fa248b5`: 2504 passed, 27 skipped (Windows-only), 20.06 s pytest, 30.1 s in total,
  **99.77%**. The first Linux run, on `5ae388b`, failed the two guard tests of item 2; the run above
  is after the fix.

`pytest -q` summary lines: Windows full `2508 passed, 23 skipped in 224.23s (0:03:44)`; Windows default
`2427 passed, 20 skipped, 84 deselected in 73.74s (0:01:13)`; WSL full `2504 passed, 27 skipped in 20.06s`.

`git log --oneline -12` before this report was committed:

```
fa248b5 test: resolve directory-descriptor paths in the audit helper and accept git's own posix_spawn (found by the Linux run)
5ae388b fix: escape the name and description of a custom rule in rule listings and SARIF; record the Phase 5 interpretations (PLAN.md v0.13)
2710930 test: add the cross-format leak matrix, hostile names per format and docs/siem-mapping.md with a real mini-siem ingest
0631ca6 feat: add the demo command with a sandboxed temporary tree, a throw-away repository and audit-hook guard tests
cda8a74 feat: add the SARIF 2.1.0 output format with structural tests, docs/sarif.md and drift tests
9fe0fea feat: add the rules command (table and JSON, secret-rules/1) with drift tests against the rules file
8be925c feat: add the JSONL output format (secret-event/1) shaped for mini-siem's generic JSON parser
9357ac6 docs: record the owner's Phase 5 decisions (PLAN.md v0.12)
090df20 docs: record the owner's acceptance of PLAN.md v0.11
7ea2020 docs: add the Phase 4 report, finding F-1 and the measured gate numbers
89513f3 fix: never run a git program found in the current directory, a relative PATH entry or a temp tree (Windows binary planting, CI run 5)
38f6979 test: cover the runner's pipe, writer and cleanup edges
```

`git status --short` before this report was committed: clean.

```
Built: --format jsonl (secret-event/1, one finding per line plus a summary line, ingested by the real mini-siem 1.0.0 without a change to it) and --format sarif (SARIF 2.1.0: rule list, level and security-severity mapping, percent-encoded URIs from the exact path, fingerprints, suppressions, notifications), the rules command (table and JSON), the demo command (sandbox, throw-away repository with a secret committed and removed, real scan and scan-git, cleanup in a finally and on Ctrl-C, exit 3 without git), Ctrl-C exit 130, docs/sarif.md and docs/siem-mapping.md with drift tests, the cross-format leak matrix and hostile-name tests per format, audit-hook guard tests for the demo
Tests added: 218 (suite 2531 collected, 84 slow): JSONL 18, SARIF 59 and doc drift 11, rules 15, sandbox 44, demo repository builder 13, demo 21 (one real process, slow), output formats 5 (three slow), siem-mapping drift 14, plus additions to the sanitiser (clip_display), the schema doc, the scan leak matrix (all four formats, shown and hidden suppressions, error paths), the audit helper and the model tests
Real coverage: 99.72% (branch, full gate, Windows, commit fa248b5); 99.77% in the WSL Linux full gate (git 2.53.0, Python 3.14.4); floor 85
Known gaps: SARIF is not validated against the official schema (no PyPI package ships it; structural tests only) and was not uploaded to GitHub code scanning; no mini-siem detection rule written, and mini-siem 1.0.0 cannot search by secret.* attribute; default gate 72.7 s to 82.1 s on this machine (above CLAUDE.md's 60 s, below its 90 s); Phase 5 code has not run on CI (Python 3.11 and 3.12 untested locally: local 3.13, WSL 3.14); the audit-hook guard fails closed on a system without /proc/self/fd (macOS, not in the CI matrix); rules takes no user rules file (D4 does not cover one); file-integrity-monitor's siem-mapping.md was not read (CLAUDE.md section 4 allows only mini-siem's parser source); the demo header shows its random temporary path; from Phase 4, still open for the README: TOCTOU between resolving git and starting it, commit and tag messages, reflog, unreachable objects, submodule contents and LFS not scanned, the deliberate exit-3 refusals, csc.exe for the Windows planted-executable test
Deviations from PLAN.md: v0.13 accepted by the owner 2026-11-10 (JSONL suppressed_by field and summary fields; SARIF driver.version, informationUri from the origin remote, URI from the exact path, generic suppression justification, run properties; rules lists 13 rules and 3 detectors; demo exit codes and Ctrl-C 130; new modules); the two unpushed commits 7b112f2 and 2fad516 were redone from 0631ca6 to remove a hex value the tool's own history scan flagged (no allowlist) (also accepted 2026-11-10)
```

## Phase 6 - Hardening, measurement, docs, release (2026-11-10)

### Owner decisions at the start of the session (PLAN.md v0.14, accepted 2026-11-10)

CI run 7 on `13b772a` is green on all six jobs.

1. The demo never prints the real path of its temporary directory; it shows the fixed label
   `<temporary directory>` (commit `0e64191`).
2. The default gate at 72 s to 82 s is accepted (above the 60 s target of CLAUDE.md section 7, below
   its 90 s limit). No time of this phase went into gate speed. See "Measured" for what the gate
   took in this session.
3. `pyproject.toml` classifier `Development Status :: 4 - Beta`, pinned by a test (commit `6a0eaeb`).

### Slices and commits

| Commit | What |
|---|---|
| `0e64191` | step 0a: the demo shows `<temporary directory>` in its introduction and in both report headers (`run_scan` and `run_scan_git` take `shown_as`, used by the demo only); `tests/helpers.local_traces`; four tests |
| `3ab13d8` | step 0b: PLAN.md v0.14 and the accepted gate time |
| `6a0eaeb` | step 0c: the Beta classifier and `tests/test_release_metadata.py` |
| `ce06835` | version 1.0.0 from its single source (`src/secret_scanner/__init__.py`), CHANGELOG `1.0.0 - 2026-11-10`, tests that pyproject, the installed metadata, `--version` and the changelog agree; the regenerated examples in the docs show 1.0.0 |
| `9c9ea00` | `scripts/bench.py` and `docs/performance.md`; README; `docs/threat-model.md` finished (F-1 kept); `docs/rules.md` (generated table); SECURITY.md; CONTRIBUTING.md; drift tests for all of them; the two invariant 10 tests; the local-path hygiene test; the fix of the command in `docs/siem-mapping.md`; PLAN.md v0.15 |
| `f259e89` | the Linux (WSL 2) measurement in `docs/performance.md` |

### What the phase found

1. **A documented command did not work.** `docs/siem-mapping.md` showed
   `secret-scanner scan . --format jsonl --host-label build-01 --output events.jsonl`. The tool
   refuses it with exit code 2: the output would be inside the scanned tree. `--output
   ../events.jsonl` is refused too (no path given to the tool may contain `..`). The document now
   scans a directory by name from its parent, says why, and
   `test_the_documented_command_runs_and_writes_the_documented_lines` runs the command as written.
   The README states the rule in its options section, and its CI example writes the report to the
   runner's temporary directory.
2. **Invariant 10 had no named test.** CLAUDE.md section 7 asks for at least one named test per
   invariant of section 5; none proved that configuration, rules and baselines are never
   discovered. Two were added (`scan`, and `scan-git` with the files committed): files under 14
   plausible names plus a `pyproject.toml` section, in the scanned tree, the current directory and
   the home directory, that ask to switch every rule off, exclude everything and suppress the
   finding. The result is the one of a run without them. The product code needed no change.
3. **The first scan of freshly written files is slow on this Windows machine, and the default time
   budget cannot be raised.** `scripts/bench.py` measured 7 ms per file (1,000 files) and 20 ms per
   file (10,000 files) for a first scan, against 0.4 ms per file for a repeat scan. A first scan of
   100,000 new files ran into `MAX_RUN_SECONDS` (600) and ended incomplete, and so did at least two
   of its three repeat scans. On Linux (WSL 2, memory file system) the same tree took 30 seconds.
   Real-time antivirus protection is on on this machine; no run was made with it off, so the cause
   is not proven. Because a configuration file can only lower a limit (PLAN.md v0.3), such a tree
   cannot be scanned completely in one run. No default was changed: this is an open decision for the
   owner (PLAN.md v0.15 item 2), stated in the README Limitations and in `docs/performance.md`.
4. **The measured throughput is modest**: 4.2 to 4.7 MiB of text per second on Windows (11.3 on
   Linux for small files), one core, pure Python. 600 s x 4.2 MiB/s = 2,520 MiB, so on this machine
   the time budget is reached before the default `MAX_TOTAL_BYTES` of 4 GiB.
5. **The default thresholds of the entropy detector are quiet.** On this repository and on the
   packages installed in the project's virtual environment (25.2 MiB together) it reported nothing
   at the default confidence and at least 1,200 strings at low confidence.
6. **One entropy fake is not detected.** `fake_entropy_token("bench-b")` scores below the 4.5 bits
   per character threshold, so the detector does not report it. That is the documented false
   negative of a fixed threshold (docs/rules.md); the test uses another seed.
7. **The mini-siem ingest was not repeated for 1.0.0.** CLAUDE.md section 4 allows only a read of
   mini-siem's parser source in this phase. The history example and the stored event in
   `docs/siem-mapping.md` therefore keep the `tool_version` `0.1.0` they were recorded with on
   2026-11-09, the document says so, and the drift test pins exactly that one value as recorded.
8. **The account name of this machine is not the name of its profile directory.** The hygiene test
   therefore takes the names from the login name and from `Users/<name>` or `home/<name>` in the
   temporary directory, the interpreter and the checkout, and looks for them only below such a
   parent (the word `runner` in `gitio/runner.py` is not the CI account `runner`).
9. The base Python of the project's virtual environment is a Microsoft Store installation, whose
   executable cannot be started by path. The release-check environments were therefore created with
   `.venv`'s own `python -m venv` (same Python 3.13.14).
10. One command that joined `gate.py` with another command through a pipe was blocked by the Claude
    Code hook, as designed; nothing ran.
11. **The Linux run on the commit of this report found a test that was wrong on Linux only.** The
    new check "no document names the system temporary directory" failed in WSL for
    `docs/performance.md`, which says that the Linux measurement wrote its files to `/tmp`: on Linux
    `/tmp` is the system temporary directory, on Windows it is a path below the user's profile. The
    shared `/tmp` identifies no machine and no account, so the check now skips it (`/tmp` and
    `/var/tmp`) and keeps flagging a per-user temporary directory; the document was right and was
    not changed. This is the second time in this project that only the Linux run showed a fault
    (Phase 5, item 2). It would have failed CI on Ubuntu.

### Review of the security-critical modules

Done as an audit of every invariant of CLAUDE.md section 5 against the tests that prove it (the
result is the control list of `docs/threat-model.md`, each control with its tests, checked by a
drift test), plus a re-read of `core/redact.py`, of the process start and stop code of
`gitio/runner.py`, and a check of every git setting the threat model names against the runner's
source. Finding: item 2 above (a missing test, no defect). Not re-read line by line in this phase:
`fs/walk.py`, `fs/safe_files.py`, `core/sanitize.py`, `core/regex_guard.py`; they are covered by
their tests (99.71% branch coverage) and by `bandit`, below.

### Release checks (CLAUDE.md section 11)

In a temporary directory outside the repository, deleted afterwards (no build output is in the
repository). Commit checked: `f259e89`, a local `git clone` of it with a clean status. Tools:
build 1.6.1 (hatchling 1.33.0), pip-audit 2.10.1, bandit 1.9.4, Python 3.13.14.

1. `python -m build`: `Successfully built secret_scanner-1.0.0.tar.gz and
   secret_scanner-1.0.0-py3-none-any.whl`. Wheel: 65 files, the rules file and `py.typed`
   included, no tests, no byte code. Metadata: `Name: secret-scanner`, `Version: 1.0.0`,
   `Author: Otabek Yakubov`, `License-Expression: MIT`, `Development Status :: 4 - Beta`,
   `Requires-Python: >=3.11`, `Requires-Dist: pyyaml>=6.0.1`; no address in it. The sdist holds
   `src`, `README.md`, `LICENSE` and `pyproject.toml` (not `docs/`, so the README's links to the
   documents work on the repository page, not inside the sdist).
2. The wheel installed into a clean virtual environment (`pip list`: pip 26.1.2, PyYAML 6.0.3,
   secret-scanner 1.0.0). There:
   - `secret-scanner --version` and `python -m secret_scanner --version`: `secret-scanner 1.0.0`;
   - `secret-scanner rules`: exit 0, 39 lines, `16 built-in rules`; `rules --format json`: exit 0;
   - `secret-scanner demo`: exit 0, 67 lines, nothing on standard error, both headers show
     `<temporary directory>`, `3 reported, 1 suppressed` and `1 reported, 0 suppressed`;
   - a driver script planted 18 runtime-generated fakes (one per rule, a private key, an entropy
     token, and three in the history of a throw-away repository that are removed in its second
     commit) and ran the installed console script: `scan` and `scan-git` in `table`, `json`,
     `jsonl` and `sarif`, each to standard output and to `--output`: exit code 1 every time;
     `scan` found 15 findings from 15 rules, `scan-git` the 3 removed secrets with their commit;
     the baseline round trip gave exit 1 then 0 for both; three error paths gave exit 2, 3 and 2.
     Every output, written file and baseline was checked against every fake with the leak check of
     the test suite: **414 checks, 0 leaks**. The positive control (the planted file itself)
     is reported as a leak.
3. `pip-audit`: for the runtime dependency alone (`PyYAML==6.0.3`): `No known vulnerabilities
   found`. For the whole clean environment it reports `pip 26.1.2 PYSEC-2026-3721` (fixed in 26.2):
   that is the pip that `python -m venv` puts into every new environment on this machine, not a
   dependency of this project, and nothing the wheel ships. `secret-scanner` itself is skipped
   ("not found on PyPI").
4. `bandit -r src`: 7,300 lines, **0 high, 0 medium, 9 low, no `nosec` and no suppression**. The
   nine, each explained instead of suppressed:
   - B105 "possible hardcoded password" (4): two character-class strings of the entropy detector
     (`core/detect/entropy.py`, lines 37 and 38) and the group name and a refusal-reason name of
     the regex guard (`core/regex_guard.py`, lines 40 and 87). They are names and alphabets, not
     credentials.
   - B404 and B603 (5): the `subprocess` import and calls of `gitio/runner.py` (lines 30, 196, 224)
     and `gitio/demo_git.py` (lines 19, 87). Starting git is what these two modules are for:
     argument lists, `shell=False`, an absolute program path, a from-scratch environment
     (docs/git-hardening.md); the architecture check allows `subprocess` nowhere else.

### Final self-checks

- `secret-scanner scan-git .` on this repository's full history (after `f259e89`): `No findings.`,
  `60 commits, 355 blobs scanned`, `history complete: yes`, `complete: yes`, exit code 0.
  `secret-scanner scan . --gitignore`: `No findings.`, 161 files scanned, exit code 0.
- Tracked files (and untracked ones that are not ignored), all by tests of the gate: no email
  address, no bidirectional, zero-width or control character, no key or secret file, no string a
  built-in rule or the private key detector matches, and (new) no account profile path, system
  temporary directory or absolute path of the checkout.
- One thing the last check does not cover, found by a search for absolute paths: the WSL spelling
  of the project folder (the Windows drive mount, then the folder path, no account name in it)
  is written in CLAUDE.md line 101, in the Linux-check command, and in
  `tests/test_hook_guard_gate.py` line 80, which quotes that command to test the hook. It was left
  as it is, because CLAUDE.md is the owner's rule file and the command is used verbatim. Every
  other absolute path in a tracked file is an invented example in a test.

### Measured (this machine: Windows 11, Python 3.13.14, git 2.54.0.windows.1, 2026-11-10)

- Full gate, Windows, on the tree committed as `9c9ea00`: 2561 passed, 23 skipped (POSIX-only),
  225.95 s pytest, 235.4 s in total, **99.71%** branch coverage. Missed: POSIX branches of
  `fs/safe_files.py`, `fs/sandbox.py`, `gitio/demo_git.py`, the runner and `scripts/bench.py`.
- Full gate, WSL Ubuntu (git 2.53.0, Python 3.14.4, outside the CI matrix), on the committed
  `9c9ea00`: 2557 passed, 27 skipped (Windows-only), 24.18 s pytest, 38.5 s in total, **99.74%**.
  The editable install in WSL was repeated first, because the installed metadata still said 0.1.0.
- Default gate, Windows, the five runs of this session in order: 81.1 s, 90.4 s, 76.1 s, 97.4 s and
  95.5 s in total (pytest alone 73.2 s to 86.3 s; 2475 passed, 20 skipped, 89 deselected at the
  end; 99.22%). Three of the five are above the 90 s of CLAUDE.md section 7 and above the 72 s to
  82 s the owner accepted; in two of those mypy took twice its usual time, which points at the
  machine being busy, but the suite also grew by 48 default tests. Nothing was moved to `slow` for
  it, as decided; the tests of this phase that take more than a second are marked `slow`.
- After this report was first committed (`9fbc97b`), the full gate ran on that commit: Windows
  passed (2561 passed, 23 skipped, 275.54 s pytest, 292.3 s in total, 99.71%); WSL failed 2 of 2557
  tests (item 11 above). The fix is in the commit that follows `9fbc97b`, and both full gates were
  run again on it; a report cannot hold the result of a run on its own commit, so those two results
  are in the session summary and are the ones to compare with CI.
- The benchmark numbers are in `docs/performance.md` and nowhere else.

`git log --oneline -15` before this report was committed:

```
f259e89 docs: add the Linux (WSL 2) measurement to docs/performance.md
9c9ea00 docs: write the 1.0.0 README, threat model, rules and performance documents with scripts/bench.py, SECURITY.md and CONTRIBUTING.md; add drift tests, the invariant 10 tests and the local-path hygiene test (PLAN.md v0.15)
ce06835 release: set version 1.0.0 from its single source, with the changelog entry and tests that metadata, command line and changelog agree
6a0eaeb build: declare Development Status 4 - Beta and pin it with a test
3ab13d8 docs: record the owner's Phase 6 decisions and the accepted default gate time (PLAN.md v0.14)
0e64191 fix: show a fixed label instead of the demo's temporary path, with tests that the output names no path, account or temporary directory
13b772a docs: record the owner's acceptance of PLAN.md v0.13 and of the rewrite of two unpushed commits
eae0f05 docs: add the Phase 5 report with the real mini-siem check and the measured gate numbers
fa248b5 test: resolve directory-descriptor paths in the audit helper and accept git's own posix_spawn (found by the Linux run)
5ae388b fix: escape the name and description of a custom rule in rule listings and SARIF; record the Phase 5 interpretations (PLAN.md v0.13)
2710930 test: add the cross-format leak matrix, hostile names per format and docs/siem-mapping.md with a real mini-siem ingest
0631ca6 feat: add the demo command with a sandboxed temporary tree, a throw-away repository and audit-hook guard tests
cda8a74 feat: add the SARIF 2.1.0 output format with structural tests, docs/sarif.md and drift tests
9fe0fea feat: add the rules command (table and JSON, secret-rules/1) with drift tests against the rules file
8be925c feat: add the JSONL output format (secret-event/1) shaped for mini-siem's generic JSON parser
```

```
Built: version 1.0.0 from one source (pyproject metadata, --version, installed metadata and CHANGELOG agree, tested); README with real pasted output (demo, scan, baseline round trip), every command and option, exit codes, limits, "How findings are shown", "What the tool reads and writes", an unverified CI example with SARIF upload, the mini-siem section, a 25-row claim-to-evidence table and the Limitations; docs/threat-model.md finished (assets, trust, attackers, the 11 invariants each with its tests, residual risks, F-1 kept); docs/rules.md (generated table); docs/performance.md from scripts/bench.py (trees of 1,000 to 100,000 files, a larger-file tree, histories of 1,000 and 5,000 commits, the entropy corpus; Windows and Linux in WSL 2); SECURITY.md; CONTRIBUTING.md; the demo shows a fixed label instead of its temporary path; Beta classifier; release checks passed in a temporary environment outside the repository
Tests added: 53 (suite 2584 collected on Windows, 89 slow): README 15 (examples are real output, options, exit codes, limits, constants, claims name existing evidence, required limitations), bench 16 (self-check, counts only, no leak, the document's commands and tables), release metadata 8 (one version everywhere, classifier), rules document 6, demo 4 (no path, account or temporary directory in the output), invariant 10 two (scan and scan-git), the documented mini-siem command 1, the local-path hygiene test 1
Real coverage: 99.71% (branch, full gate, Windows, tree of commit 9c9ea00); 99.74% in the WSL Linux full gate (git 2.53.0, Python 3.14.4); floor 85
Known gaps: a tree that needs more than MAX_RUN_SECONDS (600 s) cannot be scanned completely in one run, because a configuration file can only lower a limit, and on this Windows machine a first scan of 100,000 freshly written files does not finish in that time (owner decision open, PLAN.md v0.15 item 2); the cause of the slow first scan was not proven (no run with antivirus protection off); default gate 76.1 s to 97.4 s in this session, three of five runs above CLAUDE.md's 90 s; SARIF not validated against the official schema and not uploaded to GitHub code scanning, the README's CI workflow never run, the install-from-tag command not tried (no GitHub access); mini-siem ingest not repeated for 1.0.0 (two recorded values keep tool_version 0.1.0, stated), mini-siem cannot search by secret.* attributes and no detection rule ships; pip-audit flags the pip of the virtual environment (PYSEC-2026-3721, not a dependency of the project); bandit reports 9 low findings, explained and not suppressed; the Phase 6 code has not run on CI (Python 3.11 and 3.12 untested locally: local 3.13, WSL 3.14), macOS untested; the WSL path of the project folder is written in CLAUDE.md line 101 and in the hook test that quotes it; walk.py, safe_files.py, sanitize.py and regex_guard.py were not re-read line by line in this phase; memory near the 8 MiB file limit and anything near the hard ceilings was not measured; the 100,000-file rate on Linux is half the 10,000-file rate and was not investigated; scripts/bench.py does not mark a repeat scan that was incomplete (the document explains the one affected row); the release-check driver is not in the repository
Deviations from PLAN.md: v0.15, awaiting acceptance (bench reports first and repeat scans apart and adds a larger-file tree; no D18 default changed although MAX_RUN_SECONDS is put in question; docs/rules.md generated by a test helper, not by a command; the mini-siem ingest not repeated; the release-check driver kept outside the repository); PLAN.md Phase 6 asked for a "final review of the security-critical modules": done as an invariant-to-test audit plus a partial re-read, not a full line-by-line review; the Limitations of PLAN.md Phase 6 and of the owner's list are all in the README (a test pins them)
```
