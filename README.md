# secret-scanner

A defensive secret scanner for directories and git repositories you own. It finds credentials
that were committed or left in files (cloud keys, access tokens, private keys, high-entropy
strings), tells you where they are and, for git history, which commit introduced them, and exits
with a code a CI job can act on.

It is built to be safe to run on content you do not trust:

- **offline**: it makes no network connection, and it never checks a secret against a service;
- **read-only**: nothing in a scanned directory or repository is created, changed or deleted;
- **quiet about what it finds**: no output, error message or file ever holds a whole secret, only
  a redacted form and a fingerprint.

What it is not: it does not verify, revoke or rotate secrets, it does not rewrite git history, it
does not unpack archives or binary formats, and a clean result means "nothing matched", not "no
secret exists". The [Limitations](#limitations) section is part of the documentation, not a
footnote.

Version 1.0.0. Python 3.11 or newer. One runtime dependency (PyYAML). git 2.32 or newer is needed
only for `scan-git`, `scan --gitignore` and the history part of `demo`. Tested on Windows and
Linux; macOS is untested.

## Scan only what you are allowed to scan

Run this tool only on code, directories and repositories that you own or are explicitly authorised
to scan. Looking for credentials in other people's systems or repositories without permission may
be illegal where you live and is not what this project is for. If the tool finds a credential,
treat it as exposed and have it revoked by its owner; do not try it out.

## Install

The project is not on PyPI. Install it from a checkout:

```
git clone https://github.com/Cosmos0560/secret-scanner
cd secret-scanner
python -m pip install .
```

This is what the release check does (it builds the wheel and installs it into a clean virtual
environment; see `docs/phase-reports.md`, Phase 6). Installing straight from the tag should work
too, but could not be tried from the development machine, which has no access to GitHub:
`python -m pip install "git+https://github.com/Cosmos0560/secret-scanner@v1.0.0"`.

```
$ secret-scanner --version
secret-scanner 1.0.0
```

`python -m secret_scanner` is the same program.

## Quick start

`secret-scanner demo` shows what the tool does without touching anything of yours: it plants fake
secrets (built at run time, valid nowhere) in a temporary directory and in a throw-away git
repository, scans both with the real code, prints the result and removes everything, also when it
fails or is interrupted. This is its real output:

```
$ secret-scanner demo
secret-scanner demo
===================

Everything below happens in a temporary directory that is removed at the end,
shown here as <temporary directory>.

All secrets are fakes, built at run time from fragments; none is a real credential.
The tool never prints a whole secret: it prints a short public prefix, the length and
a short hash of the secret, and the place where it was found.

Step 1: scan a directory (secret-scanner scan DIR --baseline FILE --show-suppressed)

  The demo planted an AWS key id in .env, a GitHub token in config/settings.py, a
  private key block in deploy/id_demo and an npm token in legacy/notes.txt. It wrote a
  baseline that accepts the npm token (by fingerprint) and scanned with it:

secret-scanner 1.0.0 - scan of <temporary directory>/tree
generated 2026-11-10T12:03:09Z

SEVERITY  CONFIDENCE  RULE               LOCATION                 REDACTED
high      high        aws-access-key-id  .env:2:19                AKIA... [20 chars, sha256:c903a783]
critical  high        github-token       config/settings.py:3:17  ghp_... [40 chars, sha256:63e9a383]
critical  high        private-key        deploy/id_demo:1:1       [RSA private key, 192 base64 chars, sha256:1c10bd6b]
high      high        npm-token          legacy/notes.txt:1:21    npm_... [40 chars, sha256:e74a538a] [suppressed: fingerprint]

Summary
  files:     4 scanned of 4 seen (470 bytes)
  skipped:   none
  findings:  3 reported, 1 suppressed (1 by fingerprint, 0 by path)
             1 suppressed finding(s) listed above
  stale:     0
  issues:    0
  complete:  yes

  Three findings are reported. The accepted one is listed only because of
  --show-suppressed and is marked; without it, it is counted in the summary and not
  listed. A real run would exit with code 1 here, which is what fails a CI job.

Step 2: scan git history (secret-scanner scan-git REPO)

  The throw-away repository has 2 commits. The first adds a Stripe-style key to
  service/settings.txt; the second replaces it with a note. Scanning the repository's
  current files finds 0 secrets. Scanning its history finds
  the key and names the commit that introduced it:

secret-scanner 1.0.0 - history of <temporary directory>/repo
generated 2026-11-10T12:03:10Z

SEVERITY  CONFIDENCE  RULE               LOCATION                                REDACTED
critical  high        stripe-secret-key  service/settings.txt:2:14@661c993a9f2e  sk_live_... [38 chars, sha256:659c7f7f]

Summary
  files:     3 scanned of 3 seen (229 bytes)
  skipped:   none
  history:   2 commits, 3 blobs scanned, 0 from cache
  history complete: yes
  findings:  1 reported, 0 suppressed (0 by fingerprint, 0 by path)
  stale:     0
  issues:    0
  complete:  yes

  Deleting a secret from the files does not remove it from the history. Revoke it.

Other output: --format json, jsonl (for mini-siem) and sarif (for code scanning);
--write-baseline records the current findings; `secret-scanner rules` lists the rules.

Cleanup: the temporary directory and everything in it was removed.
```

The demo exits with code 0 when it ran as designed, and with 3 when git is not available (the
directory part still runs).

Scanning your own project works the same way. `project` below is a small generated directory with
two fake secrets:

```
$ secret-scanner scan project
secret-scanner 1.0.0 - scan of project
generated 2026-11-10T12:03:11Z

SEVERITY  CONFIDENCE  RULE               LOCATION          REDACTED
high      high        aws-access-key-id  config/.env:2:19  AKIA... [20 chars, sha256:11c64dd5]
high      high        npm-token          src/app.py:3:10   npm_... [40 chars, sha256:473b5357]

Summary
  files:     3 scanned of 3 seen (144 bytes)
  skipped:   none
  findings:  2 reported, 0 suppressed (0 by fingerprint, 0 by path)
  stale:     0
  issues:    0
  complete:  yes
```

The exit code of that run is 1, because there are findings. To accept the findings that are
already known and fail only on new ones, write a baseline and use it:

```
$ secret-scanner scan project --write-baseline baseline.yaml
secret-scanner: baseline with 2 entries written to baseline.yaml
$ secret-scanner scan project --baseline baseline.yaml
secret-scanner 1.0.0 - scan of project
generated 2026-11-10T12:03:12Z

No findings.

Summary
  files:     3 scanned of 3 seen (144 bytes)
  skipped:   none
  findings:  0 reported, 2 suppressed (2 by fingerprint, 0 by path)
  stale:     0
  issues:    0
  complete:  yes
```

The second run exits with code 0. (The table of the first run is the same as above and is left
out here; it goes to standard output, the notice to standard error.)

## Commands

```
secret-scanner scan PATH        scan the files of a directory tree
secret-scanner scan-git REPO    scan the history of a git repository
secret-scanner rules            list the built-in rules
secret-scanner demo             plant fake secrets in a temporary place, scan them, clean up
secret-scanner --version
```

### `scan PATH`

Reads every regular file under `PATH` and reports what the rules, the private key detector and
the entropy detector find. Hidden files such as `.env` are scanned. Links are never followed.

These directories are skipped by default wherever they appear: `.git`, `.hg`, `.svn`,
`node_modules`, `.venv`, `venv`, `__pycache__`, `.tox`, `.nox`, `.mypy_cache`, `.ruff_cache`,
`.pytest_cache`.

| Option | Meaning |
|---|---|
| `--gitignore` | Scan only the files git lists for the directory: tracked files, plus untracked files that are not ignored. `PATH` must be inside a git work tree. |
| `--no-default-excludes` | Also scan the directories listed above. |
| `--allow-other-owner` | With `--gitignore`: accept a repository that belongs to another user (git's "dubious ownership" check). |
| `--git PATH` | With `--gitignore`: the git program to use, as an absolute path. |

plus the [report options](#report-options-of-scan-and-scan-git).

### `scan-git REPO`

Scans every blob that was added or modified in the history of the repository at `REPO` (the top
directory of a work tree, or a bare repository): all refs by default, so branches, tags, remotes
and the stash. Each blob is scanned once. A secret is reported once per file path, with the first
commit that introduced it, so a secret that was committed and removed later is still found, and
one that was kept for a thousand commits is one finding.

| Option | Meaning |
|---|---|
| `--rev REV` | Scan only the history reachable from `REV`. |
| `--range A..B` | Scan only the commits in `A..B`. Cannot be combined with `--rev`. |
| `--allow-shallow` | Accept a shallow clone. Without it a shallow repository makes the run incomplete (exit code 4), because history before the cut-off cannot be scanned. |
| `--allow-other-owner` | Accept a repository that belongs to another user. |
| `--git PATH` | The git program to use, as an absolute path (on Windows it must be called `git.exe`). By default git is looked for on `PATH`. |

plus the [report options](#report-options-of-scan-and-scan-git).

Run `scan` from the repository root if you want `scan` and `scan-git` to agree on fingerprints:
both then use paths relative to the same root.

### Report options of `scan` and `scan-git`

| Option | Meaning |
|---|---|
| `--format FORMAT` | `table` (default), `json`, `jsonl` or `sarif`. |
| `--output FILE` | Write the report to `FILE` instead of standard output. |
| `--force` | Allow `--output` and `--write-baseline` to replace an existing file. |
| `--config FILE` | Read a configuration file (YAML). |
| `--baseline FILE` | Suppress the findings listed in `FILE`. |
| `--write-baseline FILE` | Write a baseline of the current findings to `FILE`. |
| `--show-suppressed` | Also list the findings the baseline suppresses, marked as such. |
| `--min-confidence LEVEL` | Lowest confidence to report: `low`, `medium` (default) or `high`. |
| `--fail-on LEVEL` | Lowest severity that makes the exit code 1: `info`, `low` (default), `medium`, `high` or `critical`. |
| `--host-label TEXT` | Host name written into JSON and JSONL output (default: the machine's name). |

Three rules about paths that are worth knowing before the first CI run:

- `--output` and `--write-baseline` may not point into the scanned tree, and no path given to the
  tool may contain `..`. Scan a directory by name from its parent (`secret-scanner scan project
  --output report.json`) or give the output an absolute path.
- An existing file is never replaced without `--force`, and a link is never written through.
- Configuration, rules and baselines are read only from the files you name. Nothing is picked up
  from the scanned tree, the current directory or your home directory.

### `rules`

`secret-scanner rules` lists the 13 token-format rules and the 3 detectors with id, severity,
confidence, description and keywords; `secret-scanner rules --format json` prints the same as
JSON. It prints no example secret. The table is also in [docs/rules.md](docs/rules.md).

| Option | Meaning |
|---|---|
| `--format FORMAT` | `table` (default) or `json`. |

### `demo`

No options. See [Quick start](#quick-start).

### Baseline

A baseline is a YAML file that lists findings you have reviewed and accept, so that a CI job fails
only on new ones. `--write-baseline FILE` writes one entry per current finding (fingerprint, rule
and path, and a reason for you to replace); `--baseline FILE` suppresses those findings. You can
also add path globs under `paths:` to suppress everything below a directory.

- A suppressed finding is not listed (unless you ask with `--show-suppressed`) and does not fail
  the run, but every report says how many findings were suppressed and how.
- Entries that match nothing any more are counted as `stale`, so a baseline does not silently
  grow old.
- Writing a baseline does not change the exit code of that run.
- A fingerprint depends on the rule, the file path relative to the scan root and the secret, not
  on the line: moving a secret inside a file keeps it suppressed, renaming the file does not.
- Review changes to the baseline like code. A pull request that adds its own secret's fingerprint
  to the baseline hides that secret; the tool cannot know who wrote the file.

### Output formats

| Format | What it is | Documented in |
|---|---|---|
| `table` | Text for people: severity, confidence, rule, `file:line:column` (and `@commit` for history), the redacted value, then a summary. | [docs/report-schema.md](docs/report-schema.md) |
| `json` | One document, schema `secret-report/1`, with findings, issues, statistics and counts. | [docs/report-schema.md](docs/report-schema.md) |
| `jsonl` | One event per line plus a summary line, schema `secret-event/1`, shaped for mini-siem. | [docs/siem-mapping.md](docs/siem-mapping.md) |
| `sarif` | SARIF 2.1.0 for code-scanning tools. | [docs/sarif.md](docs/sarif.md) |

The machine formats are ASCII only, and every file name, path and other text taken from scanned
content is escaped before it is written, in every format.

### Exit codes

| Code | Meaning |
|---|---|
| 0 | Clean and complete: everything was read and nothing at or above `--fail-on` was found. |
| 1 | Findings at or above `--fail-on` that the baseline does not suppress. |
| 2 | Usage, configuration, rules, baseline or input/output error. |
| 3 | git is not available, too old, refused the repository or failed. |
| 4 | Incomplete run: a limit, the time budget, an unreadable file, missing objects or shallow history. Findings found so far are still reported. |
| 130 | Interrupted with Ctrl-C. |

When more than one applies, the order is 2, then 3, then 4, then 1, then 0. An incomplete run is
never reported as clean.

### Configuration file

`--config FILE` reads an optional YAML file: `version: 1`, and any of `exclude` (path globs that
are not read at all), `min_confidence`, `fail_on`, `entropy` (`enabled`, `base64_threshold`,
`hex_threshold`, `min_length`), `disable_rules` (rule ids), `extra_rules` (your own rules, ids
starting with `custom-`, checked by the same regex guard) and `limits` (lower only). Command-line
options override the file. Unknown keys, duplicate keys, YAML aliases and tags are refused with
exit code 2.

### Limits

Every size the tool handles is bounded. A configuration file can lower a limit, never raise it
above the hard ceiling. Reaching a limit never stops the tool silently: it is recorded as an
issue, the run is marked incomplete and the exit code is 4.

| Limit (`limits:` key) | Default | Hard ceiling |
|---|---|---|
| `max_files` (entries, directories included) | 200,000 | 1,000,000 |
| `max_depth` | 64 | 128 |
| `max_file_bytes` (a larger file or blob is not scanned) | 8 MiB | 64 MiB |
| `max_line_bytes` (a longer line is scanned up to here) | 256 KiB | 4 MiB |
| `max_total_bytes` | 4 GiB | 16 GiB |
| `max_run_seconds` | 600 | 3,600 |
| `max_git_commits` | 200,000 | 1,000,000 |
| `max_git_blobs` | 1,000,000 | 2,000,000 |
| `max_findings` (reported) | 10,000 | 10,000 |
| `max_findings_per_file` | 200 | 1,000 |

The complete list is in `src/secret_scanner/core/limits.py`. What these sizes cost in time and
memory on one machine is measured in [docs/performance.md](docs/performance.md).

## How findings are shown

A finding is never shown with its secret. Every output shows this redacted form instead:

```
<public prefix>... [<length> chars, sha256:<8 hex digits>]
```

- **The public prefix** is the fixed text every token of that kind starts with (`AKIA`, `ghp_`,
  `sk_live_`), which carries no secret information. It is at most 12 characters and at most a
  quarter of the secret. For a high-entropy string, which has no fixed prefix, the first 4
  characters are shown if the string has at least 32, and nothing otherwise.
- **The length** is the number of characters of the secret.
- **The 8 hex digits** are the start of `sha256("secret-scanner/display/v1" + NUL + secret)`. They
  let you tell two findings apart, or check a secret you already hold against a finding. They are
  too short to identify a secret, and every rule only reports values with at least 64 bits of
  estimated randomness, so the hash cannot be guessed back.
- **A private key** is shown as `[RSA private key, 1592 base64 chars, sha256:...]`: the key type,
  the length of its body and the hash, nothing of the key.
- **No source line is printed**, in any format: the line could hold a second secret that no rule
  matched.

Every finding also has a **fingerprint**: the first 32 hex digits (128 bits) of
`sha256("secret-scanner/fingerprint/v1" + NUL + rule id + NUL + path + NUL + secret)`, where the
path is relative to the scan root with `/` separators. It is what a baseline lists and what SARIF
carries as `partialFingerprints`. Line, column and commit are not part of it.

Severity (how bad a leak of this kind is) and confidence (how sure the detection is) are separate
fields in every format.

## What the tool reads and writes

**Reads**

- `scan`: the regular files under the directory you name. Symbolic links, junctions and other
  reparse points are recorded and never followed; FIFOs, sockets and devices are never opened;
  cloud placeholder files are not read (reading would download them). A file is binary, and is
  counted but not scanned, when its first 8,000 bytes contain a NUL byte.
- `scan-git`: the repository's objects, through git only (below). No commit message, author name
  or tag message is read.
- The files named by `--config` and `--baseline`, and the rules file inside the installed package.
  Nothing else: no file is discovered by name anywhere.

**Runs**

`scan` starts no program at all. `scan-git` and `scan --gitignore` start git, and only these
commands: `version`; `rev-parse` (to find the git directory, to ask whether the repository is
shallow, and to turn a revision into a commit id); `log` (the history walk: commit ids, parent
ids, committer times and the list of changed blobs); `cat-file --batch-check` and `cat-file
--batch` (blob sizes and contents); and, for `scan --gitignore` only, `ls-files`. All of them only
read.

git is started with these precautions, because a repository can otherwise make git run programs
(the complete lists are in [docs/git-hardening.md](docs/git-hardening.md)):

- by absolute path, with an argument list, never through a shell; the program is found only on
  fully qualified `PATH` entries, never in the current directory, the scanned tree or the
  temporary directory, and on Windows only as `git.exe`;
- with an environment built from scratch: no user or system configuration, no terminal prompt, no
  pager, no optional locks, no replacement objects, no lazy fetching;
- with every setting that could start a program or reach the network pinned on the command line:
  no hooks, no file-system monitor, no external diff or text conversion, no credential helper, no
  ssh or proxy command, no signature check, every transport protocol disabled;
- with user-supplied revisions checked and resolved to commit ids first, and only ids passed on;
- with bounded output and time; a git that has to be stopped is stopped by its process id.

A repository whose `.git` is a file or a link (a worktree or a submodule checkout), that borrows
objects through alternates, or that has grafts is refused with exit code 3 instead of being read
in a way the scan cannot account for.

**Writes**

Only the files you ask for: `--output FILE` and `--write-baseline FILE`. Each is written to a
temporary file in the same directory and then moved into place in one step (atomically); it is
never written through a link; an existing file is replaced only with `--force`; and the target
may not be inside the scanned tree or be the configuration or baseline file the run reads. `demo`
writes only inside one temporary directory that it creates and removes.

Nothing else is written: no cache, no log file, no state between runs.

## Using it in CI

The exit codes are made for this: 1 fails the job on new findings, 4 fails it when the scan could
not look at everything.

The workflow below scans the checked-out tree, uploads the result as SARIF and uses a baseline
kept in the repository. **It has not been verified**: the development machine has no access to
GitHub, so this workflow was never run, the SARIF output has not been uploaded to GitHub code
scanning or validated against the official SARIF schema, and the action versions are the ones
known when this was written. Treat it as a starting point and check the first run.

```yaml
name: secrets
on:
  push:
    branches: [main]
  pull_request:

permissions:
  contents: read
  security-events: write   # needed by the SARIF upload

jobs:
  scan:
    runs-on: ubuntu-24.04
    steps:
      - uses: actions/checkout@v5
        with:
          persist-credentials: false
      - uses: actions/setup-python@v6
        with:
          python-version: "3.13"
      - name: Install secret-scanner
        run: python -m pip install "git+https://github.com/Cosmos0560/secret-scanner@v1.0.0"
      - name: Scan the checked-out tree
        run: >
          secret-scanner scan .
          --baseline .github/secret-baseline.yaml
          --format sarif
          --output "$RUNNER_TEMP/secrets.sarif"
      - name: Upload the SARIF file
        if: always()
        uses: github/codeql-action/upload-sarif@v3
        with:
          sarif_file: ${{ runner.temp }}/secrets.sarif
```

Notes:

- The report is written to the runner's temporary directory because an output inside the scanned
  tree is refused.
- Leave `--baseline` out until you have a baseline file. Because the baseline here comes from the
  branch under test, protect that file with code-owner review.
- To scan history as well, check out with `fetch-depth: 0` and add a `secret-scanner scan-git .`
  step. SARIF results of a history scan can point at files that no longer exist at the tip of the
  branch.

## Feeding findings to mini-siem

`--format jsonl` writes one JSON object per finding and a final summary line, shaped so that
the generic JSON parser of mini-siem (a sibling project of the same author) ingests the file
without any change to mini-siem:

```
secret-scanner scan project --format jsonl --host-label build-01 --output events.jsonl
mini-siem ingest events.jsonl --format json
```

The field list, mini-siem's limits and a real ingest with mini-siem 1.0.0 are in
[docs/siem-mapping.md](docs/siem-mapping.md). Two things to know: mini-siem 1.0.0 cannot search by
the `secret.*` attributes (free text finds the message), and this project ships no mini-siem
detection rule for these events.

## Claims and evidence

Every claim this README makes about safety or quality, with the test or document that backs it. A
test (`tests/test_readme.py::test_every_claim_names_evidence_that_exists`) fails when a named test
or document does not exist.

| Claim | Evidence |
|---|---|
| No output format, error path or the demo ever contains a secret or a long run of one | `tests/test_scan_leakage.py::test_every_format_of_every_rule_carries_no_secret`, `tests/test_scan_leakage.py::test_nothing_that_scan_emits_contains_the_secret`, `tests/test_git_scan.py::test_nothing_that_scan_git_emits_contains_the_secret`, `tests/test_demo.py::test_the_demo_prints_no_full_fake` |
| A finding cannot hold a secret: no model that reaches a renderer has a field for one | `tests/test_models.py::test_nothing_reachable_from_report_can_hold_a_secret` |
| At most 12 characters and a quarter of a secret are ever shown | `tests/test_redact.py::test_never_shows_more_than_a_quarter_or_twelve_characters` |
| The fingerprint is defined as documented and does not depend on line, column or commit | `tests/test_fingerprint.py::test_golden_vector`, `tests/test_fingerprint.py::test_line_column_and_commit_are_not_inputs` |
| No network access: network modules are banned in the source, and git cannot fetch | `tests/test_check_architecture.py::test_the_real_tree_passes`, `tests/test_git_hostile.py::test_a_missing_blob_does_not_trigger_a_lazy_fetch_over_any_transport`, `tests/test_demo.py::test_the_demo_makes_no_network_call_and_changes_no_process_state` |
| A scan changes nothing in the scanned directory or repository | `tests/test_app_scan.py::test_the_scanned_tree_is_never_changed`, `tests/test_git_scan.py::test_the_scan_changes_nothing_in_the_repository` |
| A hostile repository cannot make git run a program | `tests/test_git_hostile.py::test_scan_git_runs_nothing_and_still_finds_the_secret`, `tests/test_git_hostile.py::test_the_hostile_repository_really_does_fire_markers_when_git_is_not_protected`, `tests/test_git_hostile.py::test_scan_gitignore_runs_nothing` |
| git gets a fixed environment, a closed command set and pinned configuration | `tests/test_git_runner.py::test_the_callers_environment_is_never_inherited`, `tests/test_git_runner.py::test_the_command_set_is_closed`, `tests/test_git_runner.py::test_pinned_configuration_key_by_key`, `docs/git-hardening.md` |
| A planted `git` program is never run (finding F-1) | `tests/test_git_hostile.py::test_a_planted_git_program_is_never_chosen`, `tests/test_git_program_resolution.py::test_a_planted_program_that_would_run_is_never_run`, `docs/threat-model.md` |
| Links are never followed and only regular files are opened | `tests/test_walk.py::test_symlinks_are_recorded_and_never_followed`, `tests/test_walk.py::test_a_junction_is_not_traversed`, `tests/test_walk.py::test_fifos_are_recorded_and_never_opened`, `tests/test_walk.py::test_a_file_replaced_by_a_link_before_it_is_opened_is_never_followed` |
| File names and content cannot inject into any output format | `tests/test_output_formats.py::test_a_hostile_file_name_is_inert_in_every_format`, `tests/test_sanitize.py::test_exhaustive_sweep_over_every_code_point`, `tests/test_sanitize.py::test_newline_cannot_forge_a_second_log_line` |
| Outputs are written atomically, never through a link, never over a file without `--force`, never into the scanned tree | `tests/test_safe_files.py::test_an_existing_file_is_never_overwritten_without_force`, `tests/test_safe_files.py::test_a_link_target_is_refused_even_with_force_and_the_link_target_is_untouched`, `tests/test_safe_files.py::test_a_failed_write_leaves_neither_temporary_nor_a_changed_target`, `tests/test_app_scan.py::test_outputs_inside_the_scanned_tree_are_refused` |
| Configuration, rules and baselines are never discovered | `tests/test_app_scan.py::test_configuration_rules_and_baselines_are_never_discovered`, `tests/test_git_scan.py::test_configuration_rules_and_baselines_committed_to_a_repository_are_never_discovered` |
| Every limit is bounded, cannot be raised above its ceiling, and reaching one is exit code 4, never a clean result | `tests/test_limits.py::test_overrides_refuse_raising_and_nonsense`, `tests/test_app_scan.py::test_an_incomplete_run_without_findings_is_not_clean`, `tests/test_fs_scanner.py::test_the_time_budget_stops_the_scan_with_an_issue_and_keeps_the_findings` |
| No pattern, built-in or from a configuration file, can backtrack catastrophically | `tests/test_regex_guard.py::test_every_hostile_pattern_is_rejected_at_load_time`, `tests/test_loader_and_rules_schema.py::test_every_builtin_rule_is_within_the_guard_and_the_schema_promises`, `tests/test_regex_tripwire.py::test_rule_stays_fast_on_adversarial_lines` |
| YAML is loaded safely: no aliases, tags or duplicate keys | `tests/test_loader_and_rules_schema.py::test_aliases_and_anchors_are_refused`, `tests/test_loader_and_rules_schema.py::test_explicit_tags_are_refused`, `tests/test_loader_and_rules_schema.py::test_loader_never_uses_the_unsafe_apis` |
| A secret that was committed and later deleted is found, with the commit that added it | `tests/test_git_scan.py::test_a_secret_added_and_deleted_later_is_found_with_its_commit`, `tests/test_git_scan.py::test_a_secret_kept_for_many_commits_is_one_finding_at_the_first` |
| The demo cleans up, also on failure and on Ctrl-C, touches nothing outside its directory and prints no local path | `tests/test_demo.py::test_the_demo_touches_no_path_outside_its_temporary_directory`, `tests/test_demo.py::test_ctrl_c_removes_the_directory_too`, `tests/test_demo.py::test_the_demo_output_names_no_real_path_account_or_temporary_directory` |
| The JSONL output is what mini-siem 1.0.0 ingests | `tests/test_siem_mapping_doc.py::test_the_documented_command_runs_and_writes_the_documented_lines`, `docs/siem-mapping.md` |
| The SARIF output has the documented structure (not validated against the official schema) | `tests/test_render_sarif.py`, `tests/test_sarif_doc.py`, `docs/sarif.md` |
| This repository and its whole history contain nothing its own rules match | `tests/test_hygiene_secrets.py::test_repository_has_no_secret_shaped_strings`, `tests/test_self_history.py::test_the_repository_history_holds_no_secret_shaped_string` |
| The examples in this README are the tool's real output and its options are the real ones | `tests/test_readme.py::test_the_demo_output_is_what_the_demo_prints`, `tests/test_readme.py::test_the_scan_examples_are_what_the_commands_print`, `tests/test_readme.py::test_every_option_of_every_command_is_documented` |
| The version is 1.0.0 everywhere | `tests/test_release_metadata.py::test_the_installed_metadata_agrees_with_the_version`, `tests/test_release_metadata.py::test_the_newest_changelog_section_is_the_version_with_a_date` |
| The layering and the bans (network, shell, `assert`, `eval`) are enforced on every gate | `tests/test_check_architecture.py::test_every_rule_has_planted_violations_and_allowed_counterexamples`, `scripts/check_architecture.py` |
| The measured numbers are measured | `docs/performance.md`, `scripts/bench.py`, `tests/test_bench.py::test_a_tree_run_finds_exactly_the_planted_fakes` |

## Limitations

**Detection**

- Detection is by pattern and by entropy, so both kinds of error exist. False negatives: a secret
  in a format no rule knows, a secret that is split across lines or strings, encoded (base64 of a
  token), encrypted, compressed or otherwise obfuscated, a password with little randomness (there
  is deliberately no generic `password = ...` rule), a high-entropy string whose characters happen
  to repeat enough to score below the threshold. False positives: a random-looking identifier
  next to a name such as `token`, a test fixture, a revoked key. A clean result means that nothing
  matched.
- The token formats come from public vendor documentation as known on 2026-10-12, not from live
  verification. A vendor can change a format at any time, and new prefixes are not known until a
  rule is added. Only the 13 formats in [docs/rules.md](docs/rules.md) are covered.
- The tool never verifies a secret against a live service, by design: it makes no network
  connection. It cannot tell a live key from a revoked or an example one. Treat every finding as
  exposed until its owner says otherwise.
- Not scanned: binary files (a NUL byte in the first 8,000 bytes), archives, office documents,
  keystores and other binary formats; UTF-16 or UTF-32 text without a byte-order mark (it looks
  binary); files and blobs larger than the size limit (8 MiB by default; they are reported as
  issues); the part of a line beyond the line limit.
- The entropy detector reports a bare high-entropy string only with `--min-confidence low`, and a
  hex string only next to a suggestive name, because hashes are everywhere. It skips lockfiles,
  minified files, source maps and SVG files.

**Git history**

- Not scanned in version 1: commit messages, tag messages, author and committer names, notes, the
  reflog, unreachable objects (for example a commit that was amended away but not yet pruned),
  the contents of submodules (the entries are counted and skipped) and Git LFS objects (only the
  pointer files are in the history).
- Refused with exit code 3, deliberately: a repository whose `.git` is a file or a link (a
  worktree or a submodule checkout: scan the main repository), an object store that uses
  alternates (`git repack -a -d` makes it self-contained), and a repository with an `info/grafts`
  file. Git would follow these silently and read objects or parents the scan cannot account for.
- A shallow clone is incomplete history (exit code 4) unless you pass `--allow-shallow`; a partial
  clone reports its missing objects and is incomplete. Nothing is fetched.
- git must be trusted and at least version 2.32. The tool controls how git is started, not what
  git does with a repository.
- Between resolving the git program and starting it there is a time-of-check to time-of-use gap:
  someone who can write where git is installed could replace it in between (and could replace git
  itself anyway).
- SARIF results of a history scan can name files that no longer exist at the tip of a branch.

**Output and baselines**

- The public prefix, the length and 8 hex digits of a hash of each secret are visible to anyone
  who reads a report; for a high-entropy string of 32 characters or more, so are its first 4
  characters. Reports say where secrets are. Treat them accordingly.
- Fingerprints depend on the scan root and the file path: scanning a subdirectory, or renaming a
  file, gives different fingerprints, and a baseline written for one root does not match another.
- A baseline taken from the branch under test can suppress that branch's own secret.
- The SARIF output has not been validated against the official SARIF 2.1.0 schema (no offline
  copy was available; the structure is tested field by field against the specification) and has
  not yet been uploaded to GitHub code scanning. The CI workflow above has not been run.
- mini-siem 1.0.0 cannot search by the `secret.*` attributes of these events, and no mini-siem
  detection rule ships with this project.
- Characters that only look alike (a Cyrillic letter in a Latin file name) are printed as they
  are. Control, bidirectional and zero-width characters are always escaped.

**Platform and process**

- Tested on Windows 11 and Linux (CI: Windows and Ubuntu, Python 3.11 to 3.13). macOS is untested.
- Reading a file can update its access time on file systems that record it. Nothing else changes.
- A tree that needs more than the default time budget of 600 seconds cannot be scanned completely
  in one run. The run stops at the budget, reports what it found so far and ends as incomplete
  (exit code 4). A configuration file can only lower a limit, never raise it, and version 1.0.0
  has no option that raises the time budget. Scan such a tree in parts, one sub-directory per
  run.
- The first scan of files that were just written can be much slower than a repeat scan, because
  the operating system (and real-time antivirus protection, where it is on) inspects new files
  when they are first opened. This is where the time budget is reached first: on the development
  machine a first scan of 100,000 freshly written files did not finish in it; see
  [docs/performance.md](docs/performance.md).
- The benchmarks in `docs/performance.md` come from one machine (Windows, and Linux in WSL 2 on
  the same hardware) and generated input. They are not a promise about other hardware or real
  repositories.
- Two tests depend on the machine: the Windows test that plants a real executable needs the C#
  compiler that ships with Windows (`csc.exe`), and the test guard that records file access
  resolves directory handles through `/proc/self/fd` on POSIX, so it works on Linux and fails
  closed on a system without it (macOS, which is not in the CI matrix).
- The Claude Code hook in `.claude/` is a development aid, not part of the tool: it blocks pushes,
  tags and filtered gate runs during development, it cannot see shell aliases, variables or an
  encoded PowerShell command, and it is not in force if `sh` cannot start.

## Documentation

- [docs/rules.md](docs/rules.md): what is detected, and how severity and confidence are decided.
- [docs/report-schema.md](docs/report-schema.md): the table and the JSON report.
- [docs/siem-mapping.md](docs/siem-mapping.md): the JSONL events and mini-siem.
- [docs/sarif.md](docs/sarif.md): the SARIF mapping.
- [docs/git-hardening.md](docs/git-hardening.md): exactly how git is run.
- [docs/threat-model.md](docs/threat-model.md): assets, attackers, controls with their tests,
  residual risks, and finding F-1.
- [docs/performance.md](docs/performance.md): measured throughput and memory.
- [SECURITY.md](SECURITY.md): how to report a vulnerability.
- [CONTRIBUTING.md](CONTRIBUTING.md): how to work on the code.
- [CHANGELOG.md](CHANGELOG.md).

## License

MIT. See [LICENSE](LICENSE).
