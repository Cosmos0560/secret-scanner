# PLAN.md - secret-scanner

Design and phase plan for Project 5. Status: **approved v0.2.**
Rules for working on this plan are in CLAUDE.md. No phase starts until the decisions it depends
on are approved.

Product in one paragraph: `secret-scanner scan PATH` reads the files of a directory tree and
reports secrets found by rule detectors (known token formats), a high-entropy detector and a
private-key detector. `secret-scanner scan-git REPO` does the same for every blob in the git
history (all refs or a range), and names the commit that first introduced each secret. Every
finding carries rule id, file, line, column, commit (git only), severity and confidence as separate
fields, a redacted form of the secret and a fingerprint. A baseline file of fingerprints and path
globs suppresses known findings, so CI fails only on new ones. Output: table, JSON, JSONL
(mini-siem compatible) and SARIF 2.1.0, with exit codes for CI. `secret-scanner demo` plants fake
secrets in a temporary directory and a throw-away git repository, scans both, shows the result and
removes everything. Defensive, offline and read-only: no network, no change to anything scanned,
no full secret ever printed.

---

## 0. Open decisions (approve, or change and approve)

Mark each with `[x] approved` or write your change under it.

### D1 - How `scan-git` reads git history
Options considered:
- (a) The installed `git` binary, through one strict wrapper (`gitio/runner.py`): argument lists,
  no shell, a fixed command allowlist, an environment built from scratch (D2).
- (b) A pure-Python reader of `.git` (loose objects, pack files, deltas, pack indexes, refs,
  packed-refs).
- (c) A library: dulwich (pure Python) or pygit2 (libgit2 binding).

**Recommendation: (a).**
**Reason:** a secret scanner's worst failure is a silent miss. Git's object store has many
formats a reader must get exactly right to see every blob: pack v2 with ofs/ref deltas,
multi-pack-index, commit-graph, reftable (default in newer git), SHA-256 repositories, alternates,
promisor/partial clones, shallow grafts. Option (b) would re-implement all of them and every gap
would be an unseen blob, plus a zlib decompression-bomb surface. Option (c) adds a large runtime
dependency (and for pygit2 a C library) to a deliberately small supply chain, and still lags git
on new formats. With (a), git does what it is best at, and the risk moves to "running a program
on a hostile repository", which is a known problem with known controls: git reads repository-local
config, so every config key that can execute a program or reach the network is pinned on the
command line (command-line config wins over repository config), user config is disabled, and only
plumbing commands that never run hooks, filters or pagers are allowed (D2). These controls are
testable: a hostile repository whose config sets every known execution hook to a command that
creates a marker file must leave no marker (Phase 4). The tool needs git only for `scan-git` and
`scan --gitignore`; `scan` works without it.
- [x] approved

### D2 - git command set, environment and history walk
**Recommendation:**
- **Binary.** Resolved once to an absolute path by searching `PATH` explicitly, skipping the
  current directory, any relative `PATH` entry and anything inside the scanned tree (on Windows,
  `CreateProcess` would otherwise run a planted `git.exe` from the current directory). Override:
  `--git PATH` (absolute, validated). Minimum version **2.32** (needed for `GIT_CONFIG_GLOBAL` and
  `--diff-merges=first-parent`), checked from `git version`; older or missing gives exit 3.
- **Environment:** built from scratch, never inherited: `GIT_CONFIG_NOSYSTEM=1`,
  `GIT_CONFIG_GLOBAL=<os.devnull>`, `GIT_TERMINAL_PROMPT=0`, `GIT_PAGER=cat`, `PAGER=cat`,
  `GIT_OPTIONAL_LOCKS=0` (no index refresh or lock files), `GIT_NO_REPLACE_OBJECTS=1`,
  `GIT_NO_LAZY_FETCH=1` (newer gits), `GIT_ATTR_NOSYSTEM=1`, `LC_ALL=C`, plus the minimum the OS
  needs (`PATH` limited to the git directory; on Windows `SYSTEMROOT`). The exact key set is
  fixed in Phase 4 on both OSes and pinned by a test. Nothing else: no `GIT_DIR`, `GIT_TRACE*`,
  `GIT_EXEC_PATH`, `GIT_SSH*`, `GIT_ASKPASS`, `GIT_EXTERNAL_DIFF` from the caller.
- **Pinned config** on every call (`-c`, which wins over repository config): `core.fsmonitor=false`,
  `core.hooksPath=<os.devnull>`, `core.pager=cat`, `core.untrackedCache=false`,
  `credential.helper=` (empty), `protocol.allow=never` (no transport at all, so a partial clone
  cannot lazily fetch), `core.sshCommand=`, `core.gitProxy=`, `log.showSignature=false` (would run
  gpg), `diff.external=`, `gc.auto=0`, `maintenance.auto=false`, `log.showRoot=true`,
  `color.ui=never`, `core.quotePath=true`. Global options: `--no-pager`, `--no-replace-objects`,
  `--literal-pathspecs`, `--git-dir=<absolute git dir>`.
- **Command allowlist** (an enum in the runner; no free-form arguments):
  `version`; `rev-parse --absolute-git-dir` / `--is-shallow-repository` / `--show-object-format`
  (discovery, with `GIT_CEILING_DIRECTORIES` set to the parent of the given path so a repository
  above it is never picked up); `rev-parse --verify --end-of-options <rev>^{commit}` (resolve a
  user revision to an object id); `log` (the history walk below); `cat-file --batch-check` and
  `cat-file --batch` (blob sizes and contents, one long-running process each, no `--filters`, no
  `--textconv`); `ls-files -z --cached --others --exclude-standard` (only for `scan --gitignore`,
  D13).
- **Revisions:** default `--all` (every ref: branches, tags, remotes, stash). `--range A..B` and
  `--rev R` accept only `[A-Za-z0-9][A-Za-z0-9._/-]{0,254}` per side, no `@{`, no `:`, no leading
  `-`; each side is resolved to a full object id with `rev-parse --verify --end-of-options`, and
  only object ids are ever passed to `log`. A path argument is validated by `core/pathrules.py`
  before any git call.
- **History walk:** one streaming call
  `log --raw -z --no-abbrev --no-renames --no-ext-diff --no-textconv --no-color --no-decorate
  --no-show-signature --no-mailmap --diff-merges=first-parent --reverse --topo-order
  --format=<NUL-delimited: commit id, parent ids, committer time> [--all] --end-of-options
  [<resolved object ids>] --` (`--all` is an option, so it comes before `--end-of-options`; after
  it only object ids from `rev-parse` appear), parsed by a strict pure parser (`core/gitparse.py`) that fails closed on anything unexpected.
  For each added or modified blob: skip gitlinks (submodules, counted); look up the size with
  `--batch-check`; skip blobs over `MAX_BLOB_BYTES` (issue); read the rest with `--batch` and scan
  them. Each blob id is scanned once and its matches are cached, so a blob seen again at another
  path or commit costs nothing. A finding's commit is the first commit in the walk that introduced
  that (rule, path, secret), so a secret added once and kept for 500 commits is one finding.
  First-parent diffs of merges still catch a secret introduced only in a merge resolution, because
  only blobs new to the walk are scanned.
- **Bounds:** stdout read in chunks with a total cap per call, stderr capped and sanitised, a
  timeout per short call and the run budget for the streaming calls; on any cap the process is
  killed by its handle (never by name) and the run is incomplete.
- **Repository states:** shallow repository -> incomplete (exit 4) unless `--allow-shallow`
  (then a warning and `history_complete: false`); missing objects (partial clone) -> issue
  `missing_object`, incomplete; "dubious ownership" refusal -> exit 3 with a message, and
  `--allow-other-owner` passes `-c safe.directory=<that exact path>` (command-line config is
  "protected" config, and the pinned settings above already remove the execution vectors the
  ownership check exists for). SHA-1 and SHA-256 repositories are both supported.
- Not read in v1: commit messages, author identities, tag messages, notes contents as messages,
  reflog and unreachable objects (listed under Limitations).
**Reason:** plumbing commands with machine formats (`-z`, length-prefixed `cat-file`) avoid
parsing patch text written by hostile content; every listed knob closes a documented way for a
repository to run code, reach the network or write files.
- [x] approved

### D3 - Regular expressions and catastrophic backtracking
**Recommendation:** stdlib `re`, behind `core/regex_guard.py`, the only importer of `re`. Every
pattern (built-in, user rule, internal) is first parsed by a small own parser for an allowed
grammar and refused if anything falls outside it (fail closed):
- allowed: literals, escapes (an escaped `\.` is a literal dot), character classes, groups
  (non-capturing, plus exactly one named group `secret` for rules), top-level alternation,
  quantifiers `?`, `{n}`, `{m,n}`, word boundary `\b`, fixed-width lookbehind/lookahead of a
  single character class (for "not preceded by an alphanumeric");
- refused: an unescaped `.`, `*`, `+`, `{m,}` (unbounded), nested quantifiers (a quantified group that contains a
  quantifier), alternation inside a quantified group, backreferences, conditionals, inline flags
  other than a leading `(?i)`, `\X`-style escapes Python does not support uniformly;
- limits: pattern at most `MAX_PATTERN_CHARS`; maximum match width (computed by the parser) at
  most `MAX_MATCH_CHARS`; static cost = max width x number of top-level alternatives at most
  `MAX_PATTERN_COST`.
Inputs are bounded too: patterns run per line, and a line is at most `MAX_LINE_BYTES`. A rule's
regex runs only on lines that contain one of its keywords (pre-filter, case-insensitive substring
search), which is also the main performance lever.
Tests: a hostile-pattern table (`(a+)+$`, `(a|a)*`, `(.*a){20}`, `\d+\d+`, `(a)\1`,
`a{1,100000}`, `(?:[a-z]{1,10}){1,10}`, unbounded classes, lookbehind of variable width, a 600-char
pattern, ...) must all be refused with a named reason; the real rules all pass the guard; and one
`slow` tripwire runs every built-in rule over adversarial lines of `MAX_LINE_BYTES` (long runs of
the rule's charset, repeated prefixes, alternating near-misses) with a generous wall-clock
ceiling. The guarantee comes from the grammar; the tripwire only catches regressions and is the
single documented wall-clock assertion.
Rejected: the third-party `regex` module (match timeouts) and `google-re2` (linear time) are good
engines, but each adds a compiled dependency, and the restricted grammar is enough for token
formats.
- [x] approved

### D4 - Rule set v1, rule schema and how each rule is tested
**Rule file:** `src/secret_scanner/rules/builtin.yaml`, loaded with the strict loader (D19),
`version: 1`, at most `MAX_RULES`. Schema per rule (unknown keys refused):
`id` (kebab-case, unique), `name`, `description`, `regex` (with one named group `secret`),
`keywords` (1 to 16 lowercase literals; every true positive contains one, tested), `severity`,
`confidence`, `shown_chars` (how many leading characters of the secret are a fixed public prefix
and may be shown, D7), `min_secret_bits` (estimated from length and charset, must be >= 64,
checked by the loader, see D7), optional `min_entropy` (rejects placeholders like a prefix
followed by repeated `X`), optional `checksum` (enum, offline only), optional `context` (a keyword
that must appear on the same line, for formats that are not unique alone), and a `fake` spec
(prefix parts, charset, length) used by the fake generator (D16).

**Proposed v1 rules** (formats from public vendor documentation as known on 2026-10-12; no live
verification is possible offline, which is a documented limitation):

| id | Format (prose) | Severity | Confidence |
|---|---|---|---|
| `aws-access-key-id` | `AKIA`, `ASIA`, `ABIA` or `ACCA` + 16 base32 characters, word-bounded | high | high |
| `aws-secret-access-key` | 40 base64 characters, only with `aws` and `secret` in the key name on the same line | critical | medium |
| `github-token` | `ghp_`, `gho_`, `ghu_`, `ghs_`, `ghr_` + 36 base62 characters; CRC32 checksum checked offline | critical | high (checksum valid) / low (invalid) |
| `github-fine-grained-pat` | `github_pat_` + 22 + `_` + 59 characters | critical | high |
| `gitlab-pat` | `glpat-` + 20 to 64 characters of `[0-9A-Za-z_-]` | critical | high |
| `slack-token` | `xoxb-`, `xoxp-`, `xoxa-`, `xoxr-`, `xoxs-` + digit and alphanumeric segments | high | high |
| `slack-webhook-url` | `hooks.slack.com/services/` + `T...` / `B...` / 24 alphanumerics | medium | high |
| `stripe-secret-key` | `sk_live_` or `rk_live_` + 24 to 99 alphanumerics | critical | high |
| `google-api-key` | `AIza` + 35 characters of `[0-9A-Za-z_-]` | high | high |
| `npm-token` | `npm_` + 36 alphanumerics | high | high |
| `pypi-token` | `pypi-` + the fixed base64 macaroon header for pypi.org + at least 50 base64url characters (bounded) | critical | high |
| `sendgrid-api-key` | `SG.` + 22 + `.` + 43 base64url characters | high | high |
| `azure-storage-account-key` | `AccountKey=` + 86 base64 characters + `==` | critical | high |
| `private-key` | detector, D6 | critical (encrypted: medium) | high (complete block) / medium (truncated) |
| `entropy-base64`, `entropy-hex` | detector, D5 | medium | medium (with context) / low |

Deliberately not in v1: generic `password = "..."` rules (low-entropy secrets; a hash of them could
be brute-forced, D7), JWTs (often not secret), formats that change often or that I cannot state
precisely without looking them up (OpenAI, Anthropic, Twilio and others). Adding a rule later is
a data change plus its test entry.

**Also recommended:** a small `secret-scanner rules` command that lists id, name, severity,
confidence and description (used by docs and a drift test). It is not in your command list; drop
it if you prefer.

**How each rule is tested** (`tests/test_rules_builtin.py`, table-driven, one entry per rule id):
- a completeness test: the set of rule ids in the YAML equals the set in the test table, and each
  entry has positives and negatives (fails closed when a rule is added without tests);
- positives: a fake from the generator (D16) placed in at least six contexts (bare, single- and
  double-quoted, `KEY=value`, JSON value, YAML value, URL query parameter, end of line with CRLF);
  each must produce exactly one finding with the right rule id, line, column and redacted form;
- negatives: length minus one, length plus one where the format is fixed and word-bounded, one
  character outside the charset, prefix in the wrong case, prefix glued to a preceding word
  character, placeholder bodies (`XXXX...`, `<your-token>`, repeated characters), and the context
  rule without its context keyword;
- pre-filter consistency: every positive contains a declared keyword; with the pre-filter disabled
  the result is identical;
- checksum rules: a fake with a correct checksum (computed at runtime) gives confidence high, one
  with a wrong checksum gives low;
- the guard accepts the rule, and its cost is below the budget.
- [x] approved (including the `secret-scanner rules` command)

### D5 - High-entropy strings
**Recommendation:**
- Candidates: maximal runs of the base64/base64url alphabet (`A-Z a-z 0-9 + / = _ -`) and of hex
  digits, cut at quotes, whitespace and other punctuation; length 20 to `MAX_ENTROPY_TOKEN_CHARS`
  (256) for base64, 32 to 256 for hex.
- Score: Shannon entropy in bits per character over the token's own character frequencies.
- Thresholds: base64 >= **4.5**, hex >= **3.0** (the defaults detect-secrets uses, so they are
  familiar and comparable). A fixed threshold already implies a minimum useful length: a base64
  token shorter than 23 characters cannot reach 4.5 bits per character.
- Context: if the same line has an assignment whose key matches
  `secret|token|passw|api_key|apikey|private|credential|auth` (case-insensitive), the finding gets
  confidence medium; otherwise low. Default reporting shows medium and above (D10), so a bare
  high-entropy string is reported only with `--min-confidence low`. Hex tokens are reported only
  with context, because hashes (git ids, digests) are everywhere.
- Exclusions: a span already matched by a rule (the rule wins); UUIDs; SRI integrity values
  (`sha256-`, `sha384-`, `sha512-` prefixes); tokens with fewer than two character classes
  (upper, lower, digit); path-like tokens (more than two `/`). Default path excludes for this
  detector only: lockfiles (`package-lock.json`, `yarn.lock`, `pnpm-lock.yaml`, `poetry.lock`,
  `uv.lock`, `Cargo.lock`, `go.sum`, `composer.lock`, `Gemfile.lock`), `*.min.js`, `*.min.css`,
  `*.map`, `*.svg`.
- Tunable in config within bounds: base64 threshold 3.5 to 6.0, hex 2.5 to 4.0, minimum length 16
  to 64; the detector can be switched off.
- Phase 6 measures findings per MB at the defaults on a fixed corpus (this repository plus the
  installed packages of the project's `.venv`) and records it in `docs/performance.md`.
**Reason:** simple, explainable and familiar; context-gated confidence keeps the default report
quiet without hiding anything from someone who asks for low confidence. A length-normalised score
(comparing with the expected entropy of a random string of the same length) was considered and
left for later, because it is harder to explain and tune.
- [x] approved

### D6 - Private key blocks
**Recommendation:** a line-based state machine, not a regex over the file:
- a header line `-----BEGIN <type> PRIVATE KEY-----` (types: none, RSA, DSA, EC, OPENSSH,
  ENCRYPTED) or `-----BEGIN PGP PRIVATE KEY BLOCK-----`;
- then up to `MAX_KEY_LINES` lines of base64 body (header fields such as `Proc-Type:` allowed);
- then the matching END line.
A finding needs the header plus at least 64 base64 body characters, so docs and code that only
mention a header do not fire. Complete block -> confidence high; body without END inside the
limits -> medium. ENCRYPTED keys (header type or `Proc-Type: 4,ENCRYPTED`) -> severity medium,
others critical. The escaped one-line form found in JSON (a header, then literal `\n` sequences,
as in cloud service-account files) is recognised on a single line. The "secret" used for
redaction and fingerprinting is the body with everything but base64 characters removed, so the
same key in LF and CRLF files has the same fingerprint. The redacted form shows only the key type
(D7).
- [x] approved

### D7 - Redaction format
**Recommendation:** every output shows only
`<shown>... [<length> chars, sha256:<8 hex>]`, for example (shape only) `AKIA... [20 chars,
sha256:1a2b3c4d]`; private keys: `[RSA private key, 1592 base64 chars, sha256:1a2b3c4d]`.
- `shown` is the rule's fixed public prefix (`shown_chars`, which carries no secret bits); for the
  entropy detector the first 4 characters if the token has at least 32, else nothing. The loader
  refuses `shown_chars` above 12 or above a quarter of the minimum secret length.
- The hash is `sha256(b"secret-scanner/display/v1\x00" + secret)`, first 8 hex digits: enough to
  tell findings apart or to check a known secret locally, not enough to identify one.
- The full secret never reaches a model that can be rendered. Machine formats also carry the
  length and the 8-hex hash as separate fields.
- No source-line snippet in any output in v1: a line can hold a second, undetected secret.
  SARIF viewers show the line from the repository itself.
- Every detector emits only values with at least 64 estimated bits (D4 `min_secret_bits`, D5
  thresholds), so neither the 8-hex display hash nor the fingerprint (D8) can be brute-forced
  back to the secret. This is why low-entropy password rules are out of v1.
- [x] approved

### D8 - Fingerprint
**Recommendation:** `fingerprint = sha256(b"secret-scanner/fingerprint/v1\x00" + rule_id +
b"\x00" + path + b"\x00" + secret)`, first 32 hex digits (128 bits), where `path` is the exact
path relative to the scan root with `/` separators (for `scan-git`, the path inside the
repository), encoded as UTF-8 with `surrogateescape`.
- Line, column and commit are not part of it: moving a secret within a file, or keeping it across
  commits, keeps the fingerprint, so a baseline survives edits and a history scan reports each
  secret once per path.
- The same secret in another file, or found by another rule, is a new fingerprint (a new leak
  location needs a new decision). Two occurrences in one file share a fingerprint and are
  suppressed together.
- Consequence, documented: fingerprints depend on the scan root; run `scan` from the repository
  root (the same root `scan-git` uses) so both agree. Renaming a file changes its fingerprints.
- The prefix `v1` lets a later version change the definition without silently matching old ones.
- [x] approved

### D9 - Baseline (suppression file)
**Recommendation:** a YAML file, written by the tool and edited by people, read only from
`--baseline FILE` (never auto-discovered):
```yaml
version: 1
suppress:
  - fingerprint: "<32 hex>"
    rule: aws-access-key-id        # checked against the fingerprint's finding when present
    path: "config/settings.py"     # informational
    reason: "TODO: review"         # written by the tool; edit it
paths:                             # no findings are reported under these globs
  - "tests/fixtures/**"
```
- `scan ... --write-baseline FILE` writes every current finding (no-clobber unless `--force`,
  atomic). `--baseline FILE` suppresses listed fingerprints and paths.
- Reports always print how many findings were suppressed (by fingerprint, by path) and how many
  suppressions are stale (only when the run was complete). `--show-suppressed` lists them, marked.
- Strict loader (D19): unknown keys, malformed fingerprints, duplicates and more than
  `MAX_BASELINE_ENTRIES` are refused with exit 2, never ignored.
- Path globs use the segment matcher from file-integrity-monitor (`*`, `?`, `[...]`, `**`, no
  regex, linear time), matched against the `/` path relative to the scan root.
- Residual risk (threat model): in CI the baseline usually comes from the branch under test, so a
  pull request can add its own secret's fingerprint. The tool cannot prevent that; the docs
  recommend code-owner review for the baseline file or reading it from the base branch.
- [x] approved

### D10 - Severity, confidence and exit codes
**Recommendation:**
- Severity `info`, `low`, `medium`, `high`, `critical`: how bad a leak of this kind is (from the
  rule). Confidence `low`, `medium`, `high`: how sure the detection is (from the rule, adjusted by
  checksum, context or block completeness). Separate fields everywhere.
- `--min-confidence` (default `medium`) decides what is reported; `--fail-on` (default `low`)
  decides which reported, unsuppressed severities fail the run.
- Exit codes, aligned with file-integrity-monitor: `0` clean and complete; `1` findings at or above
  `--fail-on`; `2` usage, config, rules, baseline or I/O error; `3` git unavailable or failed (not
  installed, too old, not a repository, ownership refused, unexpected git exit); `4` incomplete
  run (any limit, the time budget, missing objects, shallow history). Precedence:
  2 > 3 > 4 > 1 > 0. An incomplete run still prints its findings and `complete: false`.
- [x] approved

### D11 - Output formats (table, JSON, JSONL)
**Recommendation:**
- `--format table|json|jsonl|sarif` (default `table`), `--output FILE` (atomic, no-clobber unless
  `--force`); stdout uses `backslashreplace` so a cp1252 console never crashes.
- Table: severity, confidence, rule, location (`file:line:col`, plus `@<12-hex commit>` for git),
  redacted value; then a summary (scanned, skipped by reason, suppressed, stale, issues, complete).
- JSON: one document, schema `secret-report/1` (documented in `docs/report-schema.md`).
- JSONL for mini-siem, following file-integrity-monitor's `docs/siem-mapping.md` approach (fit
  mini-siem's generic JSON parser without changing mini-siem): one line per finding with
  top-level `timestamp`, `host`, `message`, `event_type: "secret.finding"`, and an object
  `secret` with `rule_id`, `detector`, `severity`, `confidence`, `file`, `file_sha256`,
  `file_truncated`, `line`, `column`, `commit`, `commit_time`, `redacted`, `secret_length`,
  `secret_hash8`, `fingerprint`, `target` (`fs`|`git`), `tool_version`, `schema:
  "secret-event/1"`; plus one final line `event_type: "secret.scan_summary"` with counts and
  `complete`, so a SIEM can see incomplete runs. Never a top-level `path` (mini-siem treats it as
  `url_path`); values at most 1 024 characters, `file` cut at 1 000 with `file_truncated` and the
  full path's hash; ASCII only; well under mini-siem's attribute and line limits. Phase 5 re-reads
  mini-siem's parser (read-only) and pastes a real ingest into `docs/siem-mapping.md`.
- No CSV in v1 (not in the requested formats; it would need formula neutralising). Easy to add
  later with the sanitiser's CSV helper from file-integrity-monitor.
- [x] approved

### D12 - SARIF 2.1.0 mapping
**Recommendation:**
- One run; `version: "2.1.0"`; `$schema` set to the SARIF 2.1.0 schema URI;
  `tool.driver` with `name`, `semanticVersion`, `informationUri` (the GitHub repository page) and
  a `rules` array with one `reportingDescriptor` per rule: `id`, `name`, `shortDescription`,
  `fullDescription`, `defaultConfiguration.level`, `properties.tags: ["security", "secret"]`,
  `properties.precision` (from default confidence) and `properties.security-severity`.
- Level: `critical`, `high` -> `error`; `medium` -> `warning`; `low`, `info` -> `note`.
  `security-severity` (the number GitHub code scanning uses for its severity buckets): critical
  `9.5`, high `8.0`, medium `5.5`, low `2.0`, info omitted.
- Result: `ruleId`, `ruleIndex`, `level`, `message.text` (sanitised; rule name plus redacted value,
  plus "in commit <id>" for git), one location with `artifactLocation.uri` (the relative path,
  percent-encoded per segment, so hostile names cannot inject URI syntax) and `uriBaseId:
  "%SRCROOT%"`, `region` with `startLine`, `startColumn`, `endColumn`;
  `partialFingerprints: {"secretScanner/v1": <fingerprint>}`; `properties` with `confidence`,
  `severity`, `redacted`, `commit`.
- `run.columnKind: "unicodeCodePoints"` (D15). `invocations[0].executionSuccessful` = complete,
  scan issues as `toolExecutionNotifications`.
- Suppressed findings are omitted unless `--show-suppressed`, then included with
  `suppressions: [{kind: "external", justification: <reason>}]`.
- Recommended for `scan` of the checked-out tree in CI. For `scan-git`, results point at paths that
  may no longer exist; allowed, documented.
- Verification: tests check the emitted structure field by field against the subset we use; there
  is no schema validator dependency and no GitHub access here, so a real upload to GitHub code
  scanning is your step at release and stays a listed gap until done.
- [x] approved

### D13 - `.gitignore` handling and default excludes
**Recommendation:**
- `scan` scans everything under PATH by default, except default excluded directories: `.git`,
  `.hg`, `.svn`, `node_modules`, `.venv`, `venv`, `__pycache__`, `.tox`, `.nox`, `.mypy_cache`,
  `.ruff_cache`, `.pytest_cache` (vendored third-party trees are noise; `--no-default-excludes`
  turns them off). Hidden files such as `.env` are scanned.
- `--gitignore`: ask git for its own answer (`ls-files -z --cached --others --exclude-standard`
  through the runner, D2) and scan only the files on that list. The tool's own walker still does
  the walking, file-type checks and limits; git's list is only a filter. If PATH is not inside a
  git work tree, exit 2 with a clear message.
- Not done: re-implementing gitignore semantics in Python (negation, anchoring, directory-only
  patterns, nested files, `info/exclude`, `core.excludesFile`); every mismatch would be a silent
  miss or noise.
- Config `exclude` globs and baseline `paths` are applied on top (config excludes skip reading;
  baseline paths only suppress reporting).
- [x] approved

### D14 - Binary files
**Recommendation:** a file or blob is binary if its first 8 000 bytes contain a NUL byte (git's
own rule) and it does not start with a UTF-16 or UTF-32 byte-order mark (D15). Binary content is
not scanned and is counted as `skipped_binary` in the summary; this is not an issue and does not
make the run incomplete. No extension list (the NUL check is cheap and does not trust names).
Archives, office files, keystores and other binary formats are a documented limitation.
- [x] approved

### D15 - Encodings, lines and columns
**Recommendation:**
- Detection runs on bytes. Every v1 detector looks for ASCII tokens, so bytes-level scanning covers
  UTF-8, Latin-1, cp1252 and every other ASCII-compatible encoding without decoding and without
  decode errors.
- UTF-8 BOM is skipped. UTF-16/32 with a BOM is transcoded to UTF-8 first (strict; a failure is an
  `undecodable` issue). UTF-16 without a BOM looks binary (NUL bytes) and is skipped: documented.
- Lines split on `\n`; a trailing `\r` is removed. A line longer than `MAX_LINE_BYTES` is scanned
  up to the limit, the rest is skipped, and the file gets a `line_too_long` issue (incomplete).
- Line numbers are 1-based. Columns are 1-based Unicode code points, counted by decoding the line
  prefix as UTF-8 with `errors="replace"` (each invalid byte counts as one). The same convention
  goes into SARIF `columnKind`.
- Paths: POSIX names that are not valid UTF-8 are kept with `surrogateescape` (exact for
  fingerprints, escaped by the sanitiser for display); git paths come from `-z` output as bytes and
  follow the same rule.
- [x] approved

### D16 - Fake secrets for tests and the demo, and repository hygiene
**Recommendation:** fakes exist only at runtime, are built from fragments, and are checked for.
1. **Generator** (`core/fakes.py`, pure, used by tests and the demo): `fake(rule_id, seed)` reads
   the rule's `fake` spec (prefix parts, charset, length, optional checksum) and builds the value:
   the prefix is stored as separate parts and joined at runtime, the body is derived
   deterministically from `sha256(seed)` mapped onto the charset (no `random` module), and, where
   the charset allows, the body contains the marker `FAKE` (or `fake`, or hex `fa4e`) so a person
   reading a log sees what it is. Checksum rules get a correct checksum computed at runtime (and a
   deliberately wrong one for the negative case). Private-key fakes are random base64 bodies
   between header and footer lines that are themselves joined from parts; they are not keys.
   Entropy fakes are base64 of `sha256(seed)` outputs.
2. **Where they go:** only into `tmp_path` (tests) or the demo's own temporary directory. No full
   fake is ever written into a tracked file, a golden file, a snapshot, a doc or a commit message;
   docs show tool output, which is redacted by construction.
3. **Why fragments and not just "obviously fake" literals:** GitHub push protection and other
   scanners match formats and validate checksums; a literal in the repository would block a push or
   raise an alert whether or not it is fake. A value that never exists in any file cannot.
4. **Hygiene test** (`tests/test_hygiene_secrets.py`): runs the tool's own engine with every
   built-in high-confidence rule and the private-key detector over every tracked and
   untracked-not-ignored file (`git ls-files -co --exclude-standard`), with no allowlist. Any
   finding fails the test and is shown redacted. A positive control plants a generated fake in a
   temporary repository and proves the same check catches it. In Phase 1, before the engine
   exists, the test uses a minimal hard-coded set of format checks (AWS key id, GitHub token,
   private key block, Slack token, Stripe key); Phase 2 switches it to the engine and checks that
   the engine covers every case of the minimal set.
5. **History:** a `slow` test (Phase 4) runs `scan-git` over this repository's own history, so a
   fake that was committed and later removed is still caught before you push; CI checks out with
   `fetch-depth: 0` for it.
6. **Assertions:** tests compare outputs with fakes through `assert_not_leaked(text, secret)`,
   which fails with the redacted form, so pytest never prints a full fake into a CI log.
- [x] approved

### D17 - Git identity in throw-away repositories (touches a machine rule)
The demo and the git tests must create commits in temporary repositories, and git refuses to
commit without a name and an email.
**Recommendation:** pass `GIT_AUTHOR_NAME`, `GIT_AUTHOR_EMAIL`, `GIT_COMMITTER_NAME`,
`GIT_COMMITTER_EMAIL` and fixed dates only in the subprocess environment of commands that run
inside the temporary repository (`gitio/demo_git.py` for the demo, `tests/gitrepo.py` for tests).
The address-like value is built at runtime from fragments (`"demo"`, `"example.invalid"`), so no
file contains an email address. Nothing is written to any git config file, global or local, and
this repository's identity is never touched. Repositories are created with `--template=` (no
sample hooks), commits use `--no-verify` and the pinned config of D2. CLAUDE.md section 1 states
this exception explicitly.
- [x] approved

### D18 - Limits (initial values; `core/limits.py`)
| Constant | Default | Hard ceiling |
|---|---|---|
| `MAX_FILES` (entries incl. directories) | 200 000 | 1 000 000 |
| `MAX_DEPTH` | 64 | 128 |
| `MAX_PATH_CHARS` | 4 096 | 4 096 |
| `MAX_FILE_BYTES` (and `MAX_BLOB_BYTES`) | 8 MiB | 64 MiB |
| `MAX_LINE_BYTES` | 256 KiB | 4 MiB |
| `MAX_TOTAL_BYTES` | 4 GiB | 16 GiB |
| `MAX_RUN_SECONDS` | 600 | 3 600 |
| `MAX_GIT_COMMITS` | 200 000 | 1 000 000 |
| `MAX_GIT_BLOBS` (distinct) | 1 000 000 | 2 000 000 |
| `MAX_GIT_OUTPUT_BYTES` (per call) | 1 GiB | 4 GiB |
| `MAX_GIT_STDERR_BYTES` | 64 KiB | 64 KiB |
| `GIT_CALL_TIMEOUT_SECONDS` (short calls) | 30 | 120 |
| `MAX_FINDINGS` (reported) | 10 000 | 10 000 |
| `MAX_FINDINGS_PER_FILE` | 200 | 1 000 |
| `MAX_RULES` / `MAX_KEYWORDS_PER_RULE` | 256 / 16 | same |
| `MAX_PATTERN_CHARS` / `MAX_MATCH_CHARS` / `MAX_PATTERN_COST` | 512 / 1 024 / 8 192 | same |
| `MAX_ENTROPY_TOKEN_CHARS` | 256 | 256 |
| `MAX_KEY_LINES` | 200 | 200 |
| `MAX_CONFIG_BYTES` / `MAX_RULES_FILE_BYTES` | 256 KiB / 256 KiB | same |
| `MAX_BASELINE_BYTES` / `MAX_BASELINE_ENTRIES` | 16 MiB / 100 000 | same |
| `MAX_GLOBS` / `MAX_GLOB_CHARS` | 256 / 512 | same |

Config may lower values, never exceed a ceiling. Every limit hit is a recorded issue and makes the
run incomplete (exit 4); findings found so far are still reported. Phase 6 measures throughput and
memory at these sizes; a default changes only with a measured reason. Drift tests keep README and
docs in sync with this file.
- [x] approved

### D19 - Configuration, user rules and YAML loading
**Recommendation:**
- One optional `--config FILE` (YAML), never auto-discovered: `version: 1`, `exclude` (globs),
  `min_confidence`, `fail_on`, `entropy` (`enabled`, thresholds, minimum length, within D5
  bounds), `disable_rules` (ids, must exist), `extra_rules` (same schema as built-in rules, ids
  must start with `custom-`, same guard and limits), `limits` (lower only). CLI flags override
  config values.
- All YAML (built-in rules, config, baseline) goes through one loader in `services/loader.py`: a
  `SafeLoader` subclass that also refuses duplicate keys, anchors and aliases (no alias-expansion
  bombs) and custom tags; a size cap before parsing; a strict schema after (unknown keys, wrong
  types and YAML 1.1 surprises such as unquoted `yes` or `0755` where a string is expected are
  refused).
- The built-in rules file is read with `importlib.resources` (package data), parsed by the same
  loader, and its SHA-256 is reported in JSON and SARIF output as the rules version.
- [x] approved

### D20 - Project identity, dependencies and tooling
**Recommendation:** distribution `secret-scanner`, import package `secret_scanner`, console script
`secret-scanner`, also `python -m secret_scanner`; `src/` layout; hatchling; MIT; `authors` with
name only. Runtime dependency: **PyYAML only**. Dev: pytest, pytest-cov, ruff, mypy, types-PyYAML.
Release only: build, pip-audit, bandit. `.venv` created with Python 3.13 explicitly. CI actions:
`actions/checkout@v5` (with `fetch-depth: 0` and `persist-credentials: false`) and
`actions/setup-python@v6`, as you specified; they cannot be checked from here (no GitHub access),
so CI is verified only after you push. Not published to PyPI; releases are your GitHub tags.
**Optional (b):** the Phase 1 PreToolUse hook also blocks `git push`, `git tag`, `git add -A`,
`git add .`, `git add --all`, `git config user.*` and commit messages containing a
`Co-Authored-By` trailer, so the machine rules are enforced by the tool, not only by memory.
Recommended; it costs one more test table.
- [x] approved
- [x] optional (b) approved

---

## 1. Architecture

### 1.1 Layers and modules
```
src/secret_scanner/
  __init__.py, __main__.py
  rules/builtin.yaml            built-in rules (package data, D4)
  core/                         L0 pure, no I/O
    limits.py                   all bounds (D18), validated overrides
    models.py                   enums and frozen dataclasses (section 2)
    errors.py                   error hierarchy, exit codes, precedence (D10)
    sanitize.py                 escaping for display (control, bidi, zero-width, ANSI, surrogates)
    pathrules.py                user path validation (UNC, device, URL-like, drive-relative, ..)
    redact.py                   Redacted from a secret (D7)
    fingerprint.py              fingerprint (D8)
    regex_guard.py              only importer of re; grammar parser, width and cost (D3)
    rules.py                    rule schema validation from parsed data (D4)
    lines.py                    binary check, BOM/transcoding, line split, columns (D14, D15)
    detect/
      match.py                  Match (holds the secret; import-restricted)
      prefilter.py              keyword pre-filter
      rule_detector.py          regex rules, checksums (CRC32/base62 for GitHub)
      entropy.py                candidates, Shannon entropy, context, exclusions (D5)
      private_key.py            block state machine (D6)
      engine.py                 runs detectors per line/buffer, overlap resolution
    findings.py                 Match + location -> Finding (redact + fingerprint)
    globs.py                    segment-wise glob matcher, no regex
    suppress.py                 baseline matching, stale counting (D9)
    gitparse.py                 strict parsers for `log --raw -z` and cat-file headers
    fakes.py                    fake secret generator (D16)
    clock.py                    Clock protocol
  fs/                           L1
    walk.py                     ONLY reader of scanned files (read-only, no-follow)
    safe_files.py               ONLY I/O for own files: config, rules, baseline read; atomic writes
    sandbox.py                  ONLY mutator: the demo's temporary tree
  gitio/                        L1
    runner.py                   ONLY git runner for scanning (D2)
    demo_git.py                 builds the demo repository inside a sandbox (D17)
  host/                         L1
    clock.py                    SystemClock (only place with time.*)
    hostinfo.py                 host label default (platform.node, sanitised)
  render/                       L1 pure renderers
    table.py, json_out.py, jsonl.py, sarif.py
  services/                     L2
    loader.py                   strict YAML loader (only yaml/importlib.resources importer)
    config.py                   config + rules + baseline schemas -> models (D9, D19)
    fs_scanner.py               walk + engine -> ScanResult
    git_scanner.py              runner + gitparse + engine -> ScanResult
  app/                          L3
    scan.py, scan_git.py, demo.py
  cli/                          L4
    main.py                     argparse, exit codes, stdout wiring, top-level error handler
scripts/
  gate.py, check_architecture.py, bench.py, hooks/guard_gate.py
```

### 1.2 Data flow
`cli` -> `app.scan`: load config/rules/baseline (services.loader via fs.safe_files) -> walk
(fs.walk, optional git filter from gitio.runner) -> per file: lines.classify -> detect.engine ->
findings (redact + fingerprint; the Match is dropped here) -> suppress -> `Report` -> renderer ->
stdout or atomic file write. Exit code from the report.

`cli` -> `app.scan_git`: validate repo path -> runner discovery (git dir, shallow, object format)
-> resolve revisions -> stream `log --raw -z` -> gitparse -> new blob ids -> `--batch-check` sizes
-> `--batch` contents -> same engine and findings path, with commit attribution and blob cache ->
`Report`.

### 1.3 Reading a scanned file (`fs/walk.py`)
1. Iterative walk with sorted entries, depth guard, default and config excludes applied to
   directories before descending.
2. `lstat`: symlinks recorded as `skipped_symlink` and never followed; on Windows reparse points
   (junctions, mount points, symlinks) are not traversed, and cloud placeholders
   (`FILE_ATTRIBUTE_OFFLINE`, `RECALL_ON_DATA_ACCESS`, `RECALL_ON_OPEN`) are `skipped_offline`.
   FIFOs, sockets and devices are recorded by type and never opened.
3. Open read-only: POSIX `O_RDONLY | O_NOFOLLOW | O_NONBLOCK | O_CLOEXEC` (`O_NOATIME` best
   effort); Windows `O_RDONLY | O_BINARY`.
4. `fstat` the descriptor and compare identity and type with step 2; a mismatch is `unstable`.
5. Read at most `MAX_FILE_BYTES + 1`; a larger file is `too_large` (issue, incomplete), never
   partially scanned and called clean.
6. `FileNotFoundError` -> `vanished`; `PermissionError` -> `unreadable`; other `OSError` -> issue
   with the errno name only.

### 1.4 Writing own files (`fs/safe_files.py`)
Output reports and baselines: temporary file in the target directory, write, fsync, rename; no
overwrite of an existing path without `--force`; refuse a target that is a symlink or reparse
point; user paths validated by `core/pathrules.py` first. Nothing is ever written into a scanned
tree except where the user names the output path explicitly.

### 1.5 Commands
```
secret-scanner scan PATH [--format table|json|jsonl|sarif] [--output FILE] [--force]
                         [--config FILE] [--baseline FILE] [--write-baseline FILE]
                         [--show-suppressed] [--min-confidence LEVEL] [--fail-on SEVERITY]
                         [--gitignore] [--no-default-excludes] [--host-label TEXT]
secret-scanner scan-git REPO [--range A..B | --rev REV] [--allow-shallow]
                         [--allow-other-owner] [--git PATH] + the output/baseline options above
secret-scanner demo
secret-scanner rules                      (if approved in D4)
secret-scanner --version
```
`--write-baseline` exists on `scan` and `scan-git`; a baseline written by one works for the other
when both use the repository root (D8).

---

## 2. Data model (frozen dataclasses, slots)

| Type | Fields |
|---|---|
| `Severity` | `info`, `low`, `medium`, `high`, `critical` |
| `Confidence` | `low`, `medium`, `high` |
| `Detector` | `rule`, `entropy`, `private_key` |
| `Rule` | `id`, `name`, `description`, `detector`, `pattern` (guarded), `keywords`, `severity`, `confidence`, `shown_chars`, `min_secret_bits`, `min_entropy`, `checksum`, `context`, `fake` |
| `Match` (internal, import-restricted) | `rule_id`, `line`, `col_start`, `col_end`, `secret` (bytes), `confidence`, `kind_label` (key type for private keys) |
| `Redacted` | `shown`, `length`, `hash8`, `text` |
| `Location` | `path_key` (exact, for fingerprints), `path` (escaped, for display), `line`, `column`, `end_column`, `commit` or None, `commit_time` or None |
| `Finding` | `rule_id`, `detector`, `severity`, `confidence`, `location`, `redacted`, `fingerprint`, `suppressed_by` (None, `fingerprint`, `path`) |
| `IssueKind` | `unreadable`, `vanished`, `unstable`, `too_large`, `line_too_long`, `undecodable`, `limit_reached`, `time_budget`, `missing_object`, `shallow_history`, `findings_cap` |
| `ScanIssue` | `kind`, `path` (escaped) or None, `detail` (no content) |
| `ScanStats` | files seen/scanned, bytes scanned, skipped by reason (`binary`, `symlink`, `offline`, `special`, `excluded`, `gitignored`, `submodule`), commits, blobs scanned, blobs from cache |
| `Suppressions` | fingerprint entries (fingerprint, rule, path, reason), path globs |
| `Report` | `target` (`fs`/`git`), `target_display`, `findings`, `suppressed` counts, `stale` count, `issues`, `stats`, `complete`, `truncated`, `rules_sha256`, `generated_at`, `tool_version`, `history_complete` (git) |

`Finding` has no field that can hold a secret; a test walks the type annotations of every model
reachable from `Report` and fails on `bytes` or on a field named like `secret`/`value`.

---

## 3. Threat model summary

Assets: the secrets found (they must not leak further through the tool); the integrity of the
host running the tool; the correctness of reports (no silent misses reported as clean). Full
version goes to `docs/threat-model.md` in Phase 6.

| Threat | Control | Residual / out of scope | Evidence (test) |
|---|---|---|---|
| The tool leaks a found secret into terminal, CI log, report or SARIF upload | `Match` never leaves the detection layer; only `Redacted` + fingerprint are rendered; no snippets (D7) | shown prefix (public part or 4 chars of 32+) and an 8-hex hash are visible; path and line reveal where a secret is | cross-format leak test over all formats, both targets, all error paths, the demo |
| Secret leaks through an exception or traceback | exceptions carry no content; top-level handler prints sanitised type and message | - | error-path tests with planted fakes |
| A hostile repository runs code through git (fsmonitor, hooks, pager, textconv, external diff, gpg, credential helper, ssh command, filters) | pinned `-c` config, plumbing-only allowlist, env from scratch, no shell (D2) (CWE-78, CWE-829) | an unknown future git config key that executes; git itself having a bug | hostile-config repo with marker commands for every vector; no marker created |
| Argument injection through revision or path (`--output=...`, `-c...`) | strict revision grammar, `--end-of-options`, resolution to object ids, path validation (CWE-88) | - | injection table tests |
| Planted `git.exe` in the scanned or current directory | absolute binary resolution skipping cwd, relative PATH entries and the scanned tree (CWE-427) | a malicious git earlier on the user's own PATH | Windows test with a planted binary |
| Network access by the tool or by git (lazy fetch in partial clones) | static network ban, socket blocked in tests, `protocol.allow=never`, `GIT_NO_LAZY_FETCH` | - | architecture tests; partial-clone test (no fetch, `missing_object`, exit 4) |
| The tool changes the scanned repository (index lock, gc, maintenance) | read-only command set, `GIT_OPTIONAL_LOCKS=0`, `gc.auto=0`, no index-writing commands | atime updates on read | before/after snapshot of the whole repository incl. `.git` |
| History lies (replace refs, grafts, shallow clone) | `--no-replace-objects`, shallow = incomplete unless allowed | an attacker who rewrote history before the scan | replace-ref and shallow tests |
| ReDoS through user rules or hostile content | guarded grammar, bounded width and cost, line limit, run budget (CWE-1333) | - | hostile-pattern table, tripwire |
| Resource exhaustion (huge trees, files, lines, histories, blobs, outputs, YAML bombs) | limits, sizes checked before reading (`--batch-check`), alias refusal, time budget, incomplete exit (CWE-400) | - | limit tests per constant |
| Terminal, log or report injection through hostile names and content | single sanitiser, ASCII-only JSON, SARIF URI percent-encoding (CWE-150, CWE-117) | confusable glyphs | sanitiser sweep, hostile-name rendering tests per format |
| Symlink or junction escape, loops, FIFO hangs, cloud placeholder downloads | no-follow, regular files only, `O_NONBLOCK`, placeholders skipped (CWE-59) | parent directory swapped during the walk | special-file tests |
| File swapped while being read | lstat/fstat identity check, `unstable` (CWE-367) | changes between scan and report | TOCTOU tests via a reader hook |
| Unsafe YAML in config, rules or baseline | SafeLoader subclass, no aliases/tags/duplicates, size caps, strict schema (CWE-502) | - | loader negative table, architecture ban on `yaml.load` |
| A pull request suppresses its own secret through the baseline or config | explicit paths only, no auto-discovery, suppressed counts always printed | baseline from the tested branch can be edited by its author: review it | suppression reporting tests; documented |
| Output file attacks (symlinked `--output`, clobbering) | atomic no-follow no-clobber writes (CWE-59) | - | safe_files tests |
| Brute-forcing a secret from its display hash or fingerprint | only >= 64-bit secrets are detected; domain-separated hashes (D7, D8) | none for v1 detectors | loader test on `min_secret_bits` |
| Test fixtures or docs contain real-looking secrets (push protection, public alerts) | runtime fakes from fragments, hygiene test with no allowlist, history self-scan (D16) | - | hygiene tests, positive control |
| Missed secrets reported as clean | limits and skips make runs incomplete or are counted; Limitations section | split, encoded or encrypted secrets; binary formats; UTF-16 without BOM; commit messages; unreachable objects | documented, not a control |

CWE ids describe the tool's own controls only, and each is re-checked against the CWE list when
the docs are written.

---

## 4. Phases

Six phases, one per session (CLAUDE.md). Each ends with the full gate green on Windows and on Linux
through WSL, a commit made via the gate, and the 5-line report in `docs/phase-reports.md`.
Spend review effort on `regex_guard.py`, `redact.py`, `walk.py`, `runner.py`, `gitparse.py`,
`sanitize.py` and `sarif.py`.

### Phase 1 - Foundation, gate, hook, CI, pure core (size: M)
Depends on: D7, D8, D10, D16, D18, D20 (and D17 for the hygiene positive control).
**Scope:** `git init -b main`; `.venv` (Python 3.13); `pyproject.toml` (hatchling, PyYAML, dev
extras, ruff, mypy strict for 3.11 on linux and win32, pytest markers, branch coverage with
`fail_under = 85`); `.gitignore` (venv, caches, build output, `*.key`, `*.pem`, `.env*`);
`.gitattributes` (`eol=lf`); LICENSE; README and SECURITY.md stubs without claims; CLI with
`--version` only; `scripts/gate.py` (six steps, summary, `--full`, `--log`);
`scripts/check_architecture.py` (layers, cycles, filesystem/subprocess/network default-deny, `re`
and `yaml` restrictions, `Match` import restriction, banned APIs, fails closed);
`scripts/hooks/guard_gate.py` and `.claude/settings.json` (PreToolUse, matcher `Bash|PowerShell`;
plus D20 option b if approved); `.github/workflows/ci.yml`; `core/limits.py`, `core/errors.py`,
`core/models.py`, `core/sanitize.py`, `core/pathrules.py`, `core/redact.py`,
`core/fingerprint.py`, `core/clock.py`; `tests/conftest.py` (environment isolation, socket
blocker, `assert_not_leaked`); `docs/phase-reports.md`.
**CI:** push to main and pull requests; `permissions: contents: read`; `concurrency` with
`cancel-in-progress: true`; matrix `ubuntu-24.04`, `windows-latest` x 3.11, 3.12, 3.13,
`fail-fast: false`, `timeout-minutes: 15`; `actions/checkout@v5` with `fetch-depth: 0` and
`persist-credentials: false`, `actions/setup-python@v6`; install `.[dev]`; run
`python scripts/gate.py --full`. Until you push, the report says "CI not yet run".
**Tests:** architecture checker (every rule id has planted violations and allowed
counterexamples; the real tree passes; a planted cycle is found; a syntax error fails closed);
hook (allowed and blocked commands in Bash and PowerShell syntax, quoted text treated as data,
malformed hook input is a non-blocking error); hygiene (characters, secret files, emails, the
minimal fake-secret check with a positive control in a temporary repository); CI policy (parses
the workflow, checks permissions, matrix, concurrency, action versions, fetch depth, credentials);
sanitiser (escape table, round trip, exhaustive sweep as `slow`); pathrules (both OS flavours);
redact (format, shown-character rules, never more than allowed); fingerprint (golden vectors,
domain separation, platform independence); limits and exit-code drift skeletons; precedence table.
**Definition of done:** gate green on Windows and WSL Linux with mypy for both platforms; the
checker catches every planted violation; the hook blocks every planted bad command; first commit
via the gate; phase report written.

### Phase 2 - Detection engine (size: L)
Depends on: D3, D4, D5, D6, D14, D15, D16, D19.
**Scope:** `core/regex_guard.py`; `core/rules.py`; `services/loader.py` (strict YAML, package
data); `rules/builtin.yaml` with all v1 rules and fake specs; `core/lines.py`; `core/detect/*`
(pre-filter, rule detector with GitHub checksum, entropy, private key, engine with overlap
resolution); `core/findings.py`; `core/fakes.py`; hygiene secret test switched to the engine.
No new CLI command yet beyond an internal test entry point.
**Tests:** per-rule table (D4) with the completeness test; hostile-pattern table and guard unit
tests (grammar coverage, width and cost); `slow` tripwire; entropy (known values, thresholds per
alphabet, context, every exclusion, bounds of config values); private key (every header type,
encrypted, CRLF, truncated, header-only negative, JSON escaped form, `MAX_KEY_LINES`); lines
(UTF-8, BOM, Latin-1, UTF-16 LE/BE with BOM, invalid UTF-8, NUL binary, over-long line, columns
with multibyte prefixes); loader negatives (duplicate keys, aliases, tags, unknown keys, oversize,
YAML 1.1 surprises); `min_secret_bits` and `shown_chars` validation; type-walk test that no
renderable model can hold a secret.
**Definition of done:** the engine finds every generated fake in a mixed corpus and nothing in the
negative corpus; every rule has its test entry; gate green on both OSes; report written.

### Phase 3 - Directory scan, suppression, `scan` with table and JSON (size: L)
Depends on: D9, D10, D11 (table, JSON), D13 (default excludes), D18, D19.
**Scope:** `fs/walk.py`; `fs/safe_files.py`; `core/globs.py`; `core/suppress.py`;
`services/config.py`; `services/fs_scanner.py`; `app/scan.py`; `render/table.py`;
`render/json_out.py`; `host/clock.py`, `host/hostinfo.py`; CLI `scan` with all options except
`--gitignore` (Phase 4); `--write-baseline` is in scope (v0.7); `docs/report-schema.md`.
**Tests:** walker on temporary trees (regular, empty, hidden, nested, default excludes, config
excludes, symlinks to files and directories and dangling ones, junctions on Windows, FIFO on POSIX,
unreadable on POSIX unless root, vanished and swapped during read via a reader hook, every limit
and the time budget with a fake clock); read-only snapshot test; path guard fixture; baseline round
trip (`--write-baseline`, then `--baseline` gives exit 0), stale counting, malformed baseline
refused with exit 2, no-clobber and `--force`; hostile names (bidi, ANSI, newline, invalid bytes on
POSIX) escaped in table and JSON; cp1252 stdout; leak test for table and JSON and every error path;
exit-code table; config bounds.
**Definition of done:** `scan` over a generated temporary tree prints correct table and JSON with
the right exit codes; gate green on both OSes; report written.

### Phase 4 - Git history scan (size: L)
Depends on: D1, D2, D13 (`--gitignore`), D17.
**Scope:** `gitio/runner.py`; `core/gitparse.py`; `services/git_scanner.py`; `app/scan_git.py`;
CLI `scan-git` and `scan --gitignore`; `tests/gitrepo.py`; slow self-history scan.
**Tests:** exact environment and pinned config (asserted key by key); command allowlist (no
free-form arguments possible); revision grammar and injection table (`--output=x`, `-c x`,
`@{-1}`, `a:b`, leading dash, over-long); binary resolution (relative PATH entries and cwd skipped;
planted `git.exe` ignored on Windows); hostile repository config with a marker command for every
execution vector in D2 -> no marker; read-only snapshot of repository and `.git`; partial clone
from a local path (no fetch, `missing_object`, exit 4); shallow clone (exit 4, `--allow-shallow`);
replace refs ignored; SHA-256 repository (if the local git supports it, else `requires_git_sha256`
skip with reason); history cases: secret added and deleted later, secret only in a merge
resolution, root commit, rename (new fingerprint), same blob at two paths, binary blob, oversized
blob skipped through `--batch-check`, submodule gitlink skipped; blob cache hit counts;
`gitparse` negatives (truncated records, bad modes, bad ids, unexpected statuses) fail closed;
runner bounds with a fake process (timeout, stdout cap, stderr cap, non-zero exit) -> exit 3 or 4
as specified; git missing or too old -> exit 3; dubious ownership message (POSIX, where a
different owner can be simulated; otherwise covered by parsing the real message text).
**Definition of done:** `scan-git` reports a secret that was added and removed in the history of a
temporary repository, with its commit; every execution-vector test passes on both OSes; gate green
on both; report written.

### Phase 5 - JSONL, SARIF, demo, cross-format leak proof (size: M)
Depends on: D11, D12, D17.
**Scope:** `render/jsonl.py`; `render/sarif.py`; `fs/sandbox.py`; `gitio/demo_git.py`;
`app/demo.py`; CLI `demo` and CLI `rules` (D4, assigned here by v0.7; lists id, name, severity,
confidence and description; a drift test compares it with the rules file);
`docs/siem-mapping.md` (mini-siem parser re-read read-only; a real
ingest of demo JSONL with mini-siem's own existing environment, data directory in a temporary
folder, mini-siem's tree left unchanged); `docs/sarif.md`.
**Demo:** creates a temporary directory through the sandbox; writes a few files with generated
fakes (one in an `.env`, one in a settings file, one private key block, one suppressed via a
baseline it writes); builds a throw-away repository where one fake is committed and then removed;
runs `scan` and `scan-git`, prints both tables (redacted) and a short explanation; removes
everything in a `finally` (also on Ctrl-C); exit 0 when the demo ran as designed. Without git it
runs the directory part and exits 3 with a message saying the history part was skipped.
**Tests:** JSONL fields and limits against the mini-siem rules recorded in the doc; summary line;
SARIF structure field by field, level and security-severity table, URI percent-encoding of hostile
names, `columnKind`, suppressions with `--show-suppressed`, notifications for issues; the
cross-format leak test (4 formats x `scan`/`scan-git` x suppressed shown/hidden x every error
path x demo output) for every rule's fake; demo cleanup on failure and on interrupt; demo makes no
network call and writes nothing outside its temporary directory.
**Definition of done:** a real mini-siem ingest is pasted in the doc; SARIF passes the structural
tests (upload to GitHub code scanning is your step); gate green on both OSes; report written.

### Phase 6 - Hardening, measurement, docs, release (size: M)
Depends on: everything above.
**Scope:** `scripts/bench.py` (generated trees of 1k/10k/100k files, a long synthetic history, the
entropy corpus of D5; wall time, MB/s, commits/s, peak memory via `tracemalloc`) ->
`docs/performance.md` with machine details; re-check D18 against measurements;
`docs/threat-model.md`; `docs/rules.md` (generated rule table with a drift test); README (install,
quick start, real pasted `demo` and `scan` output, CI usage with SARIF upload and baseline,
claim-to-evidence table, "What the tool reads and writes", Limitations, mini-siem link); CHANGELOG
`1.0.0`; SECURITY.md; release checks per CLAUDE.md section 11; final review of the security-critical
modules, fixes test-first.
**Limitations section must include at least:** no verification of whether a secret is live; rule
formats taken from public knowledge without live checks; misses for split, encoded, encrypted or
obfuscated secrets, binary formats and archives, UTF-16 without BOM, files over the size limit,
commit messages and tag messages, reflog and unreachable objects, submodule contents, LFS objects;
entropy false positives and negatives; shown prefix and 8-hex hash visible; fingerprints depend on
scan root and path; a baseline from the tested branch can suppress that branch's secret; git must
be trusted and at least 2.32; atime may update; confusable glyphs.
**Definition of done:** release checks pass in a temporary venv outside the repository with pasted
output; README contains only real output and measured numbers; full gate green on both OSes; final
phase report written. Tagging and pushing are yours.

---

## 5. Changelog of this plan
- v0.1 (2026-10-12): first draft; decisions D1-D20 open.
- v0.2 (2026-10-12): all decisions approved by the owner on 2026-10-12, including D4 rules command and D20 option b.
- v0.3 (2026-10-12): Phase 1 deviations, awaiting acceptance (details in docs/phase-reports.md):
  `Rule` is not in `core/models.py` yet (it needs the guarded pattern type of Phase 2);
  `ScanStats` keeps skip counters as flat integer fields instead of a mapping;
  `Limits.with_overrides` is lower-only (D19) and the D18 ceilings are a separate hard bound;
  the architecture checker also enforces core purity (no os, sys, io, pathlib, time in `core/`)
  and the `sys.platform` guard rule (no `os.name`, no `platform.system`);
  coverage is measured over `src/secret_scanner` and `scripts`;
  `authors` in pyproject.toml and the LICENSE holder are the placeholder "secret-scanner authors"
  because the owner's name is not known to the session (D20 asks for a name only);
  the type-walk test "no renderable model can hold a secret" was written in Phase 1, not Phase 2.
- v0.4 (2026-10-12): Phase 2 follow-ups from the owner: the author placeholder is replaced by the
  owner's name in `pyproject.toml` and LICENSE (v0.3 deviation 6 resolved).
- v0.5 (2026-10-12): Phase 2 deviations and interpretations, **accepted by the owner on
  2026-10-12** (see v0.6; details in docs/phase-reports.md): `Rule`, `FakeSegment` and `Checksum` are in `core/models.py` (resolves
  v0.3 deviation 1); rule `context` is a list of 1 to 4 lower-case keywords that must all appear
  on the line; the `fake` spec is a list of segments and is the full matched text; the regex
  guard adds the rule that two adjacent variable-width items must not match the same byte, and
  defines cost as maximum width times alternation paths (D3's formula when no group holds an
  alternation), compiles byte patterns and refuses anchors; the entropy detector treats `=` as
  padding only at the end of a token, derives the hex minimum as the larger of 32 and the
  configured minimum, and enforces the 64-bit floor of D7 at run time; a key block that reaches
  `MAX_KEY_LINES` is reported at confidence medium; `Match` carries severity and shown
  characters; the test marker `requires_sh` and the hook launcher `scripts/hooks/run_guard.sh`
  (Phase 1 follow-up) are not in the plan.
- v0.6 (2026-10-12): the owner accepted every deviation and interpretation listed in v0.5 and in
  the Phase 2 report: `Rule`, `FakeSegment` and `Checksum` in `core/models.py`; `context` as a
  keyword list; the `fake` spec as a segment list; the regex guard's neighbour-ambiguity rule and
  its cost definition; entropy `=` as trailing padding only, hex minimum and the run-time 64-bit
  floor; the entropy context window; `MAX_KEY_LINES` giving confidence medium; `Match` carrying
  severity and shown characters; column counting by Python's replacement rule; the engine's
  `capped` and long-line flags (issues are Phase 3); the `requires_sh` marker and the hook
  launcher. The v0.3 (Phase 1) deviations are not covered by this entry and stay as they were.
  Known limitations recorded for the README (Phase 6 Limitations section): token formats come from
  knowledge, not from live checks; the Claude Code hook (a development control, not part of the
  tool) cannot see shell aliases, variables or PowerShell `-EncodedCommand`, and is not in force
  if `sh` cannot start.
- v0.7 (2026-10-13): owner decisions at the start of the Phase 3 continuation, **accepted by the
  owner on 2026-10-13**:
  1. The v0.3 (Phase 1) deviations are accepted (the seven items listed under v0.3 above; the
     first was resolved by v0.5 and the author placeholder, the sixth, by v0.4).
  2. Accepted scope change: `--write-baseline` is built in Phase 3, not Phase 4 or later. The
     Phase 3 Scope sentence excluded it, but its Tests list requires the `--write-baseline` /
     `--baseline` round trip. The Phase 3 Scope line is edited accordingly; `scan-git` gets the same
     option in Phase 4.
  3. The `rules` command (D4, approved) was in no phase list. It is assigned to Phase 5, together
     with the demo. The Phase 5 Scope line is edited accordingly.
  4. Test policy: `fs_scanner._count_skip` is covered by tests. Lines that can only run on POSIX or
     only on Windows are handled the way the gate already handles platform-specific code (combined
     Windows and WSL Linux coverage, or the existing pragma convention with a reason); the 85%
     floor is not lowered and there are no blanket exclusions.
- v0.8 (2026-10-13): Phase 3 interpretations and additions, **accepted by the owner on
  2026-10-13 except item 7, which v0.9 replaces** (details in docs/phase-reports.md):
  1. Exit code with `--write-baseline`: unchanged from D10. A run that finds something still exits
     1 and the baseline it wrote is the way to accept those findings; D9 does not say otherwise.
  2. A written baseline holds the reported findings and the ones the given baseline already
     suppressed by fingerprint, after the `--min-confidence` filter. Reasons already written are
     kept, path globs are carried over, and a finding that only a path glob covers is not
     duplicated as a fingerprint entry. D9 says "every current finding".
  3. Error messages never echo a key name, limit name or glob pattern taken from a configuration,
     rules or baseline file (they list the allowed keys, or the position of the entry): a mistyped
     key can be a pasted secret. This changed the text of existing messages.
  4. `--output` may not name the file given as `--config` or `--baseline`, and `--output` and
     `--write-baseline` may not name the same file; `--write-baseline` may replace `--baseline`
     (with `--force`). `--output` and `--write-baseline` inside the scanned tree are refused.
  5. The JSON `host` and the table take the host label from the application, not from `Report`
     (`Report` has no host field); the table is written to stdout, notices to stderr, and with
     `--output` stdout stays empty.
  6. `OutputFormat` (table, json) is a core model; the built-in rules are parsed once per process.
  7. Escaped output doubles backslashes (sanitiser design, Phase 1), so a Windows path in a report
     shows `\` separators. Documented in docs/report-schema.md. **Not accepted; replaced by v0.9
     item 1.**
- v0.9 (2026-10-13): owner decisions at the start of the Phase 4 session, **accepted by the owner
  on 2026-10-13**:
  1. v0.8 items 1 to 6 are accepted. Item 7 is replaced: in the table and every other human-readable
     output (notices, error messages), paths are shown relative to the scan root with `/`
     separators and escaped per component, so a Windows path never shows doubled backslashes.
     JSON keeps standard JSON string encoding. Implementation: `core/sanitize.py` gets `sanitize_path(path, windows=...)`; a path given by the
     user (scan root, `--output`, `--write-baseline`) is shown as given with `/` on Windows, where
     `\` is a separator; finding and issue paths were relative `/` keys already; on POSIX a
     backslash is a name character and stays escaped; the JSON `target.path` carries the same
     display form, and its encoding and the schema `secret-report/1` are unchanged.
     A test asserts that table output holds no doubled backslash.
  2. Gate time: the default gate (50 s to 62 s, 48 s to 110 s observed) is brought to about 40 s
     without weakening the coverage of any behaviour. `scripts/gate.py` gets `--durations N`
     (lists the slowest tests; no check is changed). The cost was fixture setup, not slow tests:
     per-test directories, `setenv` and socket patching ran 1 800 times under branch coverage.
     Environment isolation and the socket blocker are now applied once per session, and a
     per-test check proves a test left nothing in the isolated home. The leakage matrix keeps one
     representative per detector kind through every format and error path in the default run (the
     other rules run it as `slow`), and every rule still goes through the table and JSON renderers
     in the default run. Two generated or oversized inputs (1 500 random patterns, 3 000 nesting
     levels) run reduced in the default gate and in full as `slow`. Measured numbers are in
     docs/phase-reports.md. The floor of 85 % and every threshold are unchanged.
- v0.10 (2026-10-13): Phase 4 interpretations and additions, **accepted by the owner on
  2026-11-08**; item 1 (the refusals) is listed as a known, deliberate refusal under the README
  Limitations (details in docs/phase-reports.md and docs/git-hardening.md):
  1. Refusals before git reads any object, from `lstat` and bounded reads in `fs/walk.py`
     (exit code 3): `.git` as a symbolic link or reparse point, `.git` as a file (a worktree or
     submodule checkout: scan the main repository), `objects/info/alternates` or `http-alternates`
     with entries (objects outside the repository would be read silently), and `info/grafts` with
     entries (the installed git's documentation does not say that `--no-replace-objects` turns
     grafts off). The git directory git then discovers must be the one found by `lstat`.
  2. `rev-parse --show-object-format` is not called: the object id length (40 or 64) is taken from
     git's own output and must be the same everywhere.
  3. `log` also gets `--diff-filter=AMT`; D2's list is otherwise unchanged. `--no-optional-locks`
     is passed as a global option as well as the environment variable, and
     `GIT_PROTOCOL_FROM_USER=0` is added to the environment. `GIT_NO_LAZY_FETCH` is the
     environment variable only (the `--no-lazy-fetch` option is git 2.44).
  4. `scan --gitignore` discovers the work tree with no ceiling (D13 allows a PATH inside a work
     tree); `scan-git` keeps D2's ceiling at the parent of the path. A PATH outside any work tree
     is exit code 2 (D13), not 3.
  5. History statistics: `files_seen` and `files_scanned` count distinct blobs, `blobs_from_cache`
     counts (commit, path) entries of an already scanned blob, gitlinks and symlink entries are
     counted per entry. `history_complete` is true only for a non-shallow, complete run.
  6. A blob's matches are cached per (blob id, entropy detector enabled for the path), because the
     entropy detector is skipped for some paths; a finding is reported once per fingerprint, at the
     first commit of the walk (`--reverse --topo-order`).
  7. A cap or deadline hit before anything was scanned (during discovery) is exit code 4 with an
     error message and no report; after the walk has started it is a recorded issue and a report.
  8. `--git PATH` is validated by `fs/safe_files.check_program` (absolute, a regular file, not in
     the scanned tree; exit code 2). The git program is otherwise searched on PATH skipping empty
     and relative entries and anything inside the scanned tree.
  9. On Windows a stopped git is ended with `taskkill /PID <pid> /T /F` (by PID) in addition to
     `Popen.kill`, because `cmd\git.exe` starts the real git as a child.
  10. New: module `app/common.py` (the steps `scan` and `scan-git` share), `docs/git-hardening.md`
      with drift tests, test marker `requires_git_sha256`, `tests/hostile.py`.
- v0.11 (2026-11-08): D2 "Binary" made precise after CI run 5 found a real planting path
  (docs/threat-model.md, finding F-1), **accepted by the owner on 2026-11-08**. D2's text is unchanged; these are
  the rules the code now enforces beyond it: only fully qualified `PATH` entries (on Windows also
  a drive or share, not `\dir` or `C:dir`); never searched even when absolute: the scanned tree,
  the system temporary directory tree, and the current directory itself (not below it, so a
  `.venv\Scripts` entry or a start from a drive root keeps working); on Windows only `git.exe`
  (v0.10 item 8 said "regular file" only); `--git PATH` on Windows must be called `git.exe`; the
  resolved path is normalised and passed to `Popen` as `executable=` as well as `argv[0]`; the
  test helper `git_binary()` no longer uses `shutil.which`. New files: `docs/threat-model.md`
  (started here, Phase 6 completes it), `CHANGELOG.md`, `tests/test_git_program_resolution.py`.
- v0.12 (2026-11-09): owner decisions at the start of the Phase 5 session, **accepted by the owner
  on 2026-11-09** (CI run 6 on `090df20` is green on all six jobs; the F-1 fix is confirmed):
  1. Default gate time: 53 s to 66 s is accepted for now. The real-git hostile tests stay in the
     default run, because they prove on every commit that each execution vector stays closed.
     This closes the "default gate above the v0.9 target" gap of the Phase 4 report; it is
     measured again at the end of Phase 5.
  2. The README Limitations section (completed in Phase 6) will list: the time-of-check to
     time-of-use gap between resolving git and starting it; that commit messages, tag messages,
     the reflog, unreachable objects, submodule contents and LFS objects are not scanned in v1; the
     deliberate refusals of worktree and submodule `.git` files, alternates and grafts (exit code 3,
     v0.10 item 1); and that the Windows planted-executable test needs `csc.exe`.
- v0.13 (2026-11-09): Phase 5 interpretations and additions, **accepted by the owner on
  2026-11-10**, together with the rewrite of the two unpushed commits `7b112f2` and `2fad516`
  (redone from `0631ca6` to remove a hex value that the tool's own history scan flagged; details in
  docs/phase-reports.md; D11, D12 and the Phase 5 scope are otherwise built as written):
  1. JSONL (D11): the finding object also carries `suppressed_by` (last field), so that a
     suppressed finding listed with `--show-suppressed` can be told from a reported one; `timestamp`
     is the time of the run on every line (a commit's time is `secret.commit_time`); `file_sha256`
     is the SHA-256 of the full escaped path; the summary line's fields are the ones listed in
     docs/siem-mapping.md (D11 says "counts and `complete`"); scan issues are counted in the
     summary, not listed. The shape was derived from D11 and from mini-siem's parser, which was read
     read-only; file-integrity-monitor's own `docs/siem-mapping.md` was not read, because CLAUDE.md
     section 4 item 4 allows reading outside this folder only for mini-siem's parser source.
  2. SARIF (D12): `driver.version` is written as well as `semanticVersion`; `informationUri` is
     the repository page taken from this repository's `origin` remote; the artifact URI is built
     from the exact path (`path_key`), not from the escaped display form; a suppression's
     `justification` is a fixed sentence saying whether the baseline matched by fingerprint or by
     path (a `Finding` does not carry the baseline's written reason); `run.properties` holds
     `target`, `complete`, `truncated`, `historyComplete`, `rulesSha256` (D19's rules version),
     `suppressedByFingerprint`, `suppressedByPath`, `stale` and `generatedAt`; every scan issue is a
     `toolExecutionNotification` of level `warning`; `properties.commit` only on a history result.
     Not validated against the official SARIF schema (no PyPI package ships it, checked on
     2026-11-09; structural tests written from the specification) and not uploaded to GitHub code
     scanning: both stay listed known gaps.
  3. `rules` (D4): `rules [--format table|json]` lists the 13 regex rules of the rules file and the
     three detectors (`private-key`, `entropy-base64`, `entropy-hex`) with id, name, detector,
     severity, confidence, description and keywords, schema `secret-rules/1`; the detectors'
     descriptions are code (`core/ruleinfo.py`), checked against the detectors' constants. D4 does
     not cover validating a user rules file (D19's `extra_rules` are validated by the configuration
     loader with the regex guard when a scan reads them), so `rules` takes no file.
  4. `demo` (Phase 5): exit code 0 when it ran as designed, 3 without git (the history part is
     skipped), 2 when a result it checks for is missing (`DemoError`). Ctrl-C ends any command with
     exit code 130 and `interrupted` (outside D10's codes, the shell convention). The commit dates
     of the throw-away repository are fixed, so its commit ids do not change from run to run.
  5. New modules: `core/ruleinfo.py`, `render/jsonl.py`, `render/sarif.py`, `render/rules_out.py`,
     `app/rules.py`, `app/demo.py`, `fs/sandbox.py`, `gitio/demo_git.py`; `core/sanitize.clip_display`;
     `app/common.resolve_git_program` (the search `open_runner` already did, now also used by the
     demo); `DemoError`; a custom rule's name and description are escaped by `info_for_rule`.
     New test infrastructure: `tests/audit.py` (audit hooks), `tests/sarif_check.py`,
     `tests/doc_samples.py`.
- v0.14 (2026-11-10): owner decisions at the start of the Phase 6 session, **accepted by the owner
  on 2026-11-10** (CI run 7 on `13b772a` is green on all six jobs):
  1. The demo never prints the real path of its temporary directory (it is random, it is removed
     at the end, and on Windows it names the user's account). The introduction and the two report
     headers show the fixed label `<temporary directory>`; a test proves that the demo's output
     holds no absolute path, account name or temporary directory. Implementation: `run_scan` and
     `run_scan_git` take `shown_as`, used by `app/demo.py` only; no command-line option is added.
  2. Default gate time: 72 s to 82 s on this machine is accepted. It is above the 60 s target of
     CLAUDE.md section 7 and below the 90 s at which tests must move to `slow`. Phase 6 does not
     spend time on gate speed. This closes the "default gate 72.7 s to 82.1 s" gap of the Phase 5
     report.
  3. `pyproject.toml` classifier: `Development Status :: 4 - Beta` (first public release, measured
     on one machine), pinned by a test.
