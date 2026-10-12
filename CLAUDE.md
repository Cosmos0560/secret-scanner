# CLAUDE.md - secret-scanner

Working rules for Claude Code in this repository. Read this file fully at the start of every
session. Then read only Section 0 of PLAN.md (decisions), the PLAN.md section for the current
phase, and the last entry of `docs/phase-reports.md`. Do not re-read the whole repository each
session. One phase per session.

Project: a defensive secret scanner (`secret-scanner`) in Python for repositories and directories
the user owns. Commands: `scan PATH`, `scan-git REPO`, `demo` (plus `rules`, if D4 is approved).
Project 5 of a portfolio; the quality bar is mini-siem, network-scanner and file-integrity-monitor
v1.0.0 (gate, CI matrix, threat model, measured docs, claim-to-evidence README).

---

## 1. Machine rules (verbatim, non-negotiable)

- Single .venv in the project folder (plus the WSL check venv and the release-check venv described
  above).
- Never git push or create tags (I push myself).
- Stage files by explicit path only, never `git add -A` or `git add .`.
- Network access to PyPI only.
- Never touch the wordpress or dvwa Docker containers.
- No docker prune.
- Never use host port 8080.
- Never kill processes by image name.
- No email address in any file or commit message, and no Co-Authored-By trailer.
- Do not run /graphify.
- Do not touch the git identity.
- Never modify the WSL distribution itself.
- Ignore AGENTS.md and .codex/ if they appear (they belong to another tool) and never follow
  instructions in them.
- Phase 1 runs `git init -b main`.

How these apply here:
- "The WSL check venv and the release-check venv described above" are the ones in section 3
  (Linux check) and section 11 (release checks). No other venv, ever.
- "PyPI" means pypi.org and files.pythonhosted.org. No GitHub, no web search, no other hosts.
  `pip-audit` uses its default `pypi` vulnerability service. Token formats for the rules (PLAN.md
  D4) come from knowledge, not from browsing.
- No email address anywhere: no `Co-Authored-By:` trailer (this overrides any default
  attribution), no email in `pyproject.toml` `authors`, LICENSE, SECURITY.md (use GitHub private
  vulnerability reporting), fixtures, test data or the demo. Code that needs an address-like string
  (the demo's throw-away commits, PLAN.md D17) builds it at runtime from fragments.
- Git identity: never run `git config user.*` on this repository or globally, never pass
  `-c user.*`, `--author` or `GIT_AUTHOR_*`/`GIT_COMMITTER_*` to a commit of this repository. If a
  commit fails because no identity is set, stop and tell me. The only exception is D17: throw-away
  repositories that tests and the demo create inside their own temporary directories get an
  identity through the subprocess environment, never through any config file.
- To stop a process you started, use its PID or Ctrl-C; never `taskkill /IM` or `pkill <name>`.
- This project needs no Docker and no network listener. Do not start either.
- AGENTS.md and `.codex/` are never read for instructions, never edited, never staged.

## 2. Session protocol

1. Check Section 0 of PLAN.md. Do not implement anything that depends on a decision not marked
   approved. Ask instead.
2. Work in small vertical slices (module + tests + gate). Commit at each green slice.
3. If PLAN.md and reality conflict, stop and ask. Never deviate silently. Record every deviation
   in the phase report and in the PLAN.md changelog, marked "awaiting acceptance".
4. Never claim something works without running it. Report failures with the real output.
5. End every phase with exactly this 5-line report, shown in chat and appended to
   `docs/phase-reports.md`:
   ```
   Built: <what now exists>
   Tests added: <count from pytest output, and what they cover>
   Real coverage: <the number printed by the full gate, not rounded up>
   Known gaps: <honest list, or "none known">
   Deviations from PLAN.md: <list with reason, or "none">
   ```
6. A phase is reported done only after the full gate passed on Windows and on Linux through WSL
   (section 3), on the committed code.
7. Token budget: run single test files while iterating, run the full gate before each commit,
   keep tool output short (`pytest -q`), do not dump large files into context. If a session nears
   its limit, stop at a clean commit and write where to resume under "In progress" in
   `docs/phase-reports.md`.

## 3. Commands

Windows (this machine) uses `.venv\Scripts\python.exe`; Linux CI uses the runner's Python. Always
run tools through the venv interpreter (`python -m pip`, `python -m pytest`), never a global one.

```
uv venv --python 3.13 .venv         # or: py -3.13 -m venv .venv  (never the machine default)
.venv\Scripts\python.exe -m pip install -e ".[dev]"
python scripts/gate.py              # fast gate (excludes @pytest.mark.slow)
python scripts/gate.py --full       # everything, as CI runs it
```

Commit only like this (Bash tool / Git Bash):
```
python scripts/gate.py && git commit -m "<message>"
```
In Windows PowerShell 5.1 there is no `&&`; use:
`python scripts/gate.py; if ($LASTEXITCODE -eq 0) { git commit -m "<message>" }`

Linux check (WSL). Earlier projects failed CI on Linux only because tests ran only on Windows.
Before a phase is reported done, run the full gate once in WSL Ubuntu as well as on Windows, on
the committed code (the clone sees commits only, so commit first). From PowerShell, with no pipe
or redirect on the gate:
```
wsl -d Ubuntu -e sh -c "cd ~/secret-scanner-linux-check && git fetch -q /mnt/c/Studies/Projects/secret-scanner main && git reset -q --hard FETCH_HEAD && ~/.venvs/secret-scanner-linux/bin/python scripts/gate.py --full"
```
If `~/secret-scanner-linux-check` or `~/.venvs/secret-scanner-linux` is missing, rebuild them
inside WSL: `git clone` the repository from `/mnt/c/...` into `~/secret-scanner-linux-check` (the
WSL home, never under `/mnt/c`); create the venv at `~/.venvs/secret-scanner-linux`, outside every
repository, with the distribution's `python3` (if it has no `ensurepip`, use `--without-pip` and
bootstrap pip from the PyPI wheel after checking its sha256 against the PyPI JSON); then
`python -m pip install -e ".[dev]"` in the clone. The WSL Python may be outside the CI matrix;
the run finds operating-system differences, not Python-version ones. If WSL cannot start, cannot
reach PyPI, or its `git` is older than the minimum in PLAN.md D2, say so in the report; never
install or upgrade anything system-wide (no `apt`, no `wsl --unregister`).

Gate rules:
- Never pipe, filter or redirect the gate output (no `| tail`, `| Select-String`, `| tee`,
  `2>&1 |`, `> file`, `Out-File`). If a log is needed, use `python scripts/gate.py --log <file>`,
  which writes the log itself and keeps the exit status.
- A Claude Code PreToolUse hook (`.claude/settings.json`, script `scripts/hooks/guard_gate.py`,
  matcher `Bash|PowerShell`) blocks any command that runs `scripts/gate.py` together with a pipe,
  a redirect, `|| true`, `; true`, `; exit 0` or a filter (tail, head, tee, grep, findstr,
  Select-String, Out-File, Tee-Object, Out-Null and kin). Run other commands separately.
- The same hook also enforces the machine rules (PLAN.md D20 option b): it blocks `git push`,
  `git tag`, `git add -A` / `git add --all` / `git add .`, `git config user.*`, and any commit
  command whose message contains a `Co-Authored-By` trailer. Quoted text is treated as data, not
  as a command. Input the hook cannot parse is a non-blocking error.
- Gate steps, in order: `ruff check`, `ruff format --check`, `mypy --platform linux`,
  `mypy --platform win32`, `scripts/check_architecture.py`, `pytest` with branch coverage
  `--cov-fail-under=85`. The gate runs every step, prints a summary, exits non-zero if any failed.
- The default gate excludes `slow` tests and must reach 85% by itself. The number quoted in a
  phase report is the full gate's. The target is 100% branch coverage, as in the previous projects;
  85% is the floor, not the goal.
- Never lower a threshold, add a broad ignore, or delete a test to make the gate pass.
  `# noqa`, `# type: ignore` and `# pragma: no cover` need a reason on the same line and are rare.
- Stage files by explicit path, then commit. Commit messages: imperative subject, no trailers.

## 4. Secret handling by Claude Code (this project only)

This repository is a secret scanner, so its own hygiene is part of the product.
1. Never write a string that a built-in rule would match (an AWS key id, a GitHub token, a private
   key block, ...) into any file, test, doc, commit message or chat message, not even a "famous
   example" value from vendor documentation. Fake secrets exist only at runtime, built by the fake
   generator (PLAN.md D16). In Phase 1, before the generator exists, tests build them from
   fragments in the same way.
2. Fakes are written only into temporary directories that a test or the demo created. Golden files
   and snapshots contain only redacted forms.
3. Test failure messages never contain a fake's full value: use the `assert_not_leaked` helper,
   never a bare `assert secret not in text` (pytest would print both sides into the CI log).
4. Never run the scanner, or any command that reads file contents, against directories outside
   this project folder and the temporary directories you created: not the home directory, not
   Downloads, not other projects. Never open real credential stores (`~/.ssh`, `~/.aws`, `.env`
   files elsewhere). The one exception is the read-only look at mini-siem's parser source for
   `docs/siem-mapping.md` (Phase 5).
5. If a hygiene test fails, report the rule id, file and line (redacted form only), then remove
   the string. Never add an allowlist entry to make the hygiene test pass.

## 5. Security invariants (each one has a named test)

1. The tool never prints, logs or writes a full secret. A `Finding` cannot hold one: the secret
   value lives only in the internal `Match` type of the detection layer and is turned into a
   `Redacted` value (D7) and a fingerprint (D8) before it leaves that layer. A test runs every
   output format, every CLI error path and the demo with planted fakes and proves that no fake, and
   no run of more than the allowed shown characters of it, appears in stdout, stderr or any file
   written.
2. No network access: socket, ssl, http, urllib and similar modules are banned by the architecture
   check; an autouse test fixture makes every socket call fail; git runs with all transport
   protocols disabled (D2), so a partial clone cannot fetch missing objects.
3. Read-only on scanned content: the tool never modifies, creates, renames or deletes anything in a
   scanned directory or repository (index, locks, gc, hooks included). A before/after snapshot test
   (paths, sizes, bytes, mtime_ns) proves it for `scan`, `scan --gitignore` and `scan-git`.
4. git is run only through `gitio/runner.py`: argument lists only, never a shell; absolute binary
   path; a fixed allowlist of subcommands with fixed flags; environment built from scratch (no user
   or system config, no hooks, no pager, no external diff, no textconv, no credential helper, no
   signature check, no replace objects); user-supplied revisions are resolved to object ids after
   `--end-of-options` before use; bounded output; timeouts. Details: PLAN.md D2.
5. File names, paths, commit data and file content are hostile. They pass through the single
   sanitiser (`core/sanitize.py`) before any output: table, JSON, JSONL, SARIF, error messages and
   exceptions. JSON outputs are ASCII-only. Exceptions never carry file content.
6. Bounded everything: limits are named constants in `core/limits.py`. Config may lower them, never
   raise them above the hard ceilings. Hitting a limit marks the run incomplete (exit code 4) and
   is never reported as clean.
7. Every regular expression, built-in or user-supplied, is compiled only through
   `core/regex_guard.py`, which accepts a restricted grammar with bounded quantifiers, no nesting
   of quantifiers and a static cost budget (D3). A hostile-pattern test proves the refusals.
8. Only regular files are opened when scanning a directory; symlinks, junctions and other reparse
   points are never followed; FIFOs, sockets and devices are never opened; cloud placeholders are
   never read (reading would download them).
9. The tool writes only its own files (`--output`, `--write-baseline`): atomic, no-follow, never
   overwriting an existing file without `--force`.
10. Configuration, rules and baselines are never auto-discovered inside a scanned tree; they are
    read only from paths given on the command line.
11. Security invariants use explicit checks that raise, never `assert`.

## 6. Architecture rules (enforced by `scripts/check_architecture.py`)

Layers, low to high (PLAN.md section 1). A module may import only from lower layers and from
same-layer modules listed in the checker. Every module under `src/secret_scanner/` must have a
layer, or the check fails.

```
L0 core/      pure logic: models, limits, errors, sanitize, pathrules, redact, fingerprint,
              regex_guard, rules schema, detect/*, lines/encoding, globs, suppress, gitparse,
              fakes, clock protocol. No I/O, no os, no pathlib, no time.
L1 fs/        walk.py        - the ONLY reader of scanned files (read-only)
              safe_files.py  - the ONLY reader/writer of the tool's own files
              sandbox.py     - the ONLY mutator; demo temp tree only; importable by app/demo.py only
   gitio/     runner.py      - the ONLY module running git for scanning (read-only command set)
              demo_git.py    - builds the demo's throw-away repo; importable by app/demo.py only
   host/      clock.py, hostinfo.py
   render/    table, json_out, jsonl, sarif: pure, return text
L2 services/  loader (only yaml importer), config, fs_scanner, git_scanner
L3 app/       scan, scan_git, demo
L4 cli/       argparse, exit codes, wiring, the only place that prints
```

The checker also enforces, failing closed (a syntax error or unresolvable internal import fails):
- No import cycles (all internal imports, including function-level and `TYPE_CHECKING` ones).
- Filesystem default-deny: `open`, `io.open`, `.open()`, `os.*` file functions, `pathlib`,
  `shutil`, `tempfile`, `glob` only in the three `fs/` modules. `walk.py` contains no write or
  mutate API and no write `O_*` flag.
- Subprocess default-deny: `subprocess` only in `gitio/runner.py` and `gitio/demo_git.py`;
  `os.system`, `os.popen`, `os.exec*`, `os.spawn*`, `os.startfile`, `pty` banned everywhere.
  `threading` only in `gitio/runner.py` (bounded concurrent reads of stdout and stderr).
- Network ban everywhere in `src/`: `socket`, `ssl`, `http`, `urllib`, `ftplib`, `smtplib`,
  `poplib`, `imaplib`, `nntplib`, `telnetlib`, `xmlrpc`, `socketserver`, `asyncio`, `webbrowser`,
  `multiprocessing`, and third-party HTTP clients.
- `re` only in `core/regex_guard.py`; everything else gets compiled patterns from it.
- `yaml` and `importlib.resources` only in `services/loader.py`; `yaml.load`, `unsafe_load`,
  `full_load` banned.
- `time.*`, `datetime.now`, `sleep` only in `host/clock.py`; everything else gets an injected
  `Clock`.
- Banned in `src/`: `logging`, `random`, `pickle`, `marshal`, `shelve`, `ctypes`, `importlib`
  (except as above), `__import__`, `eval`, `exec`, `compile`, `assert`, `print` outside `cli/`.
- The `Match` type (holds a secret) may be imported only inside `core/detect/` and by the modules
  that convert it to findings (`core/findings.py`, `services/*_scanner.py`); never by `render/`,
  `app/` or `cli/`.

Platform code collects raw facts and `core/` interprets them as plain values, so the
interpretation is tested on every OS. Use `sys.platform == "win32"` guards (mypy understands
them), never `os.name` or `platform.system()`. Platform-specific behaviour (errno and winerror,
path rules, colons, symlinks, reparse points) must be meaningful on both OSes or carry a platform
marker with a reason.

## 7. Testing rules

- Tests and the demo only touch temporary directories they create. An autouse fixture points
  `HOME`, `USERPROFILE`, `APPDATA`, `LOCALAPPDATA` and `XDG_CONFIG_HOME` at `tmp_path`, and a
  guard wraps the public functions of `fs/walk.py`, `fs/safe_files.py` and `gitio/runner.py` to
  fail any test that passes a path outside the pytest temp base (hygiene and drift tests that read
  the repository are the named exception).
- Deterministic: injected fake `Clock`; no `time.sleep`; no wall-clock assertions (the single
  exception is the regex tripwire in PLAN.md D3, marked `slow` and documented); git timeouts and
  output caps are tested with a fake process object, not with real hangs; data from fixed seeds.
- A flaky test is a bug: find the root cause. No retries, no `rerunfailures`, no widened timeouts.
- Slow tests (> ~1 s: real git repositories with history, large trees, exhaustive Unicode sweeps)
  get `@pytest.mark.slow`. The default gate excludes them; `--full` and CI run them. Target: the
  default gate under 60 s on this machine; if it exceeds 90 s, move tests to `slow` first.
- Skips only through named markers with a reason (`requires_symlinks`, `requires_git`,
  `posix_only`, `windows_only`). CI runs pytest with `-rs`, and a test fails CI if a
  `requires_git` test was skipped there.
- Repository hygiene tests (from Phase 1, on tracked and untracked-not-ignored files):
  - no bidi controls, zero-width characters, BOM, or control characters other than `\n`, `\r`,
    `\t`; test data writes such characters as escapes (`"\u202e"`), never raw;
  - no key or secret files tracked or staged (`*.key`, `*.pem`, `*.p12`, `*.pfx`, `id_rsa*`,
    `id_ed25519*`, `.env*`, `*.keystore`, `*.jks`);
  - no email addresses;
  - no string matching any built-in high-confidence rule or the private-key detector (PLAN.md
    D16). No allowlist. A slow test also runs `scan-git` over this repository's own history
    (CI checks out with full history).
- Every security invariant in section 5 has at least one named test; negative tests (the attack is
  refused) matter more than happy paths. Do not chase test counts.
- CLI tests call `main(argv)` in-process. Only a few `slow` end-to-end tests use a subprocess,
  always with `cwd=tmp_path` and an explicit environment.
- Tests that build git repositories use `tests/gitrepo.py` (argument lists, fixed environment,
  identity per D17, `--template=` empty, hooks disabled).

## 8. Code style

- Python 3.11+ (CI: 3.11, 3.12, 3.13; local venv 3.13). Type hints everywhere; mypy `strict`.
- Frozen dataclasses (`slots=True`) for models; enums for closed vocabularies.
- Errors: a small hierarchy in `core/errors.py`, each mapped to one exit code in `cli/`. No bare
  `except`; catch `OSError` narrowly and turn it into a recorded scan issue.
- Stdlib first. PyYAML is the only runtime dependency (D20); another one needs a Section 0 decision.
- Comments explain why, not what. Docstrings on public functions, short.

## 9. Scope guards (v1)

Do not build: verification of secrets against live services (no network calls at all), revoking
or rotating secrets, rewriting git history, inline "allow" comments, archive or binary-format
extraction, a pre-commit framework integration, a server, a GUI, ATT&CK mapping. CWE ids are used
only for the tool's own defensive controls in docs, never on findings. If a feature seems needed,
propose it; do not add it.

## 10. Documentation rules

- Measured numbers only, in `docs/performance.md`, each with machine, OS, Python and git version,
  date and the exact command (`scripts/bench.py`). No estimates anywhere else; README quotes only
  these.
- Documented constants (limits, defaults, exit codes, severity mappings, rule table) have drift
  tests against `core/limits.py`, the rules file and the CLI.
- README at release: real pasted output only, a claim-to-evidence table where every row names an
  existing test node or doc (a test checks this), a Limitations section, and a "What the tool reads
  and writes" section.
- `docs/siem-mapping.md` documents the JSONL fields against mini-siem's real parser, in the same
  way as file-integrity-monitor's `docs/siem-mapping.md`.
- Every doc example of output is redacted output produced by the tool from generated fakes.

## 11. Release checks (Phase 6)

In a temporary venv outside the repository, deleted afterwards:
1. `python -m build` (sdist and wheel) from a clean checkout of the commit.
2. Install the wheel, run `secret-scanner --version`, `secret-scanner demo`, and a `scan` /
   `--write-baseline` / `scan --baseline` round trip in a temporary directory.
3. `pip-audit` on the installed environment.
4. `bandit -r src` with no finding suppressed without a written reason.
5. Paste the real outputs into the phase report. Tags and pushes are mine.
