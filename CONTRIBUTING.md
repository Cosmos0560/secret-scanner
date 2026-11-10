# Contributing

Thank you for looking at this project. It is a small, deliberately strict code base: the rules
below are what keeps a secret scanner from becoming a risk itself.

## The three rules that matter most

1. **Never commit a secret, and never commit a fake that looks like one.** No token, key or
   "example from the vendor documentation" may appear in any file, test, document or commit
   message. Fakes are built at run time by `core/fakes.py` and written only into temporary
   directories. The gate scans every tracked and untracked file with the tool's own rules, and
   the full gate scans the whole history; there is no allowlist. If the check fires, remove the
   string.
2. **Report vulnerabilities privately** (see `SECURITY.md`), never in a public issue.
3. **Scan only what you own.** Tests and the demo touch only temporary directories they create.

## Setting up

Python 3.11 or newer and git 2.32 or newer. From the repository root:

```
python -m venv .venv
.venv/bin/python -m pip install -e ".[dev]"        # Windows: .venv\Scripts\python.exe
```

After changing the version in `src/secret_scanner/__init__.py`, install again: the installed
metadata is compared with it by a test.

## The gate

One command runs everything CI runs:

```
python scripts/gate.py           # fast: without the tests marked slow
python scripts/gate.py --full    # everything, as CI runs it
```

It runs `ruff check`, `ruff format --check`, `mypy --platform linux`, `mypy --platform win32`,
`scripts/check_architecture.py` and `pytest` with branch coverage (the floor is 85%, the target is
100%). Do not pipe or filter its output; `--log FILE` writes a log and keeps the exit status.
A change is ready when the full gate passes on Windows and on Linux.

Do not lower a threshold, add a broad ignore or delete a test to make the gate pass. `# noqa`,
`# type: ignore` and `# pragma: no cover` need a reason on the same line.

## How the code is organised

Layers, low to high; a module may import only from lower layers (the architecture check enforces
this, and fails on any module without a layer):

| Layer | Package | Role |
|---|---|---|
| 0 | `core/` | pure logic: models, limits, sanitiser, redaction, fingerprints, the regex guard, the detectors. No I/O. |
| 1 | `fs/`, `gitio/`, `host/`, `render/` | `fs/walk.py` is the only reader of scanned files, `fs/safe_files.py` the only writer of the tool's own files, `gitio/runner.py` the only module that starts git; renderers return text. |
| 2 | `services/` | rule and configuration loading (the only YAML importer), the directory and history scanners. |
| 3 | `app/` | the use cases `scan`, `scan-git`, `rules`, `demo`. |
| 4 | `cli/` | argument parsing, exit codes; the only place that prints. |

Also enforced: no network module anywhere in `src/`; `re` only in `core/regex_guard.py`;
`subprocess` only in `gitio/`; no `assert`, `eval`, `exec`, `pickle`, `logging` or `print` outside
`cli/`. The details are in `CLAUDE.md` section 6 and in `scripts/check_architecture.py`.

## Tests

- Deterministic: an injected clock, no sleeping, no wall-clock assertions (one documented
  exception), fixed seeds. A flaky test is a bug; no retries.
- Tests that take more than about a second get `@pytest.mark.slow`.
- Compare outputs with fakes only through the `assert_not_leaked` fixture, never with a bare
  `assert secret not in text`: pytest would print the fake into the CI log.
- Negative tests (the attack is refused) matter more than happy paths.
- Characters such as bidirectional overrides are written as escapes or built with `chr()`, never
  raw; the hygiene test refuses them in any file.

## Adding or changing a rule

A rule is data in `src/secret_scanner/rules/builtin.yaml` plus its entry in
`tests/test_rules_builtin.py` (a completeness test fails when one is missing). Every rule needs:
a pattern the regex guard accepts, lower-case keywords that every true positive contains, at least
64 estimated bits in the secret, a `fake` specification for the generator, and positive and
negative cases. Take the format from the vendor's public documentation, say where it comes from
in the pull request, and regenerate the table in `docs/rules.md` (its drift test tells you how it
differs).

## Documentation

- Numbers appear only in `docs/performance.md`, measured with `scripts/bench.py`, each with the
  machine, versions, date and command.
- Every example of output in a document is real output of the tool over generated fakes; drift
  tests regenerate most of them.
- The README's claim-to-evidence table names real tests; a test checks that each exists.

## Commits and pull requests

Small commits, an imperative subject line, no trailers. Describe what changed and how it was
tested. By contributing you agree that your contribution is released under the project's MIT
licence.
