# How `scan-git` and `scan --gitignore` run git

A repository is hostile input: whoever made it wrote its configuration, attributes, hooks and
objects, and git reads all of them. `gitio/runner.py` is the only module that starts git for
scanning (CLAUDE.md section 5, invariant 4; PLAN.md D1, D2). This page lists what it does, and
the evidence for each setting. Every table below has a drift test
(`tests/test_git_hardening_doc.py`): a change to the runner that is not written here fails CI.

## Supported git

Minimum **2.32.0**. An older git, or none, exits with code 3 and says so. The reasons:

| Feature used | Added in git | Why it is needed |
|---|---|---|
| `GIT_CONFIG_GLOBAL`, `GIT_CONFIG_SYSTEM` | 2.32 | the user configuration must be off |
| `--diff-merges=first-parent` | 2.31 | merges are read against their first parent |
| `rev-parse --end-of-options`, `log --end-of-options` | 2.24 | no revision can be taken for an option |
| `rev-parse --is-shallow-repository` | 2.15 | shallow clones are incomplete history |
| `--no-optional-locks`, `GIT_OPTIONAL_LOCKS` | 2.15 | no index refresh, no lock files |

The "added in" column comes from git's release notes and cannot be checked offline; everything
else on this page was checked against the documentation installed with git
**2.54.0.windows.1** (`git-doc`, offline) and the commands were run against it and against
Linux git **2.53.0** (WSL Ubuntu). `docs/phase-reports.md` records the versions of each run.

## Which git program is run

git is resolved once, to an absolute and normalised path, and that path is what is started
(`fs/safe_files.find_program`, `check_program`, `search_hazards`; PLAN.md D2 "Binary"). The
reasons are in `docs/threat-model.md`, finding F-1 (a planted `git.exe`, caught by CI).

- Only fully qualified `PATH` entries are searched. Empty, `.` and relative entries are ignored,
  and so are Windows entries that depend on the current drive (`\dir`, `C:dir`).
- Never searched, even by absolute name: the scanned tree, the system temporary directory tree,
  and the current directory itself (not what lies below it).
- Windows: only `git.exe`. `git.cmd`, `git.bat`, `git.com` and other script types are never
  taken, and `shutil.which` or a bare program name is never used.
- `--git PATH`: fully qualified, an existing regular file, named `git.exe` on Windows, executable
  on POSIX, outside the scanned tree (exit code 2 otherwise). A path typed in full is trusted
  anywhere else.
- Not found: exit code 3.

## The environment

The environment of every git process is built from scratch (`environment_for`); nothing is
inherited from the caller. These variables and `PATH` (the directory of the git binary) are all
there is; on Windows `SYSTEMROOT` is added because the OS needs it.

| Variable | Value | Effect | In the installed docs |
|---|---|---|---|
| `GIT_CONFIG_NOSYSTEM` | `1` | the system configuration is not read | `git(1)` |
| `GIT_CONFIG_GLOBAL` | the null device | neither `~/.gitconfig` nor `$XDG_CONFIG_HOME/git/config` is read | `git(1)` |
| `GIT_TERMINAL_PROMPT` | `0` | git never asks on the terminal | `git(1)` |
| `GIT_PAGER` | `cat` | no pager | `git(1)` |
| `PAGER` | `cat` | no pager (overridden by `GIT_PAGER`, set as well) | `git(1)` |
| `GIT_OPTIONAL_LOCKS` | `0` | no index refresh, no lock files | `git(1)` |
| `GIT_NO_REPLACE_OBJECTS` | `1` | replace refs are ignored | `git(1)` |
| `GIT_NO_LAZY_FETCH` | `1` | a missing object is not fetched from a promisor remote | `git(1)` |
| `GIT_ATTR_NOSYSTEM` | `1` | the system attributes file is not read | not in the installed docs; harmless where unknown |
| `GIT_PROTOCOL_FROM_USER` | `0` | protocols with the `user` policy are not usable | `git(1)` |
| `LC_ALL` | `C` | machine-readable messages | locale |

`GIT_CEILING_DIRECTORIES` (the parent of the given path) is added to the discovery call only, so
a repository above the given directory is never picked up. A caller's `GIT_DIR`,
`GIT_EXTERNAL_DIFF`, `GIT_SSH*`, `GIT_ASKPASS`, `GIT_EXEC_PATH`, `GIT_TRACE*`,
`GIT_CONFIG_PARAMETERS`, `HOME` and the rest never reach git (test:
`test_the_callers_environment_cannot_make_git_run_anything`).

## Pinned configuration

Passed as `-c key=value` on every call. Command-line configuration wins over the repository's
own `.git/config` (and over files it includes), so a hostile repository cannot turn any of these
back on.

| Key | Value | What it stops | In the installed docs |
|---|---|---|---|
| `core.fsmonitor` | `false` | a monitor program or the built-in monitor daemon | `git-config` |
| `core.hooksPath` | `/dev/null` | hooks (the manual's own spelling for "no hooks") | `git-config` |
| `core.pager` | `cat` | a pager program | `git-config` |
| `core.untrackedCache` | `false` | untracked-cache writes | `git-config` |
| `credential.helper` | (empty) | credential helper programs (an empty value resets the list) | `git-config` |
| `protocol.allow` | `never` | every transport, so also a lazy fetch in a partial clone | `git-config` |
| `core.sshCommand` | (empty) | the ssh program | `git-config` |
| `core.gitProxy` | (empty) | the `git://` proxy program | `git-config` |
| `log.showSignature` | `false` | running gpg to check signatures | `git-config` |
| `diff.external` | (empty) | an external diff program | `git-config` |
| `gc.auto` | `0` | automatic garbage collection | `git-config` |
| `maintenance.auto` | `false` | automatic maintenance | `git-config` |
| `log.showRoot` | `true` | a root commit is shown with its files | `git-config` |
| `color.ui` | `never` | escape sequences in output | `git-config` |
| `core.quotePath` | `true` | (no effect with `-z`; pinned so a hostile value cannot change output) | `git-config` |

## Global options

`--no-pager`, `--no-replace-objects`, `--literal-pathspecs` and `--no-optional-locks`, then
`--git-dir=<absolute git directory>` for every call after discovery, so git never walks upwards
or looks at a work tree again. (`--no-lazy-fetch`, git 2.44, is not used: older gits reject it.
The environment variable and `protocol.allow=never` do the same.)

## The command set

A closed enum (`GitCommand`); the only variable arguments are object ids and validated revisions.
No `--filters`, no `--textconv` and no `--follow-symlinks` anywhere: blobs are read raw, so no
attribute-selected driver ever runs.

| Command | Fixed arguments | Used for |
|---|---|---|
| `version` | `version` | the minimum version check |
| `rev-parse` | `rev-parse` (`--absolute-git-dir`, `--is-shallow-repository`, `--verify --end-of-options REV^{commit}`) | discovery, shallow check, resolving a revision to an object id |
| `log` | `log --raw -z --no-abbrev --no-renames --no-ext-diff --no-textconv --no-color --no-decorate --no-show-signature --no-mailmap --diff-merges=first-parent --diff-filter=AMT --reverse --topo-order --format=%x01%H %P %ct` | the history walk |
| `cat-file --batch-check` | `cat-file --batch-check` | blob sizes before any blob is read |
| `cat-file --batch` | `cat-file --batch` | blob contents |
| `ls-files` | `ls-files -z --cached --others --exclude-standard` | `scan --gitignore` only |

The history walk reads no commit message, no author and no tag message: the format string asks
for the commit id, the parent ids and the committer time only. `--no-show-signature` is accepted
by the git versions tested although the `git-log` page names only `--show-signature`;
`--end-of-options` is documented in `gitcli`.

## What is refused before git reads any object

`fs/walk.py` examines the repository directory with `lstat` and bounded reads, and
`app/scan_git.py` refuses (exit code 3), because git itself would follow these silently:

| Found | Why it is refused |
|---|---|
| `.git` is a symbolic link or reparse point | links are never followed |
| `.git` is a file (`gitdir: ...`, a worktree or a submodule) | git would read another directory |
| `objects/info/alternates` or `http-alternates` lists a store | objects outside the repository would be read; `git repack -a -d` makes it self-contained |
| `info/grafts` has entries | grafts rewrite parent links behind git's back and are not switched off by `--no-replace-objects` |
| the directory is not the top of a work tree or a bare repository | discovery has a ceiling at the parent of the given path |
| the git directory git discovers is not the one found by `lstat` | a gitdir link or environment trick |

A repository of another owner is refused by git ("dubious ownership"); `--allow-other-owner`
passes `-c safe.directory=<that exact path>` for the discovery call, which is safe here because
the pinned settings above remove what that check exists to guard against.

## Settings that are not pinned, and why they cannot run

Some execution vectors are named by *sections* with a user-chosen name (`diff.<driver>.textconv`,
`filter.<driver>.clean`, `merge.<driver>.driver`, `gpg.<format>.program`, `alias.*`,
`pager.<command>`). Config cannot pin a wildcard, so the tool never reaches the code that would
use them: it asks for no content diff, no checkout, no merge, no signature check and no alias
(aliases that name a built-in command are ignored by git, and only built-ins are run). The
hostile-repository test (`tests/test_git_hostile.py`) sets every one of them to a program that
writes a sentinel file, and a positive control shows the same repository does run them when git is
used without these protections.

## Bounds

| Bound | Constant | Result of exceeding it |
|---|---|---|
| a short call (version, rev-parse, ls-files) | `GIT_CALL_TIMEOUT_SECONDS` | process killed, exit 4 |
| the whole run | `MAX_RUN_SECONDS` | process killed, issue `time_budget`, exit 4 |
| output of one call | `MAX_GIT_OUTPUT_BYTES` | process killed, issue `limit_reached`, exit 4 |
| standard error of one call | `MAX_GIT_STDERR_BYTES` | process killed, exit 4 |
| commits, distinct blobs | `MAX_GIT_COMMITS`, `MAX_GIT_BLOBS` | scan stops, issue `limit_reached`, exit 4 |
| blob size | `MAX_BLOB_BYTES` | blob skipped, issue `too_large`, exit 4 |

A process is stopped through its own handle (`Popen.kill`); on Windows its tree is ended with
`taskkill /PID <pid> /T /F`. No process is ever stopped by image name. A git that fails, or
prints anything the strict parsers (`core/gitparse.py`) do not accept, is exit code 3.
