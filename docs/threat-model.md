# Threat model

Status: complete for version 1.0.0 (started in Phase 4 with the finding that a real CI run
produced, finished in Phase 6). Every control below names the tests that prove it, and a drift
test (`tests/test_git_hardening_doc.py::test_every_test_named_in_the_threat_model_exists`) fails
when a named test is renamed or removed. The design decisions referred to as D1 to D20 are in
PLAN.md, the invariants in CLAUDE.md section 5.

## What the tool is, and what it protects

`secret-scanner` reads the files of a directory tree, or the blobs of a git history, and reports
strings that look like credentials. It runs on a developer's machine and in CI, with the rights of
the user who starts it. It is defensive: it reports, and it never uses, checks or sends what it
finds.

Assets, in order of importance:

1. **The secrets in the scanned content.** The tool reads them, so it must never put one in an
   output, a log, an error message or a file, and never send one anywhere.
2. **The machine and account that run the tool.** Scanning hostile content must not run code,
   reach the network, or write or change files.
3. **The scanned content itself.** A scan leaves it exactly as it was.
4. **The truth of the result.** A scan that could not look at everything must say so; a clean
   result must mean that everything was read.

## Trust

Trusted: the Python interpreter and standard library, PyYAML, the installed tool and its built-in
rules file, the git program the tool resolves (see F-1) and the options the user types.

Hostile, and treated as data only:

- file contents, file names, directory structure, links and special files in a scanned tree;
- everything in a scanned repository: objects, refs, repository configuration, hooks, attributes,
  commit data, and the layout of the `.git` directory;
- the contents of the configuration, rules and baseline files the user names (they often come
  from the repository under test);
- environment variables that could redirect git;
- the terminal or log viewer that later shows the tool's output (it must not be driven by it).

## Who attacks, and how

| Attacker | Goal | Main controls |
|---|---|---|
| The author of scanned content (a contributor, a pull request, a cloned repository) | run code on the scanning machine; make the tool read or write outside the tree; make the scan miss or hide a secret; make the scan hang or exhaust memory; forge lines in the report or drive the terminal | invariants 2 to 8, 10 |
| A reader of the tool's output (CI log, SIEM, SARIF viewer, a shared report) | learn a secret from what the tool wrote | invariant 1 |
| Someone who can place a file where the tool runs (a checkout, a shared temporary directory) | have a planted program started as git; have an output written through a link | F-1, invariant 9 |

## Controls

Each heading is one invariant of CLAUDE.md section 5.

### 1. No full secret ever leaves the detection layer

**Threat.** The report itself leaks what it found (to a CI log that is public, to a SIEM, to a
terminal scrollback), or an error message echoes a line of a scanned file.

**Controls.** The secret value exists only in the internal `Match` type of `core/detect/`. Before
anything leaves that layer it becomes a redacted form (D7: a fixed public prefix, the length, an
8-hex-digit domain-separated hash) and a fingerprint (D8). `Finding` and `Report` have no field
that could hold a secret, and the architecture check forbids `render/`, `app/` and `cli/` to import
`Match`. No output carries a source line. Exceptions never carry file content, and messages built
from configuration files never echo a key or a pattern (a mistyped key can be a pasted secret).
Every rule's secret has at least 64 estimated bits, so neither hash can be guessed back.

**Tests.** `test_nothing_reachable_from_report_can_hold_a_secret`,
`test_nothing_that_scan_emits_contains_the_secret`,
`test_every_format_of_every_rule_carries_no_secret`,
`test_no_warning_is_emitted_and_none_carries_content`,
`test_nothing_that_scan_git_emits_contains_the_secret`,
`test_scan_git_in_jsonl_and_sarif_names_the_commit_and_carries_no_secret`,
`test_commit_messages_and_author_names_never_reach_an_output`,
`test_the_demo_prints_no_full_fake`, `test_hostile_content_never_reaches_the_report`,
`test_never_shows_more_than_a_quarter_or_twelve_characters`,
`test_display_hash_is_domain_separated_from_a_plain_sha256`,
`test_read_errors_name_the_errno_and_never_the_content`,
`test_refusal_message_names_reason_and_does_not_echo_the_pattern`. The leak check itself is
tested (`test_the_leak_check_itself_catches_a_leak`,
`test_failure_message_never_contains_the_secret`).

### 2. No network access

**Threat.** A scanned repository makes the tool or git contact a server (a partial clone that
fetches missing objects, a credential helper, a proxy setting), or the tool itself sends data.

**Controls.** `socket`, `ssl`, `http`, `urllib` and every other network module are banned in
`src/` by `scripts/check_architecture.py`. git runs with `protocol.allow=never`, no credential
helper, no proxy or ssh command, `GIT_NO_LAZY_FETCH=1` and `GIT_TERMINAL_PROMPT=0`
(`docs/git-hardening.md`). In the test suite every socket call fails.

**Tests.** `test_the_real_tree_passes`, `test_planted_violation_is_found`,
`test_socket_calls_fail_during_tests`,
`test_a_missing_blob_does_not_trigger_a_lazy_fetch_over_any_transport`,
`test_a_partial_clone_reports_missing_blobs_and_never_fetches`,
`test_pinned_configuration_key_by_key`,
`test_the_demo_makes_no_network_call_and_changes_no_process_state`.

### 3. Read-only on scanned content

**Threat.** A scan changes the tree or the repository: an index refresh, a lock file, garbage
collection, a hook, a report written into the tree.

**Controls.** `fs/walk.py`, the only reader of scanned files, contains no write or mutate call and
no write flag (enforced by the architecture check). git runs with `GIT_OPTIONAL_LOCKS=0`,
`--no-optional-locks`, `gc.auto=0`, `maintenance.auto=false` and only plumbing commands. `--output`
and `--write-baseline` inside the scanned tree are refused before scanning.

**Tests.** A snapshot of every path, size, content hash and modification time before and after:
`test_the_scanned_tree_is_never_changed`, `test_scanning_changes_nothing_in_the_tree`,
`test_the_scan_changes_nothing_in_the_repository` (`scan-git` and `scan --gitignore`);
`test_outputs_inside_the_scanned_tree_are_refused`,
`test_output_inside_the_repository_is_refused_before_git_runs`.

### 4. git is run only through one hardened runner

**Threat.** A repository runs a program through its configuration (`core.fsmonitor`,
`core.sshCommand`, `diff.external`, a pager, a hook, a textconv filter, a credential helper), a
revision or path argument is taken for an option, or the caller's environment redirects git.

**Controls.** `gitio/runner.py` is the only module that starts git: argument lists, never a
shell; an absolute program path; a closed set of subcommands with fixed flags; an environment
built from scratch; every execution-related configuration key pinned on the command line; user
revisions validated and resolved to object ids after `--end-of-options`; bounded output and
timeouts; a stopped process is ended by its process id. `.git` as a link or a file, alternates
and grafts are refused before git reads any object. Details and the full key lists:
`docs/git-hardening.md`.

**Tests.** `test_the_hostile_repository_really_does_fire_markers_when_git_is_not_protected` (the
control: the same repository does run its planted commands under an unprotected git),
`test_scan_git_runs_nothing_and_still_finds_the_secret`, `test_scan_gitignore_runs_nothing`,
`test_the_callers_environment_cannot_make_git_run_anything`,
`test_environment_is_exactly_the_fixed_keys_plus_path_on_posix`,
`test_the_callers_environment_is_never_inherited`, `test_the_command_set_is_closed`,
`test_free_form_arguments_cannot_reach_a_process`,
`test_resolution_uses_end_of_options_and_the_peel`,
`test_spawn_process_runs_an_argument_list_without_a_shell`,
`test_cat_file_never_filters_or_converts`, `test_replace_refs_are_ignored`,
`test_alternates_grafts_and_links_are_refused`, `test_a_gitdir_link_file_is_refused`,
`test_a_dot_git_symlink_is_refused`, `test_taskkill_command_names_a_pid_and_never_an_image`.

### 5. Names, paths, commit data and content are hostile in every output

**Threat.** A file name with a newline forges a second report line; an escape sequence drives the
terminal; a bidirectional override or a zero-width character disguises a path; a name injects URI
syntax into SARIF or breaks JSON.

**Controls.** One sanitiser (`core/sanitize.py`) escapes every control, bidirectional, zero-width
and non-printable character before any output; the models refuse display text that is not escaped;
JSON, JSONL and SARIF are ASCII only; SARIF URIs are percent-encoded per segment from the exact
path; argparse's own error messages are escaped too.

**Tests.** `test_exhaustive_sweep_over_every_code_point`, `test_ansi_sequence_cannot_survive`,
`test_newline_cannot_forge_a_second_log_line`, `test_truncation_never_cuts_an_escape_in_half`,
`test_display_text_must_be_escaped_at_construction`,
`test_a_hostile_file_name_is_inert_in_every_format`,
`test_hostile_names_are_inert_in_table_and_json`,
`test_hostile_path_names_are_inert_in_every_output`, `test_argparse_messages_are_escaped`,
`test_a_control_character_in_a_path_option_is_refused_and_not_echoed`,
`test_a_hostile_host_label_is_refused_or_escaped`,
`test_a_cp1252_console_never_crashes_the_tool`.

### 6. Everything is bounded, and a limit is never a clean result

**Threat.** A huge file, a very long line, a deep tree, millions of entries, a git process that
never ends or floods its output: memory or time exhaustion, or a scan that silently stops early
and reports "clean".

**Controls.** Every limit is a named constant in `core/limits.py`; a configuration file may lower
a limit and never raise it above its hard ceiling. Hitting a limit is a recorded issue, the run
is marked incomplete and the exit code is 4. Measured behaviour at these sizes:
`docs/performance.md`.

**Tests.** `test_constants_match_the_d18_table_in_plan_md`,
`test_overrides_refuse_raising_and_nonsense`,
`test_the_file_size_limit_is_exact_and_a_larger_file_is_never_partly_scanned`,
`test_the_entry_limit_stops_the_walk_with_a_problem`,
`test_the_depth_limit_skips_the_deeper_directory_with_a_problem`,
`test_the_total_byte_limit_stops_the_walk`,
`test_a_too_long_line_is_cut_and_reported_but_its_start_is_scanned`,
`test_the_report_cap_truncates_stops_and_marks_the_run_incomplete`,
`test_the_time_budget_stops_the_scan_with_an_issue_and_keeps_the_findings`,
`test_an_incomplete_run_exits_four_even_with_findings`,
`test_an_incomplete_run_without_findings_is_not_clean`,
`test_a_hung_short_call_is_killed_by_pid_and_is_a_time_limit`,
`test_stdout_over_the_cap_is_killed_and_is_not_a_time_limit`,
`test_stderr_over_the_cap_is_killed`, `test_a_shallow_repository_is_incomplete_unless_allowed`.

### 7. No regular expression can backtrack catastrophically

**Threat.** A crafted line makes a built-in pattern take exponential time, or a rule from a
configuration file is itself the attack.

**Controls.** Every pattern, built-in or user-supplied, is compiled only through
`core/regex_guard.py` (the only importer of `re`): a restricted grammar with bounded quantifiers,
no nested quantifiers, no ambiguity between neighbouring variable-width items, and a static cost
budget. Patterns run per line, and a line is bounded.

**Tests.** `test_pattern_is_refused_with_its_named_reason`,
`test_every_hostile_pattern_is_rejected_at_load_time`,
`test_only_compile_pattern_makes_a_guarded_pattern`,
`test_every_builtin_rule_is_within_the_guard_and_the_schema_promises`,
`test_an_extra_rule_is_checked_against_the_lowered_limits`, and the one documented wall-clock
test, `test_rule_stays_fast_on_adversarial_lines` (a tripwire for regressions; the guarantee comes
from the grammar).

### 8. Only regular files are opened; links are never followed

**Threat.** A symbolic link, junction or other reparse point leads the scan out of the tree (to
the user's keys, for example); a FIFO or device blocks the tool; reading a cloud placeholder
downloads it; a file is swapped for a link between the check and the open.

**Controls.** `fs/walk.py` examines every entry with `lstat`, opens only regular files without
following links, compares the opened file's identity with the examined one, and records
everything else as skipped. A link as the scan root is refused.

**Tests.** `test_symlinks_are_recorded_and_never_followed`, `test_a_junction_is_not_traversed`,
`test_fifos_are_recorded_and_never_opened`, `test_special_files_are_recorded_and_not_opened`,
`test_an_offline_placeholder_is_skipped_not_read`,
`test_a_file_replaced_by_a_link_before_it_is_opened_is_never_followed`,
`test_a_file_replaced_by_another_file_before_it_is_opened_is_unstable`,
`test_a_link_as_the_root_is_refused_rather_than_followed`,
`test_links_are_counted_and_never_followed`,
`test_a_submodule_entry_and_a_symlink_entry_are_skipped`.

### 9. The tool writes only its own files, safely

**Threat.** `--output` or `--write-baseline` overwrites a file the user did not mean, is written
through a planted link, or is left half-written.

**Controls.** `fs/safe_files.py` is the only writer: a temporary file in the same directory,
flushed, then published atomically; an existing file is never replaced without `--force`; a link
at the target is refused even with `--force`; an output may not be the configuration or baseline
the run reads. The demo's files are made and removed by `fs/sandbox.py` inside one directory it
created itself.

**Tests.** `test_an_existing_file_is_never_overwritten_without_force`,
`test_a_link_target_is_refused_even_with_force_and_the_link_target_is_untouched`,
`test_a_link_planted_after_the_check_is_replaced_not_followed`,
`test_a_target_created_after_the_check_is_not_clobbered_without_force`,
`test_a_failed_write_leaves_neither_temporary_nor_a_changed_target`,
`test_the_report_is_written_atomically_and_not_over_an_existing_file`,
`test_an_output_may_not_overwrite_the_configuration_or_baseline_it_reads`,
`test_the_demo_touches_no_path_outside_its_temporary_directory`,
`test_ctrl_c_removes_the_directory_too`,
`test_the_demo_output_names_no_real_path_account_or_temporary_directory`.

### 10. Configuration, rules and baselines are never discovered

**Threat.** A pull request adds a file to the tree that switches rules off, excludes its own
paths or lists its own secret's fingerprint, and the scanner picks it up by itself.

**Controls.** Configuration and baseline are read only from `--config FILE` and `--baseline FILE`;
the rules are package data. Nothing in the scanned tree, the current directory or the user's home
is looked for. All YAML goes through one strict loader: safe loading only, no aliases, tags,
merge keys or duplicate keys, a size cap before parsing, unknown keys refused.

**Tests.** `test_configuration_rules_and_baselines_are_never_discovered`,
`test_configuration_rules_and_baselines_committed_to_a_repository_are_never_discovered`,
`test_aliases_and_anchors_are_refused`, `test_explicit_tags_are_refused`,
`test_duplicate_keys_are_refused_without_naming_the_key`,
`test_oversize_input_is_refused_before_parsing`, `test_loader_never_uses_the_unsafe_apis`,
`test_malformed_configurations_are_refused`, `test_a_malformed_baseline_is_refused`.

### 11. Security checks raise; they are not `assert`

**Threat.** A check written as `assert` disappears under `python -O`.

**Controls.** `assert` is banned in `src/` by the architecture check, with `eval`, `exec`,
`pickle`, `ctypes`, `logging` and the other modules listed in CLAUDE.md section 6. The checker
fails closed: a syntax error or an unresolvable internal import is a failure.

**Tests.** `test_every_rule_has_planted_violations_and_allowed_counterexamples`,
`test_planted_violation_is_found`, `test_missing_package_fails_closed`,
`test_one_syntax_error_does_not_hide_other_violations`. The release check also runs `bandit -r
src` (`docs/phase-reports.md`, Phase 6).

### The repository itself

**Threat.** A fake secret used in a test, a doc or the demo ends up in a tracked file or in the
history, and a scanner (this one, or a hosting service's) flags the project's own repository.

**Controls.** Fakes exist only at run time, built from fragments by `core/fakes.py`, and are
written only into temporary directories. The tool's own engine scans every tracked and
untracked-not-ignored file on every gate, and the whole history in the full gate, with no
allowlist.

**Tests.** `test_repository_has_no_secret_shaped_strings`,
`test_control_catches_a_generated_fake_in_a_temporary_repository`,
`test_the_repository_history_holds_no_secret_shaped_string`,
`test_no_forbidden_characters_in_the_repository`,
`test_no_key_or_secret_files_are_tracked_or_staged`, `test_no_email_addresses_in_the_repository`.

## Residual risks (accepted, and listed in the README Limitations)

- **Detection is incomplete by nature.** Patterns and entropy miss secrets that are split,
  encoded, encrypted or simply in a format no rule knows, and report strings that are not
  secrets. A clean result is "nothing matched", not "no secret exists".
- **A baseline from the branch under test can excuse that branch's secret.** The tool cannot know
  who wrote the baseline. Review changes to the baseline file like code, or take it from the base
  branch.
- **The shown prefix, the length and the 8-hex-digit hash are visible.** They do not identify a
  secret of 64 bits or more, but they do show that a secret of a given kind exists at a place.
- **git is trusted.** The tool controls how git is started, not what git does. A git older than
  2.32 is refused; a vulnerability in git's own object parsing is outside this model.
- **Time of check to time of use.** Between resolving the git program and starting it, and
  between examining a file and opening it, the file system can change. The scanned-file case is
  detected (identity comparison); the git program case is not (see F-1, residual risk).
- **Reading can update access times** on file systems that record them. Nothing else changes.
- **Confusable characters** (a Cyrillic letter that looks like a Latin one) are printable and are
  shown as they are; only control, bidirectional and zero-width characters are escaped.
- **The development guard is not a product control.** The Claude Code hook that blocks pushes,
  tags and filtered gate runs cannot see shell aliases, variables or an encoded PowerShell
  command, and is not in force if `sh` cannot start. It protects the development process only.

## Out of scope

Verifying whether a secret is live, revoking or rotating it, rewriting history, scanning archives
or binary formats, and protecting against a user who runs the tool with hostile options on
purpose (`--git` pointing at another program, a hostile `PATH` named by absolute path).

## Findings caught by CI or review

### F-1 Windows binary planting through the current directory and relative PATH entries

Found by CI run 5 (commit `38f6979`), reported 2026-11-08. All three Windows jobs
failed in `tests/test_git_hostile.py::test_a_planted_git_program_is_never_chosen`; Linux passed.

**Attack.** A repository (or any directory the user works in) contains a program called `git.exe`.
On Windows, `CreateProcess` with a bare program name, `shutil.which` and cmd.exe all look in the
current directory before `PATH`, unless the process or the machine sets
`NoDefaultCurrentDirectoryInExePath`. An empty or relative `PATH` entry (`""`, `.`, `bin`) also
means a place under the current directory. A tool that runs `git` by name from inside a hostile
checkout would run the attacker's program with the user's rights, before any of the git
hardening in `docs/git-hardening.md` applies. `git.cmd`, `git.bat` and the other `PATHEXT` types are
worse: they run through cmd.exe or a script host.

**What was verified.** The failure was reproduced locally by removing
`NoDefaultCurrentDirectoryInExePath=1`, which this development machine sets and the CI runners
do not (which is why the local gate was green). The product's own search
(`safe_files.find_program`) was not fooled by the empty, `.` and `bin` entries: it already skipped
relative entries. The planted program ran because the *test's helper* `tests/gitrepo.py::git_binary()`
used `shutil.which("git")` after the test had changed into the directory holding the plant, was
handed `cwd\git.exe` as "the real git", and the test then passed that directory to the product as
an absolute `PATH` entry. The product accepted it: an absolute directory that is neither the
scanned tree nor a relative entry was trusted, including the current directory itself and the
system temporary directory. The attack path is real for users too: any `PATH` that names the
current directory by absolute name, or a temporary directory, would have run a planted program
(`WinError 216` was only the planted file not being a valid executable).

**Controls (D2 "Binary", PLAN.md v0.11).**

1. git is resolved once to an absolute, normalised path (`fs/safe_files.find_program`) and the
   runner starts that path, always (`GitRunner` refuses a relative one; `spawn_process` also passes
   it as `executable=`, so Windows does not parse and search for it).
2. Only fully qualified `PATH` entries are searched (`safe_files.is_absolute`): not empty, not
   `.`, not relative, and on Windows not `\dir` or `C:dir`, which depend on the current directory or
   drive (Python before 3.13 calls the first one absolute).
3. Never searched even when absolute: the scanned tree, the system temporary directory tree, and
   the current directory itself (`safe_files.search_hazards`). Below the current directory is
   allowed: a `.venv\Scripts` on `PATH` is normal, and a recursive rule would refuse a whole
   drive when the tool is started from its root.
4. On Windows only `git.exe`: never `git.cmd`, `git.bat`, `git.com`, a script type or a name
   without extension. `which`-style lookups are not used at all.
5. `--git PATH` must be fully qualified, an existing regular file, named `git.exe` on Windows,
   executable on POSIX, and outside the scanned tree. A path typed in full is the user's choice
   and is trusted anywhere else, the current directory included.
6. The test harness uses the same search (`tests/gitrepo.py::git_binary`, cached), not
   `shutil.which`.

**Tests.** `tests/test_git_hostile.py::test_a_planted_git_program_is_never_chosen` (unchanged, the
test CI caught); in `tests/test_git_program_resolution.py`:
`test_an_empty_or_relative_path_entry_is_never_searched`,
`test_a_windows_entry_that_depends_on_the_current_drive_or_directory_is_never_searched`,
`test_the_current_directory_given_as_an_absolute_entry_is_refused`,
`test_a_directory_in_the_system_temporary_tree_is_refused`,
`test_a_directory_in_the_scanned_tree_is_refused`,
`test_a_script_type_is_never_taken_for_git`,
`test_a_windows_program_without_the_exe_extension_is_never_taken_for_git`,
`test_an_explicit_relative_program_is_refused_and_never_started`,
`test_an_explicit_windows_program_must_be_called_git_exe`,
`test_an_explicit_program_inside_the_scanned_tree_is_refused` and the slow
`test_a_planted_program_that_would_run_is_never_run`: it plants a valid, harmless executable that
writes a marker file beside itself (compiled with the C# compiler that ships with Windows; a
script on POSIX), proves with a control run that the marker is written, plants copies where a
naive search finds them, and asserts the real git was chosen, every started process came from it
and no marker exists. The unit tests are in `tests/test_git_fs.py`
(`test_the_current_directory_as_an_absolute_entry_is_skipped_but_not_what_is_below`,
`test_on_windows_a_user_given_program_must_be_called_git_exe`,
`test_windows_never_takes_a_script_type_for_the_program`, `test_is_absolute_needs_a_fully_qualified_path`).

**Residual risk.** Between the check and the start of the process the file could be replaced by
someone who can write where git is installed (a time-of-check to time-of-use gap); that person can
already replace git itself. A `PATH` the user controls and set to a hostile directory by absolute
name outside the three refused places is the user's decision.

**Why the local gate missed it.** One machine setting hid it:
`NoDefaultCurrentDirectoryInExePath=1` is set in this machine's environment, so `shutil.which`
skipped the current directory here, and the CI runners do not set it. The test was added in
`ce8cf35`; run 5 is the first CI run on record that reached it. Two consequences: the
`world` fixture of `tests/test_git_program_resolution.py` removes that variable, so these tests
behave the same on every machine, and tests never resolve a program with `shutil.which` after
changing directory (`tests/gitrepo.py::git_binary` is the one resolver; the test
`test_the_test_harness_does_not_find_a_program_in_the_current_directory` pins that).
