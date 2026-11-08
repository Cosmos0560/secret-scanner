# Threat model

Status: started in Phase 4 with the findings that real runs produced. Phase 6 (PLAN.md section 4)
completes it: assets, trust boundaries, every control against CLAUDE.md section 5, and the
residual risks. Controls named here have tests, and a drift test
(`tests/test_git_hardening_doc.py::test_every_test_named_in_the_threat_model_exists`) fails when a
named test is renamed or removed.

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
