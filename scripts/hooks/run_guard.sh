#!/bin/sh
# Launcher of the PreToolUse hook (CLAUDE.md section 3, "Hook launcher").
#
# guard_gate.py is standard-library only, so it needs a Python 3.10 or newer, not the project's
# .venv. The first interpreter that runs is used, in this order:
#   1. `py -3` (the Windows launcher), 2. `python3`, 3. `python`, 4. the project venv.
# If none runs, the command is BLOCKED (exit 2) with a message. Exit 2 is deliberate: in Claude
# Code's hook protocol every other failing exit code (a missing file is 127) is a non-blocking
# error, which would silently turn the guard into "allow everything".
#
# Only POSIX sh builtins are used, so this also works when PATH holds nothing useful.

case $0 in
    */*) here=${0%/*} ;;
    *) here=. ;;
esac
hook="$here/guard_gate.py"

# True when "$@" starts a Python that is new enough. Python's own exit status is the answer; the
# Microsoft Store stub on Windows, a missing command and an old Python all fail here.
usable() {
    "$@" -c 'import sys; sys.exit(0 if sys.version_info >= (3, 10) else 1)' >/dev/null 2>&1
}

# shellcheck disable=SC2086  # "py -3" must split into two words
for candidate in "py -3" python3 python; do
    if usable $candidate; then
        exec $candidate "$hook"
    fi
done

for candidate in "$here/../../.venv/Scripts/python.exe" "$here/../../.venv/bin/python"; do
    if usable "$candidate"; then
        exec "$candidate" "$hook"
    fi
done

{
    echo "guard_gate: BLOCKED. No usable Python 3.10+ was found for the PreToolUse hook"
    echo "(tried: py -3, python3, python, .venv). Every Bash and PowerShell command is refused"
    echo "until one exists: install Python 3.10+ or create the project venv"
    echo "(uv venv --python 3.13 .venv). See CLAUDE.md section 3, \"Hook launcher\"."
} >&2
exit 2
