#!/usr/bin/env python
"""Claude Code PreToolUse hook for the Bash and PowerShell tools (CLAUDE.md section 3).

Reads the hook payload (JSON) on stdin and blocks, with exit code 2 and a reason on stderr:

* any command that runs `scripts/gate.py` together with a pipe, a redirect, `|| ...`, `; true`,
  `; exit 0` or a filter (tail, head, tee, grep, findstr, Select-String, Out-File, Tee-Object,
  Out-Null and kin): the gate's exit status and output must never be filtered or masked;
* `git push`, `git tag`, `git add -A` / `--all` / `.`, `git config user.*`, and a commit command
  whose message contains a `Co-Authored-By` trailer (PLAN.md D20 option b: the machine rules are
  enforced by the tool, not only by memory).

Quoted text is data, not a command: `echo "git push"` is allowed. Input the hook cannot parse
exits 1, a non-blocking error: the hook must never wedge a session. Standard library only.
"""

from __future__ import annotations

import json
import re
import sys
from collections.abc import Sequence
from dataclasses import dataclass, field
from pathlib import Path
from typing import TextIO

EXIT_ALLOW = 0
EXIT_ERROR = 1  # non-blocking error in Claude Code's hook protocol
EXIT_BLOCK = 2

MAX_STDIN_BYTES = 4_000_000
MAX_NESTING = 4
MAX_FILE_BYTES = 65_536

GUARDED_TOOLS = frozenset({"Bash", "PowerShell"})

FILTER_COMMANDS = frozenset(
    {
        "tail",
        "head",
        "tee",
        "grep",
        "egrep",
        "fgrep",
        "rg",
        "findstr",
        "select-string",
        "select-object",
        "where-object",
        "foreach-object",
        "sort",
        "sort-object",
        "out-file",
        "tee-object",
        "out-null",
        "out-string",
        "more",
        "less",
        "sed",
        "awk",
        "cut",
        "tr",
        "wc",
        "uniq",
        "format-table",
        "format-list",
        "set-content",
        "add-content",
    }
)

_SEPARATORS = frozenset({"|", "||", "&&", "&", ";", "\n", "(", ")", "{", "}", "`"})
_SEQUENCE_SEPARATORS = frozenset({";", "&", "\n"})
_ESCAPABLE = frozenset(" \t\"'$&|;<>(){}#`\\*?")
_WRAPPERS = frozenset(
    {"env", "command", "builtin", "exec", "nohup", "time", "sudo", "call", "start", "uv", "run"}
)
_BASH_SHELLS = frozenset({"bash", "sh", "zsh", "dash", "ksh", "fish"})
_POWERSHELLS = frozenset({"pwsh", "powershell"})
_EXE_SUFFIXES = (".exe", ".cmd", ".bat", ".com")
_ASSIGNMENT = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*=")
_PYTHON = re.compile(r"^(?:python|pythonw|py|pypy)[0-9.]*$")
_GATE_PATH = re.compile(r"(?:^|/)gate\.py$", re.IGNORECASE)
_TRAILER = re.compile(r"co-authored-by\s*:", re.IGNORECASE)
_BASH_C_OPTION = re.compile(r"^-[A-Za-z]*c[A-Za-z]*$")

_GIT_OPTIONS_WITH_ARGUMENT = frozenset(
    {"-C", "-c", "--git-dir", "--work-tree", "--namespace", "--super-prefix", "--config-env"}
)
_COMMIT_LIKE = frozenset(
    {"commit", "commit-tree", "merge", "rebase", "revert", "cherry-pick", "am", "notes"}
)
_ADD_EVERYTHING_PATHSPECS = frozenset({".", "./", ".\\", ":/", "*"})


@dataclass(slots=True)
class _Lexed:
    items: list[tuple[str, str]] = field(default_factory=list)  # ("word" | "op", text)
    nested: list[str] = field(default_factory=list)  # command substitutions inside "..."


class _Lexer:
    """A small shell-and-PowerShell tokenizer. It is total (never raises) and linear."""

    def __init__(self, text: str) -> None:
        self.text = text
        self.pos = 0
        self.result = _Lexed()
        self.word: list[str] = []
        self.has_word = False
        self.heredocs: list[tuple[str, bool]] = []

    # -- helpers -----------------------------------------------------------------------------
    def _append(self, chunk: str) -> None:
        self.word.append(chunk)
        self.has_word = True

    def _flush(self) -> None:
        if self.has_word:
            self.result.items.append(("word", "".join(self.word)))
        self.word = []
        self.has_word = False

    def _operator(self, op: str) -> None:
        self._flush()
        self.result.items.append(("op", op))

    def _peek(self, offset: int = 0) -> str:
        index = self.pos + offset
        return self.text[index] if index < len(self.text) else ""

    # -- constructs --------------------------------------------------------------------------
    def _single_quoted(self) -> None:
        self.has_word = True
        self.pos += 1
        while True:
            end = self.text.find("'", self.pos)
            if end == -1:
                self.word.append(self.text[self.pos :])
                self.pos = len(self.text)
                return
            self.word.append(self.text[self.pos : end])
            self.pos = end + 1
            if self._peek() != "'":
                return
            self.word.append("'")  # PowerShell '' inside single quotes is a literal quote
            self.pos += 1

    def _substitution_end(self, start: int) -> int:
        """Index just past the `)` that closes a `$(` whose content begins at `start`."""
        depth = 1
        index = start
        while index < len(self.text):
            char = self.text[index]
            if char == "(":
                depth += 1
            elif char == ")":
                depth -= 1
                if depth == 0:
                    return index + 1
            index += 1
        return len(self.text)

    def _double_quoted_into(self, close: str | None, end_marker: str | None = None) -> None:
        """Read a double-quoted string (or an expandable here-string) into the current word.
        Command substitutions inside it execute, so their content is queued for analysis."""
        text = self.text
        self.has_word = True
        while self.pos < len(text):
            if end_marker is not None and text.startswith(end_marker, self.pos):
                self.pos += len(end_marker)
                return
            char = text[self.pos]
            if close is not None and char == close:
                self.pos += 1
                return
            if char in "\\`" and self.pos + 1 < len(text):
                follower = text[self.pos + 1]
                if follower in '"\\$`':
                    self.word.append(follower)
                    self.pos += 2
                    continue
            if char == "$" and text.startswith("$(", self.pos):
                end = self._substitution_end(self.pos + 2)
                self.result.nested.append(text[self.pos + 2 : max(end - 1, self.pos + 2)])
                self.word.append(text[self.pos : end])
                self.pos = end
                continue
            if char == "`":
                end = text.find("`", self.pos + 1)
                if end != -1:
                    self.result.nested.append(text[self.pos + 1 : end])
                    self.word.append(text[self.pos : end + 1])
                    self.pos = end + 1
                    continue
            self.word.append(char)
            self.pos += 1

    def _here_string(self) -> bool:
        quote = self._peek(1)
        if quote not in {"'", '"'} or self._peek(2) not in {"\r", "\n"}:
            return False
        marker = "\n" + quote + "@"
        self.has_word = True
        self.pos += 2
        if quote == '"':
            self._double_quoted_into(None, end_marker=marker)
            return True
        end = self.text.find(marker, self.pos)
        if end == -1:
            self.pos = len(self.text)
        else:
            self.word.append(self.text[self.pos : end])
            self.pos = end + len(marker)
        return True

    def _backslash(self) -> None:
        follower = self._peek(1)
        if follower == "\n":
            self.pos += 2
        elif follower == "\r" and self._peek(2) == "\n":
            self.pos += 3
        elif follower and follower in _ESCAPABLE:
            self._append(follower)
            self.pos += 2
        else:
            self._append("\\")
            self.pos += 1

    def _heredoc_start(self) -> None:
        """At `<<`: record the delimiter; the body is skipped at the next newline."""
        index = self.pos + 2
        strip_tabs = False
        if index < len(self.text) and self.text[index] == "-":
            strip_tabs = True
            index += 1
        while index < len(self.text) and self.text[index] in " \t":
            index += 1
        delimiter: list[str] = []
        quote = self.text[index] if index < len(self.text) else ""
        if quote in {"'", '"'}:
            index += 1
            while index < len(self.text) and self.text[index] != quote:
                delimiter.append(self.text[index])
                index += 1
            index += 1
        else:
            while index < len(self.text) and self.text[index] not in " \t\r\n;|&<>()":
                delimiter.append(self.text[index])
                index += 1
        if delimiter:
            self.heredocs.append(("".join(delimiter), strip_tabs))
        self.pos = index
        self._operator("<")

    def _skip_heredoc_bodies(self) -> None:
        for delimiter, strip_tabs in self.heredocs:
            while self.pos < len(self.text):
                end = self.text.find("\n", self.pos)
                line_end = len(self.text) if end == -1 else end
                line = self.text[self.pos : line_end].rstrip("\r")
                self.pos = len(self.text) if end == -1 else end + 1
                if (line.lstrip("\t") if strip_tabs else line) == delimiter:
                    break
        self.heredocs = []

    # -- main loop ---------------------------------------------------------------------------
    def run(self) -> _Lexed:
        text = self.text
        while self.pos < len(text):
            char = text[self.pos]
            if char in " \t\r":
                self._flush()
                self.pos += 1
            elif char == "\n":
                self._operator("\n")
                self.pos += 1
                self._skip_heredoc_bodies()
            elif char == "#" and not self.has_word:
                end = text.find("\n", self.pos)
                self.pos = len(text) if end == -1 else end
            elif char == "'":
                self._single_quoted()
            elif char == '"':
                self.pos += 1
                self._double_quoted_into('"')
            elif char == "@" and not self.has_word and self._here_string():
                continue
            elif char == "$" and self._peek(1) == "(":
                self._operator("(")
                self.pos += 2
            elif char == "\\":
                self._backslash()
            elif char == "`":
                if self._peek(1) == "\n":
                    self.pos += 2
                else:
                    self._operator("`")
                    self.pos += 1
            elif char == "<":
                if text.startswith("<<<", self.pos):
                    self._operator("<")
                    self.pos += 3
                elif text.startswith("<<", self.pos):
                    self._heredoc_start()
                else:
                    self._operator("<")
                    self.pos += 1
            elif char in "|&>":
                double = char + char
                if char != ">" and text.startswith(double, self.pos):
                    self._operator(double)
                    self.pos += 2
                elif char == ">" and text.startswith(">>", self.pos):
                    self._operator(">>")
                    self.pos += 2
                else:
                    self._operator(char)
                    self.pos += 1
            elif char in ";(){}":
                self._operator(char)
                self.pos += 1
            else:
                self._append(char)
                self.pos += 1
        self._flush()
        return self.result


@dataclass(slots=True)
class _Segment:
    words: list[str]
    sep_before: str


@dataclass(slots=True)
class _Parsed:
    segments: list[_Segment] = field(default_factory=list)
    ops: set[str] = field(default_factory=set)


def _program_name(word: str) -> str:
    name = re.split(r"[\\/]", word)[-1].lower()
    for suffix in _EXE_SUFFIXES:
        if name.endswith(suffix):
            return name[: -len(suffix)]
    return name


def _program_index(words: Sequence[str]) -> int | None:
    """Index of the word that names the program, skipping assignments and wrappers."""
    index = 0
    while index < len(words):
        word = words[index]
        if _ASSIGNMENT.match(word):
            index += 1
        elif _program_name(word) in _WRAPPERS:
            index += 1
            while index < len(words) and words[index].startswith("-"):
                index += 1
        else:
            return index
    return None


def _split(items: Sequence[tuple[str, str]], parsed: _Parsed) -> None:
    current: list[str] = []
    separator = ""
    for kind, value in items:
        if kind == "word":
            current.append(value)
            continue
        parsed.ops.add(value)
        if value in _SEPARATORS:
            if current:
                parsed.segments.append(_Segment(current, separator))
                current = []
            separator = value
    if current:
        parsed.segments.append(_Segment(current, separator))


def _command_string_of(program: str, rest: Sequence[str]) -> str | None:
    """The command text a shell-like program is asked to run, when it is given one."""
    if program in _BASH_SHELLS:
        for index, word in enumerate(rest):
            if _BASH_C_OPTION.match(word) and index + 1 < len(rest):
                return rest[index + 1]
        return None
    lowered = [word.lower() for word in rest]
    if program in _POWERSHELLS:
        for index, word in enumerate(lowered):
            if word in {"-c", "-command"} and index + 1 < len(rest):
                return " ".join(rest[index + 1 :])
        return None
    if program == "cmd":
        for index, word in enumerate(lowered):
            if word in {"/c", "/k", "/r"} and index + 1 < len(rest):
                return " ".join(rest[index + 1 :])
        return None
    if program in {"invoke-expression", "iex"} and rest:
        return " ".join(rest)
    return None


def _wsl_command(rest: Sequence[str]) -> list[str]:
    """The command words that follow wsl's own options."""
    index = 0
    while index < len(rest):
        word = rest[index]
        if word in {"-e", "--exec", "--"}:
            return list(rest[index + 1 :])
        if word in {"-d", "--distribution", "-u", "--user", "--cd"}:
            index += 2
        elif word.startswith("-"):
            index += 1
        else:
            return list(rest[index:])
    return []


def _expand(words: list[str], parsed: _Parsed, depth: int) -> None:
    """Add the commands nested inside a segment (shell -c strings, wsl, iex)."""
    if depth >= MAX_NESTING:
        return
    index = _program_index(words)
    if index is None:
        return
    program = _program_name(words[index])
    rest = words[index + 1 :]
    if program == "wsl":
        inner = _wsl_command(rest)
        if inner:
            parsed.segments.append(_Segment(inner, ";"))
            _expand(inner, parsed, depth + 1)
        return
    command = _command_string_of(program, rest)
    if command is not None:
        _merge(command, parsed, depth + 1)


def _merge(command: str, parsed: _Parsed, depth: int) -> None:
    if depth > MAX_NESTING:
        return
    lexed = _Lexer(command).run()
    before = len(parsed.segments)
    _split(lexed.items, parsed)
    for segment in list(parsed.segments[before:]):
        _expand(segment.words, parsed, depth)
    for nested in lexed.nested:
        _merge(nested, parsed, depth + 1)


def parse_command(command: str) -> _Parsed:
    parsed = _Parsed()
    _merge(command, parsed, 0)
    return parsed


def _is_gate_token(word: str) -> bool:
    normalized = word.replace("\\", "/")
    return bool(_GATE_PATH.search(normalized)) or normalized.lower() == "scripts.gate"


def _runs_gate(words: Sequence[str]) -> bool:
    """True when this command line runs scripts/gate.py: a Python interpreter (possibly behind
    wrappers) with the script among its arguments, or the script executed directly."""
    for index, word in enumerate(words):
        if _is_gate_token(word) and all(_is_launcher_prefix(w) for w in words[:index]):
            return True  # executed directly, or `python -m scripts.gate` handled below
        if _PYTHON.match(_program_name(word)):
            if not all(_is_launcher_prefix(w) for w in words[:index]):
                return False
            return any(_is_gate_token(other) for other in words[index + 1 :])
    return False


def _is_launcher_prefix(word: str) -> bool:
    return (
        bool(_ASSIGNMENT.match(word))
        or _program_name(word) in _WRAPPERS
        or word.startswith("-")
        or word[:1].isdigit()
    )


def _gate_reasons(parsed: _Parsed) -> list[str]:
    if not any(_runs_gate(segment.words) for segment in parsed.segments):
        return []
    reasons: list[str] = []
    if "|" in parsed.ops:
        reasons.append("a pipe")
    if "||" in parsed.ops:
        reasons.append("`||` (it can mask the gate's exit status)")
    if parsed.ops & {">", ">>"}:
        reasons.append("a redirect")
    for segment in parsed.segments:
        index = _program_index(segment.words)
        if index is None:
            continue
        program = _program_name(segment.words[index])
        arguments = segment.words[index + 1 :]
        if program in FILTER_COMMANDS:
            reasons.append(f"the filter `{program}`")
        if segment.sep_before in _SEQUENCE_SEPARATORS:
            if program in {"true", ":", "$true"}:
                reasons.append(f"`; {program}` (it masks the gate's exit status)")
            elif program == "exit" and (not arguments or arguments[0] == "0"):
                reasons.append("`; exit 0` (it masks the gate's exit status)")
    return reasons


def _git_subcommand(arguments: Sequence[str]) -> tuple[str | None, list[str]]:
    index = 0
    while index < len(arguments):
        word = arguments[index]
        if word in _GIT_OPTIONS_WITH_ARGUMENT:
            index += 2
        elif word.startswith("-"):
            index += 1
        else:
            return word.lower(), list(arguments[index + 1 :])
    return None, []


def _add_everything(arguments: Sequence[str]) -> bool:
    for word in arguments:
        if word in {"--all"} or word in _ADD_EVERYTHING_PATHSPECS:
            return True
        if word.startswith("-") and not word.startswith("--") and "A" in word[1:]:
            return True
    return False


def _message_files(arguments: Sequence[str], cwd: Path | None) -> list[str]:
    """Texts of files given with -F/--file (best effort, bounded, never raises)."""
    paths: list[str] = []
    for index, word in enumerate(arguments):
        if word in {"-F", "--file"} and index + 1 < len(arguments):
            paths.append(arguments[index + 1])
        elif word.startswith("--file="):
            paths.append(word[len("--file=") :])
    texts: list[str] = []
    for name in paths:
        if name == "-":
            continue
        candidate = Path(name)
        if cwd is not None and not candidate.is_absolute():
            candidate = cwd / candidate
        try:
            with candidate.open("rb") as handle:
                texts.append(handle.read(MAX_FILE_BYTES).decode("utf-8", errors="replace"))
        except OSError:
            continue
    return texts


def _git_reasons(parsed: _Parsed, raw_command: str, cwd: Path | None) -> list[str]:
    reasons: list[str] = []
    for segment in parsed.segments:
        index = _program_index(segment.words)
        if index is None or _program_name(segment.words[index]) != "git":
            continue
        subcommand, arguments = _git_subcommand(segment.words[index + 1 :])
        if subcommand == "push":
            reasons.append("`git push`: pushing is done by the owner")
        elif subcommand == "tag":
            reasons.append("`git tag`: tagging is done by the owner")
        elif subcommand == "add" and _add_everything(arguments):
            reasons.append("`git add -A` / `--all` / `.`: stage files by explicit path only")
        elif subcommand == "config" and any(
            not word.startswith("-") and word.lower().startswith("user.") for word in arguments
        ):
            reasons.append("`git config user.*`: the git identity is never touched")
        elif subcommand in _COMMIT_LIKE:
            texts = [raw_command, *_message_files(arguments, cwd)]
            if any(_TRAILER.search(text) for text in texts):
                reasons.append("a Co-Authored-By trailer in a commit message")
    return reasons


def evaluate(command: str, cwd: Path | None = None) -> list[str]:
    """Return the reasons this command must be blocked (empty: allowed)."""
    parsed = parse_command(command)
    reasons = _gate_reasons(parsed)
    if reasons:
        reasons = [f"gate.py must run alone, without {reason}" for reason in reasons]
    reasons.extend(_git_reasons(parsed, command, cwd))
    return list(dict.fromkeys(reasons))


def _read_payload(stdin: TextIO | None) -> object:
    if stdin is not None:
        raw = stdin.read()
    else:
        raw = sys.stdin.buffer.read(MAX_STDIN_BYTES).decode("utf-8")
    return json.loads(raw)


def main(stdin: TextIO | None = None, stderr: TextIO | None = None) -> int:
    err = stderr if stderr is not None else sys.stderr
    try:
        payload = _read_payload(stdin)
    except (OSError, ValueError) as error:  # includes JSON and Unicode decoding errors
        print(f"guard_gate: unreadable hook input ({type(error).__name__})", file=err)
        return EXIT_ERROR
    if not isinstance(payload, dict):
        print("guard_gate: hook input is not a JSON object", file=err)
        return EXIT_ERROR
    tool_name = payload.get("tool_name")
    if not isinstance(tool_name, str):
        print("guard_gate: hook input has no tool_name", file=err)
        return EXIT_ERROR
    if tool_name not in GUARDED_TOOLS:
        return EXIT_ALLOW
    tool_input = payload.get("tool_input")
    command = tool_input.get("command") if isinstance(tool_input, dict) else None
    if not isinstance(command, str):
        print("guard_gate: hook input has no command string", file=err)
        return EXIT_ERROR
    cwd_value = payload.get("cwd")
    cwd = Path(cwd_value) if isinstance(cwd_value, str) and cwd_value else None
    reasons = evaluate(command, cwd)
    if not reasons:
        return EXIT_ALLOW
    print("guard_gate: BLOCKED. " + "; ".join(reasons) + ".", file=err)
    print("See CLAUDE.md section 3 (gate rules) and section 1 (machine rules).", file=err)
    return EXIT_BLOCK


if __name__ == "__main__":  # pragma: no cover - exercised by the subprocess tests
    sys.exit(main())
