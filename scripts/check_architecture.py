#!/usr/bin/env python
"""Architecture checker for src/secret_scanner (CLAUDE.md section 6). Fails closed.

Rules (each has a stable id; see RULES): layering and same-layer imports, import cycles,
file system / subprocess / network default-deny, `re`, `yaml`, `importlib` and `time`
restrictions, banned APIs, and import restrictions for `Match` and the demo sandbox.

Usage: python scripts/check_architecture.py [--root DIR]
Exit status: 0 clean, 1 violations found, 2 the checker itself failed.
"""

from __future__ import annotations

import argparse
import ast
import fnmatch
import sys
from collections.abc import Iterable, Mapping, Sequence
from dataclasses import dataclass
from pathlib import Path

PACKAGE = "secret_scanner"
ROOT_NAME = ""  # the package's own __init__.py
MAIN_NAME = "__main__"

RULES: dict[str, str] = {
    "no-package": "the source package directory is missing",
    "syntax": "a source file cannot be read or parsed (fails closed)",
    "unknown-package": "a module is outside every known layer",
    "unresolved-import": "an internal import names a module that does not exist",
    "layer": "a module imports from a higher layer",
    "same-layer": "a same-layer import that the checker does not list",
    "cycle": "an import cycle",
    "core-pure": "core/ imports an I/O, OS, sys or time module",
    "fs": "file system access outside fs/walk.py, fs/safe_files.py and fs/sandbox.py",
    "walk-write": "fs/walk.py uses a write or mutate API",
    "subprocess": "subprocess outside gitio/runner.py and gitio/demo_git.py",
    "threading": "threading outside gitio/runner.py",
    "os-exec": "os.system, os.popen, os.exec*, os.spawn*, os.startfile or pty",
    "network": "a network module or third-party HTTP client",
    "re": "re outside core/regex_guard.py",
    "yaml": "yaml or importlib outside services/loader.py",
    "yaml-unsafe": "yaml.load, unsafe_load or full_load",
    "time": "time, datetime.now or sleep outside host/clock.py",
    "banned-module": "logging, random, pickle, marshal, shelve or ctypes",
    "banned-builtin": "eval, exec, compile or __import__",
    "print": "print outside cli/",
    "assert": "assert statement (security checks raise explicitly)",
    "platform": "os.name or platform.system instead of a sys.platform guard",
    "match": "Match imported outside core/detect, core/findings and services/*_scanner",
    "sandbox": "fs/sandbox or gitio/demo_git imported outside app/demo",
}

# Layers, low to high (PLAN.md section 1). A top-level package name maps to its layer.
LAYERS: Mapping[str, int] = {
    "core": 0,
    "fs": 1,
    "gitio": 1,
    "host": 1,
    "render": 1,
    "services": 2,
    "app": 3,
    "cli": 4,
}

# Same-layer imports that are allowed, by importing module. Everything else at the same layer is
# refused. Extend this table deliberately when a phase adds a module.
SAME_LAYER_ALLOWED: Mapping[str, frozenset[str]] = {
    "__main__": frozenset({"cli.main"}),
    "core.sanitize": frozenset(),
    "core.errors": frozenset({"core.sanitize"}),
    "core.limits": frozenset({"core.errors"}),
    "core.models": frozenset({"core.regex_guard", "core.sanitize"}),
    "core.pathrules": frozenset({"core.errors", "core.limits", "core.sanitize"}),
    "core.redact": frozenset({"core.errors", "core.models"}),
    "core.fingerprint": frozenset(),
    "core.clock": frozenset(),
    "core.checksums": frozenset(),
    "core.regex_guard": frozenset({"core.errors", "core.limits"}),
    "core.fakes": frozenset({"core.checksums", "core.models"}),
    "core.rules": frozenset(
        {
            "core.errors",
            "core.fakes",
            "core.limits",
            "core.models",
            "core.redact",
            "core.regex_guard",
        }
    ),
    "core.lines": frozenset(),
    "core.globs": frozenset({"core.errors", "core.limits", "core.sanitize"}),
    "core.suppress": frozenset(
        {"core.errors", "core.globs", "core.limits", "core.models", "core.rules"}
    ),
    "core.findings": frozenset(
        {"core.detect.match", "core.fingerprint", "core.models", "core.redact"}
    ),
    "core.detect.match": frozenset({"core.models"}),
    "core.detect.prefilter": frozenset(),
    "core.detect.entropy": frozenset(
        {
            "core.detect.match",
            "core.errors",
            "core.limits",
            "core.lines",
            "core.models",
            "core.redact",
            "core.regex_guard",
            "core.rules",
        }
    ),
    "core.detect.rule_detector": frozenset(
        {
            "core.checksums",
            "core.detect.entropy",
            "core.detect.match",
            "core.detect.prefilter",
            "core.lines",
            "core.models",
        }
    ),
    "core.detect.private_key": frozenset(
        {
            "core.detect.match",
            "core.limits",
            "core.lines",
            "core.models",
            "core.regex_guard",
            "core.rules",
        }
    ),
    "core.detect.engine": frozenset(
        {
            "core.detect.entropy",
            "core.detect.match",
            "core.detect.prefilter",
            "core.detect.private_key",
            "core.detect.rule_detector",
            "core.limits",
            "core.lines",
            "core.models",
        }
    ),
    "core.gitparse": frozenset({"core.errors", "core.sanitize"}),
    "services.loader": frozenset(),
    "services.config": frozenset({"services.loader"}),
    "services.git_scanner": frozenset({"services.fs_scanner"}),
    "app.scan": frozenset({"app.common"}),
    "app.scan_git": frozenset({"app.common"}),
    "cli.main": frozenset(),
}

FS_MODULES = frozenset({"fs.walk", "fs.safe_files", "fs.sandbox"})

CORE_PURITY_ROOTS = frozenset(
    {"os", "sys", "io", "pathlib", "time", "shutil", "tempfile", "glob", "subprocess"}
)

NETWORK_ROOTS = frozenset(
    {
        "socket",
        "ssl",
        "http",
        "urllib",
        "ftplib",
        "smtplib",
        "poplib",
        "imaplib",
        "nntplib",
        "telnetlib",
        "xmlrpc",
        "socketserver",
        "asyncio",
        "webbrowser",
        "multiprocessing",
        "requests",
        "httpx",
        "aiohttp",
        "urllib3",
        "httplib2",
        "pycurl",
        "websockets",
        "websocket",
        "paramiko",
    }
)

OS_FILE_FUNCTIONS = frozenset(
    {
        "open",
        "remove",
        "unlink",
        "rmdir",
        "removedirs",
        "rename",
        "renames",
        "replace",
        "mkdir",
        "makedirs",
        "listdir",
        "scandir",
        "walk",
        "fwalk",
        "stat",
        "lstat",
        "fstat",
        "chmod",
        "chown",
        "lchown",
        "link",
        "symlink",
        "readlink",
        "truncate",
        "ftruncate",
        "utime",
        "fsync",
        "fdopen",
        "mkfifo",
        "mknod",
        "access",
        "read",
        "write",
        "pread",
        "pwrite",
        "sendfile",
        "getcwd",
        "chdir",
        "chroot",
    }
)
OS_PATH_FILE_FUNCTIONS = frozenset(
    {
        "exists",
        "lexists",
        "isfile",
        "isdir",
        "islink",
        "ismount",
        "getsize",
        "getmtime",
        "getatime",
        "getctime",
        "samefile",
        "sameopenfile",
        "samestat",
        "realpath",
        "abspath",
        "expanduser",
        "expandvars",
    }
)
IO_FILE_FUNCTIONS = frozenset({"io.open", "io.FileIO", "io.open_code"})

WALK_WRITE_OS_FUNCTIONS = frozenset(
    {
        "write",
        "pwrite",
        "remove",
        "unlink",
        "rmdir",
        "removedirs",
        "rename",
        "renames",
        "replace",
        "mkdir",
        "makedirs",
        "chmod",
        "chown",
        "lchown",
        "link",
        "symlink",
        "truncate",
        "ftruncate",
        "utime",
        "fsync",
        "fdatasync",
        "mkfifo",
        "mknod",
        "umask",
    }
)
WALK_WRITE_FLAGS = frozenset(
    {"O_WRONLY", "O_RDWR", "O_CREAT", "O_TRUNC", "O_APPEND", "O_EXCL", "O_TMPFILE"}
)
WALK_WRITE_ATTRIBUTES = frozenset(
    {
        "write",
        "write_text",
        "write_bytes",
        "mkdir",
        "touch",
        "unlink",
        "rmdir",
        "rename",
        "symlink_to",
        "hardlink_to",
        "chmod",
        "truncate",
    }
)
WALK_FORBIDDEN_IMPORTS = frozenset({"shutil", "tempfile"})

OS_EXEC_EXACT = frozenset({"os.system", "os.popen", "os.startfile", "os.fork", "os.forkpty"})
OS_EXEC_PREFIXES = ("os.exec", "os.spawn", "os.posix_spawn")
YAML_UNSAFE = frozenset(
    {
        "yaml.load",
        "yaml.load_all",
        "yaml.unsafe_load",
        "yaml.unsafe_load_all",
        "yaml.full_load",
        "yaml.full_load_all",
    }
)
DATETIME_NOW = frozenset(
    {
        "datetime.datetime.now",
        "datetime.datetime.utcnow",
        "datetime.datetime.today",
        "datetime.date.today",
    }
)
PLATFORM_BANNED = frozenset({"os.name", "platform.system"})
BANNED_BUILTINS = frozenset({"eval", "exec", "compile", "__import__"})

MATCH_MODULE = "core.detect.match"
MATCH_IMPORTER_PATTERNS = ("core.detect.*", "core.findings", "services.*_scanner")
SANDBOX_MODULES = frozenset({"fs.sandbox", "gitio.demo_git"})
SANDBOX_IMPORTERS = frozenset({"app.demo"})


@dataclass(frozen=True, slots=True)
class ModuleBan:
    """Importing any of `roots` (or a submodule) is a violation unless the importer is allowed."""

    rule: str
    roots: frozenset[str]
    allowed: frozenset[str]


MODULE_BANS: tuple[ModuleBan, ...] = (
    ModuleBan(
        "subprocess", frozenset({"subprocess"}), frozenset({"gitio.runner", "gitio.demo_git"})
    ),
    ModuleBan("threading", frozenset({"threading", "_thread"}), frozenset({"gitio.runner"})),
    ModuleBan("os-exec", frozenset({"pty"}), frozenset()),
    ModuleBan("network", NETWORK_ROOTS, frozenset()),
    ModuleBan("re", frozenset({"re"}), frozenset({"core.regex_guard"})),
    ModuleBan("yaml", frozenset({"yaml", "importlib"}), frozenset({"services.loader"})),
    ModuleBan("time", frozenset({"time"}), frozenset({"host.clock"})),
    ModuleBan("fs", frozenset({"pathlib", "shutil", "tempfile", "glob"}), FS_MODULES),
    ModuleBan(
        "banned-module",
        frozenset({"logging", "random", "pickle", "marshal", "shelve", "ctypes"}),
        frozenset(),
    ),
)


@dataclass(frozen=True, slots=True)
class Violation:
    rule: str
    path: str
    line: int
    message: str

    def format(self) -> str:
        return f"{self.path}:{self.line}: [{self.rule}] {self.message}"


@dataclass(frozen=True, slots=True)
class ImportRef:
    line: int
    module: str  # absolute dotted module name
    names: tuple[str, ...]  # names of a from-import (empty for a plain import)


@dataclass(slots=True)
class ModuleInfo:
    name: str  # dotted name relative to the package; "" for the package root
    rel_path: str
    is_package: bool
    tree: ast.Module | None


def module_name(parts: Sequence[str]) -> str:
    """Dotted module name for path parts relative to the package directory."""
    *directories, filename = parts
    stem = filename[: -len(".py")]
    if stem == "__init__":
        return ".".join(directories)
    return ".".join([*directories, stem])


def layer_of(name: str) -> int | None:
    if name == ROOT_NAME:
        return 0
    if name == MAIN_NAME:
        return 4
    return LAYERS.get(name.split(".")[0])


def _load_modules(package_dir: Path, project_root: Path, out: list[Violation]) -> list[ModuleInfo]:
    modules: list[ModuleInfo] = []
    for path in sorted(package_dir.rglob("*.py")):
        relative = path.relative_to(package_dir)
        rel_path = path.relative_to(project_root).as_posix()
        tree: ast.Module | None
        try:
            tree = ast.parse(path.read_text(encoding="utf-8"), filename=rel_path)
        except (OSError, SyntaxError, ValueError, RecursionError, MemoryError) as error:
            out.append(Violation("syntax", rel_path, 1, f"cannot parse: {type(error).__name__}"))
            tree = None
        modules.append(
            ModuleInfo(
                name=module_name(relative.parts),
                rel_path=rel_path,
                is_package=path.name == "__init__.py",
                tree=tree,
            )
        )
    return modules


def _absolute_module(info: ModuleInfo, node: ast.ImportFrom) -> str | None:
    """Absolute dotted module of a from-import; None when a relative import leaves the package."""
    if node.level == 0:
        return node.module or ""
    here = PACKAGE + (f".{info.name}" if info.name else "")
    base = here if info.is_package else here.rpartition(".")[0]
    for _ in range(node.level - 1):
        base = base.rpartition(".")[0]
    if base != PACKAGE and not base.startswith(PACKAGE + "."):
        return None
    return base + (f".{node.module}" if node.module else "")


def _collect_imports(info: ModuleInfo, tree: ast.Module, out: list[Violation]) -> list[ImportRef]:
    refs: list[ImportRef] = []
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            refs.extend(ImportRef(node.lineno, alias.name, ()) for alias in node.names)
        elif isinstance(node, ast.ImportFrom):
            module = _absolute_module(info, node)
            if module is None:
                out.append(
                    Violation(
                        "unresolved-import",
                        info.rel_path,
                        node.lineno,
                        "relative import leaves the package",
                    )
                )
                continue
            refs.append(ImportRef(node.lineno, module, tuple(alias.name for alias in node.names)))
    return refs


def _aliases(info: ModuleInfo, tree: ast.Module) -> dict[str, str]:
    """Map local names to the fully qualified names they were imported as."""
    aliases: dict[str, str] = {}
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for alias in node.names:
                if alias.asname:
                    aliases[alias.asname] = alias.name
                else:
                    top = alias.name.split(".")[0]
                    aliases[top] = top
        elif isinstance(node, ast.ImportFrom):
            module = _absolute_module(info, node)
            if module is None:
                continue
            for alias in node.names:
                if alias.name != "*":
                    aliases[alias.asname or alias.name] = f"{module}.{alias.name}"
    return aliases


def _qualified(node: ast.AST, aliases: Mapping[str, str]) -> str | None:
    if isinstance(node, ast.Name):
        return aliases.get(node.id)
    if isinstance(node, ast.Attribute):
        base = _qualified(node.value, aliases)
        return None if base is None else f"{base}.{node.attr}"
    return None


def _may_import_match(importer: str) -> bool:
    return any(fnmatch.fnmatchcase(importer, pattern) for pattern in MATCH_IMPORTER_PATTERNS)


def _is_internal(module: str) -> bool:
    return module == PACKAGE or module.startswith(PACKAGE + ".")


def _matches_root(module: str, roots: Iterable[str]) -> bool:
    return any(module == root or module.startswith(root + ".") for root in roots)


def _is_fs_qualified(qualified: str) -> bool:
    if qualified in IO_FILE_FUNCTIONS:
        return True
    if qualified.startswith("os.path."):
        return qualified[len("os.path.") :] in OS_PATH_FILE_FUNCTIONS
    if qualified.startswith("os."):
        return qualified[len("os.") :] in OS_FILE_FUNCTIONS
    return False


def _is_walk_write_qualified(qualified: str) -> bool:
    if qualified == "io.open":
        return True
    if qualified.startswith("os."):
        tail = qualified[len("os.") :]
        return tail in WALK_WRITE_OS_FUNCTIONS or tail in WALK_WRITE_FLAGS
    return False


class _Checker:
    def __init__(self, modules: Sequence[ModuleInfo]) -> None:
        self.modules = modules
        self.names = {module.name for module in modules}
        self.violations: list[Violation] = []
        # module -> {target module -> first line}, for cycle detection
        self.graph: dict[str, dict[str, int]] = {module.name: {} for module in modules}

    def report(self, rule: str, info: ModuleInfo, line: int, message: str) -> None:
        self.violations.append(Violation(rule, info.rel_path, line, message))

    # -- imports -----------------------------------------------------------------------------
    def _targets(self, ref: ImportRef) -> list[str] | None:
        """Internal modules a reference points at, or None when it names nothing that exists."""
        relative = "" if ref.module == PACKAGE else ref.module[len(PACKAGE) + 1 :]
        if relative and relative not in self.names:
            return None
        found: list[str] = []
        for name in ref.names:
            candidate = f"{relative}.{name}" if relative else name
            if name != "*" and candidate in self.names:
                found.append(candidate)
        return found or [relative]

    def _check_module_bans(self, info: ModuleInfo, ref: ImportRef) -> None:
        for ban in MODULE_BANS:
            if _matches_root(ref.module, ban.roots) and info.name not in ban.allowed:
                self.report(ban.rule, info, ref.line, f"import of {ref.module} is not allowed here")
        if layer_of(info.name) == 0 and _matches_root(ref.module, CORE_PURITY_ROOTS):
            self.report("core-pure", info, ref.line, f"core/ must not import {ref.module}")
        if info.name == "fs.walk" and _matches_root(ref.module, WALK_FORBIDDEN_IMPORTS):
            self.report("walk-write", info, ref.line, f"fs/walk.py must not import {ref.module}")

    def _check_internal(self, info: ModuleInfo, ref: ImportRef) -> None:
        targets = self._targets(ref)
        if targets is None:
            self.report("unresolved-import", info, ref.line, f"{ref.module} does not exist")
            return
        source_layer = layer_of(info.name)
        for target in targets:
            self._record_edge(info, target, ref.line)
            target_layer = layer_of(target)
            if source_layer is not None and target_layer is not None and target != info.name:
                self._check_layers(info, target, source_layer, target_layer, ref.line)
            names_match = target == MATCH_MODULE or "Match" in ref.names
            if names_match and not _may_import_match(info.name):
                self.report("match", info, ref.line, "Match may not be imported here")
            if target in SANDBOX_MODULES and info.name not in SANDBOX_IMPORTERS:
                self.report("sandbox", info, ref.line, f"{target} may not be imported here")

    def _record_edge(self, info: ModuleInfo, target: str, line: int) -> None:
        if target != ROOT_NAME and target in self.graph:
            self.graph[info.name].setdefault(target, line)

    def _check_layers(
        self, info: ModuleInfo, target: str, source_layer: int, target_layer: int, line: int
    ) -> None:
        if target_layer > source_layer:
            self.report("layer", info, line, f"layer {source_layer} imports layer {target_layer}")
            return
        if target_layer < source_layer or target == ROOT_NAME:
            return
        is_ancestor = info.name.startswith(target + ".")
        if not is_ancestor and target not in SAME_LAYER_ALLOWED.get(info.name, frozenset()):
            self.report("same-layer", info, line, f"{info.name} may not import {target}")

    # -- syntax tree -------------------------------------------------------------------------
    def _check_qualified(self, info: ModuleInfo, qualified: str, line: int) -> None:
        if qualified in OS_EXEC_EXACT or qualified.startswith(OS_EXEC_PREFIXES):
            self.report("os-exec", info, line, f"{qualified} starts a program")
        if qualified in YAML_UNSAFE:
            self.report("yaml-unsafe", info, line, f"{qualified} is not a safe loader")
        if qualified in PLATFORM_BANNED:
            self.report("platform", info, line, f"{qualified}: use a sys.platform guard")
        if qualified in DATETIME_NOW and info.name != "host.clock":
            self.report("time", info, line, f"{qualified} reads the clock")
        if _is_fs_qualified(qualified) and info.name not in FS_MODULES:
            self.report("fs", info, line, f"{qualified} touches the file system")
        if info.name == "fs.walk" and _is_walk_write_qualified(qualified):
            self.report("walk-write", info, line, f"{qualified} is a write or mutate API")

    def _check_call(self, info: ModuleInfo, node: ast.Call, aliases: Mapping[str, str]) -> None:
        func = node.func
        if isinstance(func, ast.Name) and func.id not in aliases:
            if func.id in BANNED_BUILTINS:
                self.report("banned-builtin", info, node.lineno, f"{func.id}() is banned")
            elif func.id == "print" and info.name.split(".")[0] != "cli":
                self.report("print", info, node.lineno, "print() outside cli/")
            elif func.id == "open":
                if info.name == "fs.walk":
                    self.report("walk-write", info, node.lineno, "open() in fs/walk.py")
                elif info.name not in FS_MODULES:
                    self.report("fs", info, node.lineno, "open() outside the fs/ modules")
        elif (
            isinstance(func, ast.Attribute)
            and func.attr == "open"
            and _qualified(func, aliases) is None
            and info.name not in FS_MODULES
        ):
            self.report("fs", info, node.lineno, ".open() outside the fs/ modules")

    def _check_tree(self, info: ModuleInfo, tree: ast.Module) -> None:
        aliases = _aliases(info, tree)
        for node in ast.walk(tree):
            if isinstance(node, ast.Assert):
                self.report("assert", info, node.lineno, "assert statement")
            elif isinstance(node, ast.Call):
                self._check_call(info, node, aliases)
            if isinstance(node, ast.Name | ast.Attribute):
                qualified = _qualified(node, aliases)
                if qualified is not None:
                    self._check_qualified(info, qualified, node.lineno)
            if (
                info.name == "fs.walk"
                and isinstance(node, ast.Attribute)
                and node.attr in WALK_WRITE_ATTRIBUTES
            ):
                self.report("walk-write", info, node.lineno, f".{node.attr} in fs/walk.py")

    # -- driver ------------------------------------------------------------------------------
    def check_module(self, info: ModuleInfo) -> None:
        if info.tree is None:
            return
        if layer_of(info.name) is None:
            self.report("unknown-package", info, 1, f"{info.name} is outside every known layer")
        for ref in _collect_imports(info, info.tree, self.violations):
            if _is_internal(ref.module):
                self._check_internal(info, ref)
            else:
                self._check_module_bans(info, ref)
        self._check_tree(info, info.tree)

    def check_cycles(self) -> None:
        index: dict[str, int] = {}
        low: dict[str, int] = {}
        stack: list[str] = []
        on_stack: set[str] = set()
        counter = 0
        components: list[list[str]] = []

        def visit(start: str) -> None:
            nonlocal counter
            work: list[tuple[str, list[str]]] = [(start, sorted(self.graph[start]))]
            index[start] = low[start] = counter
            counter += 1
            stack.append(start)
            on_stack.add(start)
            while work:
                node, pending = work[-1]
                if pending:
                    child = pending.pop()
                    if child not in index:
                        index[child] = low[child] = counter
                        counter += 1
                        stack.append(child)
                        on_stack.add(child)
                        work.append((child, sorted(self.graph[child])))
                    elif child in on_stack:
                        low[node] = min(low[node], index[child])
                    continue
                work.pop()
                if work:
                    parent = work[-1][0]
                    low[parent] = min(low[parent], low[node])
                if low[node] == index[node]:
                    members: list[str] = []
                    while True:
                        member = stack.pop()
                        on_stack.discard(member)
                        members.append(member)
                        if member == node:
                            break
                    components.append(members)

        for name in sorted(self.graph):
            if name not in index:
                visit(name)
        by_name = {module.name: module for module in self.modules}
        for members in components:
            first = sorted(members)[0]
            self_loop = len(members) == 1 and first in self.graph[first]
            if len(members) > 1 or self_loop:
                targets = [m for m in sorted(members) if m in self.graph[first]]
                line = self.graph[first][targets[0]] if targets else 1
                cycle = " -> ".join(sorted(members))
                self.report("cycle", by_name[first], line, f"import cycle: {cycle}")


def check_tree(project_root: Path) -> list[Violation]:
    """Check src/secret_scanner under `project_root`; return every violation found."""
    package_dir = project_root / "src" / PACKAGE
    if not package_dir.is_dir():
        return [Violation("no-package", f"src/{PACKAGE}", 1, "the source package is missing")]
    violations: list[Violation] = []
    modules = _load_modules(package_dir, project_root, violations)
    checker = _Checker(modules)
    for info in modules:
        checker.check_module(info)
    checker.check_cycles()
    violations.extend(checker.violations)
    unique = {(v.rule, v.path, v.line, v.message): v for v in violations}
    return sorted(unique.values(), key=lambda v: (v.path, v.line, v.rule, v.message))


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="check_architecture", description=__doc__)
    parser.add_argument(
        "--root",
        type=Path,
        default=Path(__file__).resolve().parent.parent,
        help="project root (default: the repository containing this script)",
    )
    args = parser.parse_args(argv)
    try:
        violations = check_tree(args.root)
    except Exception as error:
        print(f"check_architecture: checker failure: {type(error).__name__}", file=sys.stderr)
        return 2
    for violation in violations:
        print(violation.format())
    if violations:
        print(f"check_architecture: {len(violations)} violation(s)")
        return 1
    print("check_architecture: ok")
    return 0


if __name__ == "__main__":  # pragma: no cover - the entry point is exercised by the gate itself
    sys.exit(main())
