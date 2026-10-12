"""The architecture checker: every rule id has planted violations and allowed counterexamples; the
real tree passes; a cycle is found; a syntax error fails closed."""

from __future__ import annotations

from pathlib import Path

import pytest

from scripts import check_architecture as arch
from tests.helpers import PROJECT_ROOT

Files = dict[str, str | bytes]

PACKAGE_DIR = Path("src") / "secret_scanner"


def build(root: Path, files: Files) -> None:
    """Write `files` (paths relative to the package directory) plus the package `__init__` files."""
    package = root / PACKAGE_DIR
    package.mkdir(parents=True, exist_ok=True)
    explicit = {Path(name).as_posix() for name in files}
    directories = {Path()}
    for relative in files:
        directories.update(Path(relative).parents)
    for directory in directories:
        init = package / directory / "__init__.py"
        init.parent.mkdir(parents=True, exist_ok=True)
        if (directory / "__init__.py").as_posix() not in explicit and not init.exists():
            init.write_text("", encoding="utf-8")
    for relative, content in files.items():
        target = package / relative
        target.parent.mkdir(parents=True, exist_ok=True)
        if isinstance(content, bytes):
            target.write_bytes(content)
        else:
            target.write_text(content, encoding="utf-8", newline="\n")


def rules_found(root: Path) -> set[str]:
    return {violation.rule for violation in arch.check_tree(root)}


Case = tuple[str, Files]

PLANTED: dict[str, list[Case]] = {
    "no-package": [],  # a missing package is tested separately below
    "syntax": [
        ("invalid syntax", {"core/bad.py": "def (:\n"}),
        ("not utf-8", {"core/bad.py": b"x = '\xff\xfe'\n"}),
        ("null byte", {"core/bad.py": b"x = 1\x00\n"}),
    ],
    "unknown-package": [
        ("unlisted package", {"weird/x.py": "x = 1\n"}),
        ("unlisted nested package", {"plugins/a/b.py": "x = 1\n"}),
    ],
    "unresolved-import": [
        ("missing module", {"cli/main.py": "import secret_scanner.core.ghost\n"}),
        ("missing from-module", {"cli/main.py": "from secret_scanner.ghost import x\n"}),
        ("relative import leaves the package", {"core/a.py": "from ... import x\n"}),
    ],
    "layer": [
        (
            "core imports services",
            {"core/a.py": "from secret_scanner.services import b\n", "services/b.py": "x = 1\n"},
        ),
        (
            "fs imports app",
            {"fs/walk.py": "from secret_scanner.app import scan\n", "app/scan.py": "x = 1\n"},
        ),
        (
            "services import cli",
            {"services/x.py": "import secret_scanner.cli.main\n", "cli/main.py": "x = 1\n"},
        ),
        ("relative upward import", {"core/a.py": "from ..cli import main\n", "cli/main.py": ""}),
    ],
    "same-layer": [
        (
            "core imports unlisted core",
            {"core/a.py": "from secret_scanner.core import b\n", "core/b.py": "x = 1\n"},
        ),
        (
            "render imports render",
            {
                "render/table.py": "from secret_scanner.render import jsonl\n",
                "render/jsonl.py": "x = 1\n",
            },
        ),
        (
            "fs imports host",
            {"fs/walk.py": "import secret_scanner.host.clock\n", "host/clock.py": "x = 1\n"},
        ),
        (
            "listed pair, wrong direction",
            {
                "core/sanitize.py": "import secret_scanner.core.errors\n",
                "core/errors.py": "x = 1\n",
            },
        ),
    ],
    "cycle": [
        (
            "two modules",
            {
                "core/a.py": "from secret_scanner.core import b\n",
                "core/b.py": "from secret_scanner.core import a\n",
            },
        ),
        (
            "function-level import",
            {
                "core/a.py": "def f():\n    from secret_scanner.core import b\n",
                "core/b.py": "from secret_scanner.core import a\n",
            },
        ),
        (
            "TYPE_CHECKING import",
            {
                "core/a.py": "from typing import TYPE_CHECKING\nif TYPE_CHECKING:\n"
                "    from secret_scanner.core import b\n",
                "core/b.py": "import secret_scanner.core.a\n",
            },
        ),
        (
            "three modules",
            {
                "core/a.py": "import secret_scanner.core.b\n",
                "core/b.py": "import secret_scanner.core.c\n",
                "core/c.py": "import secret_scanner.core.a\n",
            },
        ),
        ("self import", {"core/a.py": "import secret_scanner.core.a\n"}),
    ],
    "core-pure": [
        ("os", {"core/a.py": "import os\n"}),
        ("pathlib", {"core/a.py": "from pathlib import Path\n"}),
        ("sys", {"core/a.py": "import sys\n"}),
        ("time", {"core/a.py": "import time\n"}),
        ("io", {"core/a.py": "import io\n"}),
        ("root package", {"__init__.py": "import os\n"}),
    ],
    "fs": [
        ("open builtin", {"services/x.py": "def f():\n    return open('f')\n"}),
        ("pathlib import", {"services/x.py": "import pathlib\n"}),
        ("shutil import", {"app/x.py": "import shutil\n"}),
        ("tempfile import", {"app/x.py": "from tempfile import mkdtemp\n"}),
        ("glob import", {"app/x.py": "import glob\n"}),
        ("os.remove", {"app/x.py": "import os\nos.remove('x')\n"}),
        ("from os import listdir", {"app/x.py": "from os import listdir\nlistdir('.')\n"}),
        ("os.path.exists", {"app/x.py": "import os.path\nos.path.exists('p')\n"}),
        ("os alias", {"app/x.py": "import os as o\no.stat('p')\n"}),
        ("io.open", {"app/x.py": "import io\nio.open('f')\n"}),
        ("method open", {"app/x.py": "def f(p):\n    return p.open()\n"}),
        ("os.scandir", {"app/x.py": "import os\nos.scandir('.')\n"}),
    ],
    "walk-write": [
        ("os.write", {"fs/walk.py": "import os\nos.write(1, b'x')\n"}),
        ("O_WRONLY", {"fs/walk.py": "import os\nflags = os.O_WRONLY\n"}),
        ("O_CREAT", {"fs/walk.py": "import os\nflags = os.O_RDONLY | os.O_CREAT\n"}),
        ("open builtin", {"fs/walk.py": "open('f')\n"}),
        ("shutil", {"fs/walk.py": "import shutil\n"}),
        ("tempfile", {"fs/walk.py": "import tempfile\n"}),
        ("os.mkdir", {"fs/walk.py": "import os\nos.mkdir('d')\n"}),
        ("io.open", {"fs/walk.py": "import io\nio.open('f')\n"}),
        ("write_text", {"fs/walk.py": "def f(p):\n    p.write_text('x')\n"}),
        ("unlink", {"fs/walk.py": "def f(p):\n    p.unlink()\n"}),
    ],
    "subprocess": [
        ("import", {"app/scan.py": "import subprocess\n"}),
        ("from import", {"services/git_scanner.py": "from subprocess import run\n"}),
        ("core", {"core/x.py": "import subprocess\n"}),
    ],
    "threading": [
        ("import", {"app/scan.py": "import threading\n"}),
        ("in demo_git", {"gitio/demo_git.py": "import threading\n"}),
    ],
    "os-exec": [
        ("os.system", {"gitio/runner.py": "import os\nos.system('x')\n"}),
        ("os.popen", {"gitio/runner.py": "import os\nos.popen('x')\n"}),
        ("os.execv", {"gitio/runner.py": "import os\nos.execv('x', [])\n"}),
        ("os.spawnl", {"gitio/runner.py": "import os\nos.spawnl(0, 'x')\n"}),
        ("os.startfile", {"app/x.py": "import os\nos.startfile('x')\n"}),
        ("pty", {"gitio/runner.py": "import pty\n"}),
    ],
    "network": [
        ("socket", {"app/x.py": "import socket\n"}),
        ("urllib.request", {"app/x.py": "import urllib.request\n"}),
        ("http.client", {"app/x.py": "from http import client\n"}),
        ("requests", {"app/x.py": "import requests\n"}),
        ("httpx", {"app/x.py": "import httpx\n"}),
        ("asyncio", {"app/x.py": "import asyncio\n"}),
        ("multiprocessing", {"app/x.py": "import multiprocessing\n"}),
        ("webbrowser", {"cli/main.py": "import webbrowser\n"}),
        ("ssl in runner", {"gitio/runner.py": "import ssl\n"}),
    ],
    "re": [
        ("import re", {"core/x.py": "import re\n"}),
        ("from re import", {"services/x.py": "from re import compile as c\n"}),
    ],
    "yaml": [
        ("yaml in core", {"core/x.py": "import yaml\n"}),
        ("importlib.resources elsewhere", {"app/x.py": "import importlib.resources\n"}),
        ("from importlib", {"app/x.py": "from importlib import resources\n"}),
        ("yaml in config", {"services/config.py": "import yaml\n"}),
    ],
    "yaml-unsafe": [
        ("yaml.load", {"services/loader.py": "import yaml\nyaml.load('x')\n"}),
        ("yaml.unsafe_load", {"services/loader.py": "import yaml\nyaml.unsafe_load('x')\n"}),
        ("yaml.full_load", {"services/loader.py": "import yaml\nyaml.full_load('x')\n"}),
        ("from yaml import load", {"services/loader.py": "from yaml import load\nload('x')\n"}),
    ],
    "time": [
        ("import time", {"app/x.py": "import time\n"}),
        ("datetime.now", {"app/x.py": "from datetime import datetime\ndatetime.now()\n"}),
        ("datetime.datetime.utcnow", {"app/x.py": "import datetime\ndatetime.datetime.utcnow()\n"}),
        ("date.today", {"app/x.py": "import datetime\ndatetime.date.today()\n"}),
        ("alias", {"app/x.py": "import datetime as dt\ndt.datetime.now()\n"}),
        ("time in core clock", {"core/clock.py": "import time\n"}),
    ],
    "banned-module": [
        ("logging", {"app/x.py": "import logging\n"}),
        ("random", {"app/x.py": "import random\n"}),
        ("pickle", {"app/x.py": "import pickle\n"}),
        ("marshal", {"app/x.py": "import marshal\n"}),
        ("shelve", {"app/x.py": "import shelve\n"}),
        ("ctypes", {"app/x.py": "import ctypes\n"}),
    ],
    "banned-builtin": [
        ("eval", {"app/x.py": "eval('1')\n"}),
        ("exec", {"app/x.py": "exec('x')\n"}),
        ("compile", {"app/x.py": "compile('x', 'f', 'exec')\n"}),
        ("__import__", {"app/x.py": "__import__('os')\n"}),
    ],
    "print": [
        ("app", {"app/x.py": "print('x')\n"}),
        ("render", {"render/x.py": "print('x')\n"}),
        ("core", {"core/x.py": "print('x')\n"}),
        ("__main__", {"__main__.py": "print('x')\n"}),
    ],
    "assert": [
        ("core", {"core/x.py": "def f(x):\n    assert x\n"}),
        ("cli", {"cli/main.py": "assert True\n"}),
    ],
    "platform": [
        ("os.name", {"host/x.py": "import os\nwindows = os.name == 'nt'\n"}),
        ("platform.system", {"host/x.py": "import platform\nplatform.system()\n"}),
        ("from platform", {"host/x.py": "from platform import system\nsystem()\n"}),
    ],
    "match": [
        (
            "module import in app",
            {
                "app/scan.py": "from secret_scanner.core.detect import match\n",
                "core/detect/match.py": "class Match: ...\n",
            },
        ),
        (
            "name import in app",
            {
                "app/scan.py": "from secret_scanner.core.detect.match import Match\n",
                "core/detect/match.py": "class Match: ...\n",
            },
        ),
        (
            "render",
            {
                "render/x.py": "import secret_scanner.core.detect.match\n",
                "core/detect/match.py": "class Match: ...\n",
            },
        ),
        (
            "re-export",
            {
                "cli/main.py": "from secret_scanner.services.fs_scanner import Match\n",
                "services/fs_scanner.py": "Match = object\n",
            },
        ),
    ],
    "sandbox": [
        (
            "sandbox from app",
            {"app/scan.py": "import secret_scanner.fs.sandbox\n", "fs/sandbox.py": "x = 1\n"},
        ),
        (
            "demo_git from services",
            {
                "services/x.py": "from secret_scanner.gitio import demo_git\n",
                "gitio/demo_git.py": "x = 1\n",
            },
        ),
    ],
}

ALLOWED: dict[str, list[Case]] = {
    "no-package": [("minimal package", {"__init__.py": '__version__ = "0"\n'})],
    "syntax": [("valid module", {"core/ok.py": "x = 1\n"})],
    "unknown-package": [
        ("listed host package", {"host/hostinfo.py": "x = 1\n"}),
        ("top-level main", {"__main__.py": "x = 1\n"}),
    ],
    "unresolved-import": [
        (
            "existing module",
            {
                "cli/main.py": "from secret_scanner.core import models\n",
                "core/models.py": "x = 1\n",
            },
        ),
        (
            "attribute of a package",
            {
                "cli/main.py": "from secret_scanner.core import something" + chr(10),
                "core/__init__.py": "",
            },
        ),
        (
            "relative import inside",
            {
                "core/errors.py": "from .sanitize import sanitize\n",
                "core/sanitize.py": "def sanitize(): ...\n",
            },
        ),
        (
            "root version",
            {
                "cli/main.py": "from secret_scanner import __version__\n",
                "__init__.py": '__version__ = "0"\n',
            },
        ),
    ],
    "layer": [
        (
            "app imports core",
            {
                "app/scan.py": "from secret_scanner.core import models\n",
                "core/models.py": "x = 1\n",
            },
        ),
        (
            "cli imports services",
            {
                "cli/main.py": "import secret_scanner.services.config\n",
                "services/config.py": "x = 1\n",
            },
        ),
    ],
    "same-layer": [
        (
            "listed pair",
            {
                "core/errors.py": "from secret_scanner.core.sanitize import sanitize\n",
                "core/sanitize.py": "def sanitize(): ...\n",
            },
        ),
        (
            "chain",
            {
                "core/limits.py": "from secret_scanner.core.errors import ConfigError\n",
                "core/errors.py": "class ConfigError(Exception): ...\n",
            },
        ),
        (
            "main imports cli.main",
            {
                "__main__.py": "from secret_scanner.cli.main import main\n",
                "cli/main.py": "def main(): ...\n",
            },
        ),
    ],
    "cycle": [
        (
            "dag",
            {
                "core/limits.py": "import secret_scanner.core.errors\n",
                "core/errors.py": "import secret_scanner.core.sanitize\n",
                "core/sanitize.py": "x = 1\n",
            },
        ),
    ],
    "core-pure": [
        ("os outside core", {"host/x.py": "import os\n"}),
        ("sys in cli", {"cli/main.py": "import sys\n"}),
        (
            "datetime in core",
            {
                "core/clock.py": "from datetime import datetime\n"
                "def f(m: datetime) -> str:\n"
                "    return m.isoformat()\n"
            },
        ),
    ],
    "fs": [
        ("open in safe_files", {"fs/safe_files.py": "def f():\n    return open('f')\n"}),
        ("os.remove in sandbox", {"fs/sandbox.py": "import os\nos.remove('x')\n"}),
        ("pathlib in walk", {"fs/walk.py": "import pathlib\n"}),
        ("star import", {"app/x.py": "from os.path import *\n"}),
        ("os.path.join anywhere", {"app/x.py": "import os\nos.path.join('a', 'b')\nos.environ\n"}),
        ("method named read on an object", {"app/x.py": "def f(o):\n    return o.read()\n"}),
    ],
    "walk-write": [
        (
            "read-only open flags",
            {
                "fs/walk.py": "import os\n"
                "fd = os.open('p', os.O_RDONLY | os.O_NOFOLLOW)\n"
                "os.read(fd, 10)\nos.scandir('.')\nos.lstat('p')\n"
            },
        ),
        ("str.replace", {"fs/walk.py": "def f(s):\n    return s.replace('a', 'b')\n"}),
        (
            "write in safe_files",
            {"fs/safe_files.py": "import os\nos.write(1, b'x')\nos.O_WRONLY\n"},
        ),
    ],
    "subprocess": [
        ("runner", {"gitio/runner.py": "import subprocess\n"}),
        ("demo_git", {"gitio/demo_git.py": "from subprocess import run\n"}),
    ],
    "threading": [("runner", {"gitio/runner.py": "import threading\n"})],
    "os-exec": [
        ("subprocess in runner", {"gitio/runner.py": "import subprocess\nsubprocess.run([])\n"}),
        ("os.environ", {"gitio/runner.py": "import os\nos.environ\n"}),
    ],
    "network": [
        ("stdlib neighbours", {"app/x.py": "import json\nimport hashlib\nimport argparse\n"}),
        ("urlparse-free", {"app/x.py": "import secret_scanner\n"}),
    ],
    "re": [("regex_guard", {"core/regex_guard.py": "import re\nre.compile('a')\n"})],
    "yaml": [
        (
            "loader",
            {
                "services/loader.py": "import yaml\nimport importlib.resources\n"
                "from importlib import resources\n"
            },
        ),
    ],
    "yaml-unsafe": [
        (
            "safe loader",
            {
                "services/loader.py": "import yaml\nyaml.safe_load('x')\n"
                "class L(yaml.SafeLoader): ...\n"
            },
        ),
    ],
    "time": [
        (
            "clock",
            {
                "host/clock.py": "import time\nfrom datetime import UTC, datetime\n"
                "time.monotonic()\ntime.sleep(0)\ndatetime.now(UTC)\n"
            },
        ),
        ("injected clock", {"app/x.py": "def f(clock):\n    return clock.now_utc()\n"}),
    ],
    "banned-module": [("neighbours", {"app/x.py": "import json\nimport dataclasses\n"})],
    "banned-builtin": [
        ("re.compile attribute", {"core/regex_guard.py": "import re\nre.compile('a')\n"}),
        ("method called exec", {"app/x.py": "def f(o):\n    o.exec()\n    o.eval()\n"}),
    ],
    "print": [
        ("cli", {"cli/main.py": "print('x')\n"}),
        ("cli subpackage", {"cli/sub/x.py": "print('x')\n"}),
    ],
    "assert": [
        ("explicit raise", {"core/x.py": "def f(x):\n    if not x:\n        raise ValueError\n"})
    ],
    "platform": [
        ("sys.platform", {"host/x.py": "import sys\nwindows = sys.platform == 'win32'\n"}),
        ("platform.node", {"host/hostinfo.py": "import platform\nplatform.node()\n"}),
    ],
    "match": [
        (
            "fs_scanner",
            {
                "services/fs_scanner.py": "from secret_scanner.core.detect.match import Match\n",
                "core/detect/match.py": "class Match: ...\n",
            },
        ),
        (
            "git_scanner",
            {
                "services/git_scanner.py": "from secret_scanner.core.detect import match\n",
                "core/detect/match.py": "class Match: ...\n",
            },
        ),
    ],
    "sandbox": [
        (
            "demo",
            {
                "app/demo.py": "import secret_scanner.fs.sandbox\n"
                "from secret_scanner.gitio import demo_git\n",
                "fs/sandbox.py": "x = 1\n",
                "gitio/demo_git.py": "x = 1\n",
            },
        ),
    ],
}


def _cases(table: dict[str, list[Case]]) -> list[tuple[str, str, Files]]:
    return [(rule, label, files) for rule, cases in table.items() for label, files in cases]


def test_every_rule_has_planted_violations_and_allowed_counterexamples() -> None:
    assert set(PLANTED) == set(arch.RULES)
    assert set(ALLOWED) == set(arch.RULES)
    # "no-package" is exercised by its own test; every other rule needs a planted case.
    assert all(PLANTED[rule] for rule in arch.RULES if rule != "no-package")
    assert all(ALLOWED[rule] for rule in arch.RULES)


@pytest.mark.parametrize(
    ("rule", "label", "files"),
    _cases(PLANTED),
    ids=lambda value: value if isinstance(value, str) else "files",
)
def test_planted_violation_is_found(rule: str, label: str, files: Files, tmp_path: Path) -> None:
    build(tmp_path, files)
    assert rule in rules_found(tmp_path), label


@pytest.mark.parametrize(
    ("rule", "label", "files"),
    _cases(ALLOWED),
    ids=lambda value: value if isinstance(value, str) else "files",
)
def test_allowed_counterexample_is_clean(
    rule: str, label: str, files: Files, tmp_path: Path
) -> None:
    build(tmp_path, files)
    assert arch.check_tree(tmp_path) == [], f"{rule}: {label}"


def test_missing_package_fails_closed(tmp_path: Path) -> None:
    violations = arch.check_tree(tmp_path)
    assert [violation.rule for violation in violations] == ["no-package"]


def test_violation_carries_path_line_and_rule(tmp_path: Path) -> None:
    build(tmp_path, {"core/a.py": "x = 1\ny = 2\nimport os\n"})
    (violation,) = arch.check_tree(tmp_path)
    assert violation.rule == "core-pure"
    assert violation.path == "src/secret_scanner/core/a.py"
    assert violation.line == 3
    assert violation.format().startswith("src/secret_scanner/core/a.py:3: [core-pure]")


def test_cycle_report_names_every_member(tmp_path: Path) -> None:
    build(
        tmp_path,
        {
            "core/a.py": "import secret_scanner.core.b\n",
            "core/b.py": "import secret_scanner.core.c\n",
            "core/c.py": "import secret_scanner.core.a\n",
        },
    )
    cycles = [v for v in arch.check_tree(tmp_path) if v.rule == "cycle"]
    assert len(cycles) == 1
    assert "core.a -> core.b -> core.c" in cycles[0].message


def test_one_syntax_error_does_not_hide_other_violations(tmp_path: Path) -> None:
    build(tmp_path, {"core/bad.py": "def (:\n", "core/a.py": "import os\n"})
    assert rules_found(tmp_path) == {"syntax", "core-pure"}


def test_the_real_tree_passes() -> None:
    assert arch.check_tree(PROJECT_ROOT) == []


def test_every_module_of_the_real_tree_has_a_layer() -> None:
    package = PROJECT_ROOT / "src" / "secret_scanner"
    for path in package.rglob("*.py"):
        name = arch.module_name(path.relative_to(package).parts)
        assert arch.layer_of(name) is not None, name


def test_same_layer_table_names_only_real_layer_zero_to_four_modules() -> None:
    for importer, allowed in arch.SAME_LAYER_ALLOWED.items():
        assert arch.layer_of(importer) is not None
        for target in allowed:
            assert arch.layer_of(target) == arch.layer_of(importer)


def test_main_reports_clean_and_dirty_trees(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    build(tmp_path, {"core/ok.py": "x = 1\n"})
    assert arch.main(["--root", str(tmp_path)]) == 0
    assert "check_architecture: ok" in capsys.readouterr().out
    build(tmp_path, {"core/a.py": "import os\n"})
    assert arch.main(["--root", str(tmp_path)]) == 1
    output = capsys.readouterr().out
    assert "[core-pure]" in output
    assert "1 violation(s)" in output


def test_main_exits_two_when_the_checker_itself_fails(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str], tmp_path: Path
) -> None:
    def explode(root: Path) -> list[arch.Violation]:
        raise RuntimeError("boom")

    monkeypatch.setattr(arch, "check_tree", explode)
    assert arch.main(["--root", str(tmp_path)]) == 2
    assert "checker failure: RuntimeError" in capsys.readouterr().err


def test_module_name_mapping() -> None:
    assert arch.module_name(["__init__.py"]) == ""
    assert arch.module_name(["__main__.py"]) == "__main__"
    assert arch.module_name(["core", "__init__.py"]) == "core"
    assert arch.module_name(["core", "detect", "match.py"]) == "core.detect.match"
