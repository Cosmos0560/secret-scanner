"""The generated tree behind the examples in docs/sarif.md and docs/siem-mapping.md.

The examples in those documents are the real output of the tool over this tree, built at run time
from the fake generator (nothing secret-shaped exists in any file of the repository). The drift
tests rebuild the tree, run the tool and compare the result with the document, so an example can
never describe output the code no longer produces.
"""

from __future__ import annotations

import re
from pathlib import Path

from secret_scanner.core.fakes import build_fake
from secret_scanner.services.loader import load_builtin_rules

SEED = "doc-sample"
HOST_LABEL = "example-host"
TIMESTAMP = re.compile(r"\d{4}-\d\d-\d\dT\d\d:\d\d:\d\dZ")
MASK = "<time>"


def make_sample_tree(root: Path) -> None:
    """A small project with two generated fakes: an AWS key id in `config/.env` (line 2) and an npm
    token in `src/app.py` (line 3)."""
    rules = {rule.id: rule for rule in load_builtin_rules().rules}
    aws = build_fake(rules["aws-access-key-id"], SEED)
    npm = build_fake(rules["npm-token"], SEED)
    files = {
        "config/.env": f"# deployment settings\nAWS_ACCESS_KEY_ID={aws}\n",
        "src/app.py": f'import os\n\nTOKEN = "{npm}"\n',
        "README.md": "Nothing to see here.\n",
    }
    for relative, text in files.items():
        path = root / relative
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(text, encoding="utf-8", newline="\n")


def mask_times(text: str) -> str:
    """Replace every `YYYY-MM-DDTHH:MM:SSZ` timestamp, which differs from run to run."""
    return TIMESTAMP.sub(MASK, text)
