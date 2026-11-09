"""The `rules` use case: the built-in rules and detectors, listed (PLAN.md D4).

Reads the packaged rules file through the strict loader (`services/loader.py`) and nothing else:
no configuration, no user rules, no file system. Returns text; printing is the CLI's job.
"""

from __future__ import annotations

from secret_scanner import __version__
from secret_scanner.core.errors import UsageError
from secret_scanner.core.models import OutputFormat
from secret_scanner.core.ruleinfo import rule_infos
from secret_scanner.render.rules_out import render_rules_json, render_rules_table
from secret_scanner.services.loader import load_builtin_rules

__all__ = ["run_rules"]


def run_rules(output_format: OutputFormat = OutputFormat.TABLE) -> str:
    """The built-in rules as `table` or `json` text. Other formats are for findings, not rules."""
    if output_format not in {OutputFormat.TABLE, OutputFormat.JSON}:
        raise UsageError("rules: the format is table or json")
    builtin = load_builtin_rules()
    infos = rule_infos(builtin.rules)
    if output_format is OutputFormat.JSON:
        return render_rules_json(infos, version=__version__, rules_sha256=builtin.sha256)
    return render_rules_table(infos, version=__version__, rules_sha256=builtin.sha256)
