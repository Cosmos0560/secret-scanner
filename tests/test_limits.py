"""Limits (PLAN.md D18): defaults and ceilings, validated overrides, and drift against PLAN.md."""

from __future__ import annotations

import re

import pytest

from secret_scanner.core import limits
from secret_scanner.core.errors import ConfigError
from secret_scanner.core.limits import DEFAULT_LIMITS, LIMIT_SPECS, Limits
from tests.helpers import PROJECT_ROOT

UNITS = {"KiB": 1024, "MiB": 1024**2, "GiB": 1024**3}


def _parse_number(cell: str) -> int:
    text = cell.strip()
    for unit, factor in UNITS.items():
        if text.endswith(" " + unit):
            return int(text[: -len(unit)].replace(" ", "")) * factor
    return int(text.replace(" ", ""))


def _plan_table() -> dict[str, tuple[int, int]]:
    """Name -> (default, ceiling) as written in the D18 table of PLAN.md."""
    plan = (PROJECT_ROOT / "PLAN.md").read_text(encoding="utf-8")
    start = plan.index("### D18")
    section = plan[start : plan.index("\n### ", start + 1)]
    table: dict[str, tuple[int, int]] = {}
    for line in section.splitlines():
        if not line.startswith("| `"):
            continue
        cells = [cell.strip() for cell in line.strip().strip("|").split("|")]
        names = re.findall(r"`([A-Z_]+)`", cells[0])
        defaults = [_parse_number(part) for part in cells[1].split(" / ")]
        if cells[2] == "same":
            ceilings = defaults
        else:
            ceilings = [_parse_number(part) for part in cells[2].split(" / ")]
        if len(defaults) == 1:
            defaults = defaults * len(names)
            ceilings = ceilings * len(names)
        assert len(names) == len(defaults) == len(ceilings), line
        for name, default, ceiling in zip(names, defaults, ceilings, strict=True):
            table[name] = (default, ceiling)
    return table


def test_constants_match_the_d18_table_in_plan_md() -> None:
    table = _plan_table()
    assert table, "no D18 rows were parsed"
    for name, (default, ceiling) in table.items():
        assert getattr(limits, name) == default, name
        assert getattr(limits, name + "_CEILING") == ceiling, name


def test_every_limit_in_the_spec_list_is_documented_in_plan_md() -> None:
    table = _plan_table()
    for spec in LIMIT_SPECS:
        assert (spec.default, spec.ceiling) == table[spec.name], spec.name


def test_defaults_never_exceed_their_ceilings_and_are_positive() -> None:
    for spec in LIMIT_SPECS:
        assert 1 <= spec.default <= spec.ceiling, spec.name


def test_limits_dataclass_has_one_field_per_spec() -> None:
    assert limits.limit_field_names() == tuple(spec.name.lower() for spec in LIMIT_SPECS)
    for spec in LIMIT_SPECS:
        assert getattr(DEFAULT_LIMITS, spec.name.lower()) == spec.default


def test_blob_limit_is_the_file_limit() -> None:
    assert limits.MAX_BLOB_BYTES == limits.MAX_FILE_BYTES
    assert limits.MAX_BLOB_BYTES_CEILING == limits.MAX_FILE_BYTES_CEILING
    lowered = DEFAULT_LIMITS.with_overrides({"max_file_bytes": 1000})
    assert lowered.max_blob_bytes == 1000


def test_overrides_can_lower_values() -> None:
    lowered = DEFAULT_LIMITS.with_overrides({"max_files": 10, "max_depth": 3})
    assert (lowered.max_files, lowered.max_depth) == (10, 3)
    assert lowered.max_line_bytes == DEFAULT_LIMITS.max_line_bytes
    assert DEFAULT_LIMITS.with_overrides({}) == DEFAULT_LIMITS
    assert DEFAULT_LIMITS.with_overrides({"max_files": limits.MAX_FILES}) == DEFAULT_LIMITS


@pytest.mark.parametrize(
    ("overrides", "message"),
    [
        ({"max_files": limits.MAX_FILES_CEILING + 1}, "hard ceiling"),
        ({"max_files": limits.MAX_FILES + 1}, "only be lowered"),
        ({"max_files": 0}, "at least 1"),
        ({"max_files": -5}, "at least 1"),
        ({"max_files": True}, "integer"),
        ({"max_files": "10"}, "integer"),
        ({"max_files": 1.5}, "integer"),
        ({"max_nothing": 5}, "unknown limit"),
        ({"MAX_FILES": 5}, "unknown limit"),
    ],
)
def test_overrides_refuse_raising_and_nonsense(overrides: dict[str, object], message: str) -> None:
    with pytest.raises(ConfigError, match=message):
        DEFAULT_LIMITS.with_overrides(overrides)


def test_overrides_are_applied_on_top_of_a_lowered_base() -> None:
    base = Limits().with_overrides({"max_files": 100})
    with pytest.raises(ConfigError, match="only be lowered"):
        base.with_overrides({"max_files": 200})
