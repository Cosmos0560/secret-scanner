"""Every bound of the tool, as named constants (PLAN.md D18).

Each limit has a default and a hard ceiling. Configuration may lower a value, never raise it above
its default, and nothing may exceed a ceiling. Hitting a limit during a run is recorded as an issue
and makes the run incomplete (exit code 4); it is never reported as clean.
"""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass, fields, replace

from secret_scanner.core.errors import ConfigError

KIB = 1024
MIB = 1024 * KIB
GIB = 1024 * MIB

MAX_FILES = 200_000  # entries, including directories
MAX_FILES_CEILING = 1_000_000
MAX_DEPTH = 64
MAX_DEPTH_CEILING = 128
MAX_PATH_CHARS = 4_096
MAX_PATH_CHARS_CEILING = 4_096
MAX_FILE_BYTES = 8 * MIB
MAX_FILE_BYTES_CEILING = 64 * MIB
MAX_BLOB_BYTES = MAX_FILE_BYTES  # one row in D18: "(and MAX_BLOB_BYTES)"
MAX_BLOB_BYTES_CEILING = MAX_FILE_BYTES_CEILING
MAX_LINE_BYTES = 256 * KIB
MAX_LINE_BYTES_CEILING = 4 * MIB
MAX_TOTAL_BYTES = 4 * GIB
MAX_TOTAL_BYTES_CEILING = 16 * GIB
MAX_RUN_SECONDS = 600
MAX_RUN_SECONDS_CEILING = 3_600
MAX_GIT_COMMITS = 200_000
MAX_GIT_COMMITS_CEILING = 1_000_000
MAX_GIT_BLOBS = 1_000_000  # distinct
MAX_GIT_BLOBS_CEILING = 2_000_000
MAX_GIT_OUTPUT_BYTES = 1 * GIB  # per call
MAX_GIT_OUTPUT_BYTES_CEILING = 4 * GIB
MAX_GIT_STDERR_BYTES = 64 * KIB
MAX_GIT_STDERR_BYTES_CEILING = 64 * KIB
GIT_CALL_TIMEOUT_SECONDS = 30  # short calls
GIT_CALL_TIMEOUT_SECONDS_CEILING = 120
MAX_FINDINGS = 10_000  # reported
MAX_FINDINGS_CEILING = 10_000
MAX_FINDINGS_PER_FILE = 200
MAX_FINDINGS_PER_FILE_CEILING = 1_000
MAX_RULES = 256
MAX_RULES_CEILING = 256
MAX_KEYWORDS_PER_RULE = 16
MAX_KEYWORDS_PER_RULE_CEILING = 16
MAX_PATTERN_CHARS = 512
MAX_PATTERN_CHARS_CEILING = 512
MAX_MATCH_CHARS = 1_024
MAX_MATCH_CHARS_CEILING = 1_024
MAX_PATTERN_COST = 8_192
MAX_PATTERN_COST_CEILING = 8_192
MAX_ENTROPY_TOKEN_CHARS = 256
MAX_ENTROPY_TOKEN_CHARS_CEILING = 256
MAX_KEY_LINES = 200
MAX_KEY_LINES_CEILING = 200
MAX_CONFIG_BYTES = 256 * KIB
MAX_CONFIG_BYTES_CEILING = 256 * KIB
MAX_RULES_FILE_BYTES = 256 * KIB
MAX_RULES_FILE_BYTES_CEILING = 256 * KIB
MAX_BASELINE_BYTES = 16 * MIB
MAX_BASELINE_BYTES_CEILING = 16 * MIB
MAX_BASELINE_ENTRIES = 100_000
MAX_BASELINE_ENTRIES_CEILING = 100_000
MAX_GLOBS = 256
MAX_GLOBS_CEILING = 256
MAX_GLOB_CHARS = 512
MAX_GLOB_CHARS_CEILING = 512


@dataclass(frozen=True, slots=True)
class LimitSpec:
    """One row of the D18 table."""

    name: str
    default: int
    ceiling: int


LIMIT_SPECS: tuple[LimitSpec, ...] = (
    LimitSpec("MAX_FILES", MAX_FILES, MAX_FILES_CEILING),
    LimitSpec("MAX_DEPTH", MAX_DEPTH, MAX_DEPTH_CEILING),
    LimitSpec("MAX_PATH_CHARS", MAX_PATH_CHARS, MAX_PATH_CHARS_CEILING),
    LimitSpec("MAX_FILE_BYTES", MAX_FILE_BYTES, MAX_FILE_BYTES_CEILING),
    LimitSpec("MAX_LINE_BYTES", MAX_LINE_BYTES, MAX_LINE_BYTES_CEILING),
    LimitSpec("MAX_TOTAL_BYTES", MAX_TOTAL_BYTES, MAX_TOTAL_BYTES_CEILING),
    LimitSpec("MAX_RUN_SECONDS", MAX_RUN_SECONDS, MAX_RUN_SECONDS_CEILING),
    LimitSpec("MAX_GIT_COMMITS", MAX_GIT_COMMITS, MAX_GIT_COMMITS_CEILING),
    LimitSpec("MAX_GIT_BLOBS", MAX_GIT_BLOBS, MAX_GIT_BLOBS_CEILING),
    LimitSpec("MAX_GIT_OUTPUT_BYTES", MAX_GIT_OUTPUT_BYTES, MAX_GIT_OUTPUT_BYTES_CEILING),
    LimitSpec("MAX_GIT_STDERR_BYTES", MAX_GIT_STDERR_BYTES, MAX_GIT_STDERR_BYTES_CEILING),
    LimitSpec(
        "GIT_CALL_TIMEOUT_SECONDS", GIT_CALL_TIMEOUT_SECONDS, GIT_CALL_TIMEOUT_SECONDS_CEILING
    ),
    LimitSpec("MAX_FINDINGS", MAX_FINDINGS, MAX_FINDINGS_CEILING),
    LimitSpec("MAX_FINDINGS_PER_FILE", MAX_FINDINGS_PER_FILE, MAX_FINDINGS_PER_FILE_CEILING),
    LimitSpec("MAX_RULES", MAX_RULES, MAX_RULES_CEILING),
    LimitSpec("MAX_KEYWORDS_PER_RULE", MAX_KEYWORDS_PER_RULE, MAX_KEYWORDS_PER_RULE_CEILING),
    LimitSpec("MAX_PATTERN_CHARS", MAX_PATTERN_CHARS, MAX_PATTERN_CHARS_CEILING),
    LimitSpec("MAX_MATCH_CHARS", MAX_MATCH_CHARS, MAX_MATCH_CHARS_CEILING),
    LimitSpec("MAX_PATTERN_COST", MAX_PATTERN_COST, MAX_PATTERN_COST_CEILING),
    LimitSpec("MAX_ENTROPY_TOKEN_CHARS", MAX_ENTROPY_TOKEN_CHARS, MAX_ENTROPY_TOKEN_CHARS_CEILING),
    LimitSpec("MAX_KEY_LINES", MAX_KEY_LINES, MAX_KEY_LINES_CEILING),
    LimitSpec("MAX_CONFIG_BYTES", MAX_CONFIG_BYTES, MAX_CONFIG_BYTES_CEILING),
    LimitSpec("MAX_RULES_FILE_BYTES", MAX_RULES_FILE_BYTES, MAX_RULES_FILE_BYTES_CEILING),
    LimitSpec("MAX_BASELINE_BYTES", MAX_BASELINE_BYTES, MAX_BASELINE_BYTES_CEILING),
    LimitSpec("MAX_BASELINE_ENTRIES", MAX_BASELINE_ENTRIES, MAX_BASELINE_ENTRIES_CEILING),
    LimitSpec("MAX_GLOBS", MAX_GLOBS, MAX_GLOBS_CEILING),
    LimitSpec("MAX_GLOB_CHARS", MAX_GLOB_CHARS, MAX_GLOB_CHARS_CEILING),
)

_SPEC_BY_FIELD: dict[str, LimitSpec] = {spec.name.lower(): spec for spec in LIMIT_SPECS}


@dataclass(frozen=True, slots=True)
class Limits:
    """The effective limits of one run. Field names are the lower-cased constant names."""

    max_files: int = MAX_FILES
    max_depth: int = MAX_DEPTH
    max_path_chars: int = MAX_PATH_CHARS
    max_file_bytes: int = MAX_FILE_BYTES
    max_line_bytes: int = MAX_LINE_BYTES
    max_total_bytes: int = MAX_TOTAL_BYTES
    max_run_seconds: int = MAX_RUN_SECONDS
    max_git_commits: int = MAX_GIT_COMMITS
    max_git_blobs: int = MAX_GIT_BLOBS
    max_git_output_bytes: int = MAX_GIT_OUTPUT_BYTES
    max_git_stderr_bytes: int = MAX_GIT_STDERR_BYTES
    git_call_timeout_seconds: int = GIT_CALL_TIMEOUT_SECONDS
    max_findings: int = MAX_FINDINGS
    max_findings_per_file: int = MAX_FINDINGS_PER_FILE
    max_rules: int = MAX_RULES
    max_keywords_per_rule: int = MAX_KEYWORDS_PER_RULE
    max_pattern_chars: int = MAX_PATTERN_CHARS
    max_match_chars: int = MAX_MATCH_CHARS
    max_pattern_cost: int = MAX_PATTERN_COST
    max_entropy_token_chars: int = MAX_ENTROPY_TOKEN_CHARS
    max_key_lines: int = MAX_KEY_LINES
    max_config_bytes: int = MAX_CONFIG_BYTES
    max_rules_file_bytes: int = MAX_RULES_FILE_BYTES
    max_baseline_bytes: int = MAX_BASELINE_BYTES
    max_baseline_entries: int = MAX_BASELINE_ENTRIES
    max_globs: int = MAX_GLOBS
    max_glob_chars: int = MAX_GLOB_CHARS

    @property
    def max_blob_bytes(self) -> int:
        """Blobs share the file size limit (D18)."""
        return self.max_file_bytes

    def with_overrides(self, overrides: Mapping[str, object]) -> Limits:
        """Return a copy with lowered values. Refuse unknown names, non-integers and any value
        that is below 1, above the hard ceiling, or above this run's current value."""
        updates: dict[str, int] = {}
        for name, value in overrides.items():
            spec = _SPEC_BY_FIELD.get(name)
            if spec is None:
                # the name is not echoed (it may be a pasted secret); the known ones are listed
                raise ConfigError(f"unknown limit (known: {', '.join(sorted(_SPEC_BY_FIELD))})")
            if isinstance(value, bool) or not isinstance(value, int):
                raise ConfigError(f"limit {name} must be an integer")
            if value < 1:
                raise ConfigError(f"limit {name} must be at least 1")
            if value > spec.ceiling:
                raise ConfigError(f"limit {name} is above its hard ceiling of {spec.ceiling}")
            if value > getattr(self, name):
                raise ConfigError(f"limit {name} can only be lowered, not raised")
            updates[name] = value
        return replace(self, **updates)


DEFAULT_LIMITS = Limits()


def limit_field_names() -> tuple[str, ...]:
    """The field names of `Limits`, in declaration order."""
    return tuple(field.name for field in fields(Limits))
