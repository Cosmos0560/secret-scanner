"""The host label that machine-readable output carries (PLAN.md D11, `--host-label`).

The label comes from the machine's node name unless the user gives one. Either way it is
escaped for display and limited in length, so a hostile host name or option value cannot inject
anything into a report.
"""

from __future__ import annotations

import platform

from secret_scanner.core.errors import UsageError
from secret_scanner.core.sanitize import sanitize

MAX_HOST_LABEL_CHARS = 255
UNKNOWN_HOST = "unknown"


def resolve_host_label(override: str | None) -> str:
    """The label to report: `override` if given (refused when empty or holding a control
    character), else the node name, else "unknown"."""
    if override is not None:
        if not override.strip():
            raise UsageError("--host-label must not be empty")
        if any(ord(char) < 0x20 or ord(char) == 0x7F for char in override):
            raise UsageError("--host-label must not contain control characters")
        return sanitize(override, max_chars=MAX_HOST_LABEL_CHARS, ascii_only=True)
    node = platform.node().strip()
    if not node:
        return UNKNOWN_HOST
    return sanitize(node, max_chars=MAX_HOST_LABEL_CHARS, ascii_only=True)
