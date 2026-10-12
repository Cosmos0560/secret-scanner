"""The system clock: the only module that reads real time (CLAUDE.md section 6)."""

from __future__ import annotations

import time
from datetime import UTC, datetime


class SystemClock:
    """`Clock` backed by the operating system."""

    def now_utc(self) -> datetime:
        return datetime.now(UTC)

    def monotonic(self) -> float:
        return time.monotonic()
