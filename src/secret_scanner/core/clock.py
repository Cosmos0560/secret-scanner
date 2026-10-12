"""Clock protocol (PLAN.md section 1.1). The only implementation that reads real time is
`host/clock.py`; everything else receives a `Clock`, so tests inject a fake one."""

from __future__ import annotations

from datetime import UTC, datetime
from typing import Protocol


class Clock(Protocol):
    """Source of wall-clock and monotonic time."""

    def now_utc(self) -> datetime:
        """The current time as a timezone-aware UTC datetime."""
        ...

    def monotonic(self) -> float:
        """Seconds from a monotonic source, for budgets and durations."""
        ...


def isoformat_utc(moment: datetime) -> str:
    """Format an aware datetime as `YYYY-MM-DDTHH:MM:SSZ` (UTC, no fractional seconds)."""
    if moment.tzinfo is None or moment.utcoffset() is None:
        raise ValueError("timestamp must be timezone-aware")
    return moment.astimezone(UTC).strftime("%Y-%m-%dT%H:%M:%SZ")
