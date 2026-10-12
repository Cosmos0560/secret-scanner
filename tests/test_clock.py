"""Clock protocol and timestamp formatting."""

from __future__ import annotations

from datetime import UTC, datetime, timedelta, timezone

import pytest

from secret_scanner.core.clock import Clock, isoformat_utc
from tests.helpers import FakeClock


def test_fake_clock_satisfies_the_protocol_and_advances_only_on_request() -> None:
    clock: Clock = FakeClock()
    first = clock.monotonic()
    assert clock.monotonic() == first
    assert isinstance(clock, FakeClock)
    clock.advance(2.5)
    assert clock.monotonic() == first + 2.5
    assert clock.now_utc() == datetime(2026, 1, 1, tzinfo=UTC) + timedelta(seconds=2.5)


def test_isoformat_utc_is_second_resolution_with_z() -> None:
    moment = datetime(2026, 10, 12, 8, 30, 15, 987654, tzinfo=UTC)
    assert isoformat_utc(moment) == "2026-10-12T08:30:15Z"


def test_isoformat_utc_converts_other_zones() -> None:
    plus_two = timezone(timedelta(hours=2))
    assert isoformat_utc(datetime(2026, 1, 1, 2, 0, 0, tzinfo=plus_two)) == "2026-01-01T00:00:00Z"


def test_isoformat_utc_refuses_naive_datetimes() -> None:
    with pytest.raises(ValueError, match="timezone-aware"):
        isoformat_utc(datetime(2026, 1, 1))
