"""The system clock and the host label."""

from __future__ import annotations

import platform
from datetime import UTC, timedelta

import pytest

from secret_scanner.core.clock import Clock
from secret_scanner.core.errors import UsageError
from secret_scanner.host.clock import SystemClock
from secret_scanner.host.hostinfo import MAX_HOST_LABEL_CHARS, UNKNOWN_HOST, resolve_host_label


def test_system_clock_satisfies_the_protocol() -> None:
    clock: Clock = SystemClock()
    first = clock.monotonic()
    assert clock.monotonic() >= first
    moment = clock.now_utc()
    assert moment.tzinfo is not None
    assert moment.utcoffset() == timedelta(0)
    assert moment.tzinfo is UTC


def test_an_explicit_label_is_kept_when_it_is_plain() -> None:
    assert resolve_host_label("build-runner-07") == "build-runner-07"


def test_an_explicit_label_is_escaped_to_ascii_and_bounded() -> None:
    assert resolve_host_label("caf" + chr(0xE9)) == "caf\\xe9"
    shown = resolve_host_label("h" * 1000)
    assert len(shown) == MAX_HOST_LABEL_CHARS
    assert shown.endswith("...")


@pytest.mark.parametrize("label", ["", "   ", "a\nb", "a\x1b[31m", "a\x00b"])
def test_an_unusable_explicit_label_is_refused(label: str) -> None:
    with pytest.raises(UsageError, match="--host-label"):
        resolve_host_label(label)


def test_the_default_comes_from_the_node_name_and_is_escaped(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(platform, "node", lambda: "box" + chr(0x202E) + "name\n")
    assert resolve_host_label(None) == "box\\u202ename"


def test_an_empty_node_name_gives_unknown(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(platform, "node", lambda: "  ")
    assert resolve_host_label(None) == UNKNOWN_HOST
