"""Clock abstraction so the scheduler and re-page timers are testable with a fake clock.

The scheduler measures *intervals* on a monotonic clock and records *wall-clock* event
times (outage start, last-up) for display. Both are routed through a ``Clock`` so tests can
drive time deterministically (see :class:`ManualClock`).
"""

from __future__ import annotations

import time
from typing import Protocol


class Clock(Protocol):
    """Source of monotonic and wall-clock time."""

    def monotonic(self) -> float: ...
    def wall(self) -> float: ...


class SystemClock:
    """Real clock backed by :mod:`time`."""

    def monotonic(self) -> float:
        return time.monotonic()

    def wall(self) -> float:
        return time.time()


class ManualClock:
    """Test clock with explicitly advanced time."""

    def __init__(self, monotonic: float = 0.0, wall: float = 0.0) -> None:
        self._mono = monotonic
        self._wall = wall

    def monotonic(self) -> float:
        return self._mono

    def wall(self) -> float:
        return self._wall

    def advance(self, seconds: float) -> None:
        """Advance both clocks by ``seconds``."""
        self._mono += seconds
        self._wall += seconds
