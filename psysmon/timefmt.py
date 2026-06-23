"""Small shared time-formatting helpers (used by the notifier and the status output).

Reproduces the original C display formats: a clock timestamp without the year (``timedata``
in lib.c) and a ``DD:HH:MM`` elapsed duration (``str_difftime``).
"""

from __future__ import annotations

import time


def clock_time(epoch: float, *, never_if_zero: bool = False) -> str:
    """Format ``epoch`` as ``Mon DD HH:MM:SS`` (local time), no year.

    With ``never_if_zero``, a falsy/zero epoch renders ``"Never"`` (for a node that has not
    failed yet) — matching the original ``timedata(NULL)``.
    """
    if never_if_zero and not epoch:
        return "Never"
    return time.strftime("%b %d %H:%M:%S", time.localtime(epoch))


def duration(seconds: float) -> str:
    """Format a span of ``seconds`` as ``DD:HH:MM`` (clamped at zero)."""
    secs = max(0, int(seconds))
    days, rem = divmod(secs, 86400)
    hours, rem = divmod(rem, 3600)
    minutes = rem // 60
    return f"{days:02d}:{hours:02d}:{minutes:02d}"


def elapsed(since: float, now: float) -> str:
    """Format the elapsed time from ``since`` to ``now`` as ``DD:HH:MM``."""
    return duration(now - since)
