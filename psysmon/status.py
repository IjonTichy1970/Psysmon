"""Check status codes and their display strings.

Ported verbatim from the original C ``config.h`` (the ``SYSM_*`` defines) and ``lib.c``
(``errtostr`` and ``type_to_name``). A check returns one of these integer codes;
``OK == 0`` means up, and every nonzero code is a distinct failure reason.

Keeping the exact integer values and display strings preserves compatibility with the
status page and with operators' muscle memory.
"""

from __future__ import annotations

from enum import IntEnum


class Status(IntEnum):
    """Result of a single check (``SYSM_*`` in the original config.h)."""

    OK = 0
    CONN_REFUSED = 1
    NET_UNREACH = 2
    HOST_DOWN = 3
    TIMED_OUT = 4
    NO_DNS = 5
    UNPINGABLE = 6
    THROTTLED = 7
    NO_AUTH = 8
    NO_RESPONSE = 9
    IN_PROGRESS = 10
    BAD_AUTH = 11
    BAD_RESPONSE = 12
    X500_WEDGED = 13
    # psysmon-only code, outside the legacy 0..13 range: a loss-tolerant ping that got some
    # replies but fewer than min_pings — reachable but lossy (#22). 0.93 never had a code for it.
    DEGRADED = 14


# errtostr() — human-readable status, used in the status file's "Status" column.
_STATUS_TEXT: dict[int, str] = {
    Status.OK: "up",
    Status.CONN_REFUSED: "Conn Ref",
    Status.NET_UNREACH: "Net Unrch",
    Status.HOST_DOWN: "Host Down",
    Status.TIMED_OUT: "Conn Timed Out",
    Status.NO_DNS: "No dns entry",
    Status.UNPINGABLE: "Unpingable",
    Status.THROTTLED: "Thrttl",
    Status.NO_AUTH: "No Auth",
    Status.NO_RESPONSE: "No Srvr Resp",
    Status.IN_PROGRESS: "Conn in prog",
    Status.BAD_AUTH: "Bad Auth",
    Status.BAD_RESPONSE: "Bad Resp",
    Status.X500_WEDGED: "Wedged",
    Status.DEGRADED: "Degraded",
}


def errtostr(value: int) -> str:
    """Return the display string for a status code (``errtostr`` in lib.c)."""
    return _STATUS_TEXT.get(value, "ERROR")


def is_up(value: int) -> bool:
    """True if the code means the service is fully up.

    ``DEGRADED`` is deliberately *not* up — a lossy host is shown as a problem and does not reset
    an outage. For "is this host reachable enough to check what's behind it", use
    :func:`is_reachable`.
    """
    return value == Status.OK


def is_reachable(value: int) -> bool:
    """True if the host is reachable enough to forward to its dependents (up *or* degraded).

    Dependency suppression gates a child on its ancestor pings being reachable, not strictly up:
    a degraded (lossy-but-answering) router still forwards packets, so suppressing everything
    behind it would mask real outages there. Only a fully-down ancestor (UNPINGABLE, etc.)
    suppresses its subtree. ``DEGRADED`` only ever comes from a loss-tolerant ping (#22).
    """
    return value == Status.OK or value == Status.DEGRADED
