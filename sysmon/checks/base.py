"""Common check interface and exception-to-status mapping (Milestone 5).

Every checker implements ``Checker`` and returns a :class:`sysmon.status.Status` integer code
— it never raises for an *expected* failure. The central timeout wrapper and the standard
mapping (refused -> CONN_REFUSED, unreachable -> NET_UNREACH, timeout -> TIMED_OUT, DNS ->
NO_DNS, ...) live here so individual protocol modules stay thin.

Not yet implemented.
"""

from __future__ import annotations

from typing import Protocol

from sysmon.config.model import Node


class Checker(Protocol):
    """Async probe for one node; returns a ``Status`` code (0 == up)."""

    async def check(self, node: Node, deadline: float) -> int: ...


def map_exception(exc: BaseException) -> int:
    """Translate a socket/OS exception into a ``Status`` code."""
    raise NotImplementedError("Milestone 5: exception mapping")
