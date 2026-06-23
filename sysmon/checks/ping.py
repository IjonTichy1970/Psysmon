"""ICMP echo ping (Milestone 7).

Reproduces ``icmp.c`` but modern and concurrent: a single shared raw ICMP socket opened as
root, registered with ``loop.add_reader``; outbound echo requests carry a monotonic 16-bit
identifier/sequence, and replies are demultiplexed to per-request futures. The socket is
optionally ``bind()``-ed to the configured source IP (ACL-load-bearing). One unanswered echo
after the retry budget -> ``Status.UNPINGABLE``.

The raw socket is opened before privileges are dropped (see :mod:`sysmon.privilege`) and kept
open across the drop.

Not yet implemented.
"""

from __future__ import annotations

from sysmon.config.model import Node


class PingService:
    """Owns the shared raw ICMP socket and demuxes echo replies by identifier."""

    def __init__(self, source_ip: str | None = None) -> None:
        self._source_ip = source_ip

    async def check(self, node: Node, deadline: float) -> int:
        """Send an echo request and await a matching reply (or time out)."""
        raise NotImplementedError("Milestone 7: ICMP ping")
