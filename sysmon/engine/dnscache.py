"""In-process DNS cache (Milestone 5).

Reproduces the original ``dnscache.c`` intent — reduce nameserver load — as a hostname ->
(address, resolved_at) map with a ``dnsexpire`` TTL and periodic ``dnslog`` stats. Adds
single-flight coalescing and TTL jitter to avoid thundering herds.

Unlike the original (which resolved at config-load time and *dropped* hosts that failed),
resolution happens at check time and a failure surfaces as ``Status.NO_DNS`` without removing
the node — so transient DNS failures self-heal.

Not yet implemented.
"""

from __future__ import annotations


class DnsCache:
    """Async DNS resolver with expiry and periodic stats."""

    def __init__(self, expire_s: float, log_s: float) -> None:
        self._expire_s = expire_s
        self._log_s = log_s

    async def resolve(self, hostname: str) -> str | None:
        """Return a cached/fresh IP for ``hostname`` (or None on failure)."""
        raise NotImplementedError("Milestone 5: DNS cache")
