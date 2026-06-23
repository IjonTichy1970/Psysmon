"""In-process DNS cache.

Reproduces the original ``dnscache.c`` intent — reduce nameserver load — as a hostname ->
(address, resolved_at) map with a ``dnsexpire`` TTL and ``dnslog`` periodic stats, plus
single-flight coalescing so a burst of checks for the same host triggers one lookup.

Unlike the original (which resolved at config-load time and *dropped* hosts that failed),
resolution happens at check time and a failure surfaces as ``None`` (the checker turns that
into ``Status.NO_DNS``) without removing the node — so transient DNS failures self-heal.

The actual lookup and the clock are injectable so the cache is testable without real DNS.
Satisfies :class:`psysmon.checks.base.Resolver`.
"""

from __future__ import annotations

import asyncio
import socket
import time
from collections.abc import Awaitable, Callable

ResolveFn = Callable[[str], Awaitable[str | None]]


async def _system_resolve(hostname: str) -> str | None:
    """Resolve via the event loop's getaddrinfo (first IPv4 address), or None on failure."""
    loop = asyncio.get_running_loop()
    try:
        infos = await loop.getaddrinfo(
            hostname, None, family=socket.AF_INET, type=socket.SOCK_STREAM
        )
    except socket.gaierror:
        return None
    return infos[0][4][0] if infos else None


class DnsCache:
    """Async DNS resolver with TTL expiry, single-flight, and hit/miss stats."""

    def __init__(
        self,
        expire_s: float = 900.0,
        log_s: float = 600.0,
        *,
        resolve_fn: ResolveFn | None = None,
        monotonic: Callable[[], float] = time.monotonic,
    ) -> None:
        self._expire_s = expire_s
        self._log_s = log_s
        self._resolve_fn = resolve_fn or _system_resolve
        self._monotonic = monotonic
        self._cache: dict[str, tuple[str, float]] = {}
        self._locks: dict[str, asyncio.Lock] = {}
        self._hits = 0
        self._misses = 0
        self._expired = 0

    def _fresh(self, hostname: str, now: float) -> str | None:
        entry = self._cache.get(hostname)
        if entry is not None and (now - entry[1]) < self._expire_s:
            return entry[0]
        return None

    async def resolve(self, hostname: str) -> str | None:
        """Return a cached or freshly-resolved IP for ``hostname`` (or None on failure)."""
        cached = self._fresh(hostname, self._monotonic())
        if cached is not None:
            self._hits += 1
            return cached

        lock = self._locks.setdefault(hostname, asyncio.Lock())
        async with lock:
            # Another waiter may have populated the cache while we waited for the lock.
            cached = self._fresh(hostname, self._monotonic())
            if cached is not None:
                self._hits += 1
                return cached
            self._misses += 1
            if self._cache.pop(hostname, None) is not None:
                # A previously-cached entry aged out: count one expiration and evict it, so a host
                # that now fails to resolve isn't re-counted as "expired" on every retry.
                self._expired += 1
            ip = await self._resolve_fn(hostname)
            if ip is not None:
                self._cache[hostname] = (ip, self._monotonic())
            return ip

    @property
    def stats(self) -> dict[str, int]:
        """Cache statistics for the periodic ``dnslog`` line."""
        return {
            "hits": self._hits,
            "misses": self._misses,
            "expired": self._expired,
            "entries": len(self._cache),
        }
