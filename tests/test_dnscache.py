"""Tests for the in-process DNS cache."""

from __future__ import annotations

import asyncio
import socket

from psysmon.engine.dnscache import DnsCache


class Clock:
    def __init__(self) -> None:
        self.t = 0.0

    def __call__(self) -> float:
        return self.t


def test_caches_within_ttl():
    calls = []

    async def resolver(host, family):
        calls.append(host)
        return "10.0.0.1"

    async def go():
        cache = DnsCache(expire_s=100, resolve_fn=resolver)
        assert await cache.resolve("a.example.net") == "10.0.0.1"
        assert await cache.resolve("a.example.net") == "10.0.0.1"
        assert calls == ["a.example.net"]  # second hit served from cache
        assert cache.stats == {"hits": 1, "misses": 1, "expired": 0, "entries": 1}

    asyncio.run(go())


def test_ttl_expiry_reresolves():
    calls = []
    clock = Clock()

    async def resolver(host, family):
        calls.append(host)
        return "10.0.0.1"

    async def go():
        cache = DnsCache(expire_s=100, resolve_fn=resolver, monotonic=clock)
        await cache.resolve("a.example.net")
        clock.t = 50
        await cache.resolve("a.example.net")  # still fresh
        clock.t = 200
        await cache.resolve("a.example.net")  # expired -> re-resolve
        assert calls == ["a.example.net", "a.example.net"]
        # The aged-out entry counts as one expiration; the fresh hit at t=50 does not.
        assert cache.stats["expired"] == 1
        assert cache.stats["hits"] == 1 and cache.stats["misses"] == 2

    asyncio.run(go())


def test_expired_counts_each_aging_cumulatively():
    clock = Clock()

    async def resolver(host, family):
        return "10.0.0.1"

    async def go():
        cache = DnsCache(expire_s=100, resolve_fn=resolver, monotonic=clock)
        await cache.resolve("a.example.net")    # t=0: first resolve, cached
        clock.t = 200
        await cache.resolve("a.example.net")    # aged out -> expired #1, re-cached
        clock.t = 400
        await cache.resolve("a.example.net")    # aged out again -> expired #2
        assert cache.stats["expired"] == 2  # cumulative across periods

    asyncio.run(go())


def test_expired_not_recounted_when_resolution_keeps_failing():
    clock = Clock()
    answers = ["10.0.0.1", None, None]

    async def resolver(host, family):
        return answers.pop(0) if answers else None

    async def go():
        cache = DnsCache(expire_s=100, resolve_fn=resolver, monotonic=clock)
        await cache.resolve("a.example.net")    # t=0 -> cached
        clock.t = 200
        await cache.resolve("a.example.net")    # aged out -> expired=1; now resolves None (evicted)
        clock.t = 400
        await cache.resolve("a.example.net")    # no stale entry left -> NOT re-counted as expired
        assert cache.stats["expired"] == 1

    asyncio.run(go())


def test_single_flight_coalesces():
    started = 0

    async def slow(host, family):
        nonlocal started
        started += 1
        await asyncio.sleep(0.05)
        return "10.0.0.1"

    async def go():
        cache = DnsCache(resolve_fn=slow)
        results = await asyncio.gather(*[cache.resolve("a.example.net") for _ in range(5)])
        assert results == ["10.0.0.1"] * 5
        assert started == 1  # one lookup served all five waiters

    asyncio.run(go())


def test_failure_not_cached():
    calls = []

    async def failing(host, family):
        calls.append(host)
        return None

    async def go():
        cache = DnsCache(resolve_fn=failing)
        assert await cache.resolve("bad.example.net") is None
        assert await cache.resolve("bad.example.net") is None
        assert calls == ["bad.example.net", "bad.example.net"]  # negative results re-tried
        assert cache.stats["expired"] == 0  # an entry that was never cached can't expire

    asyncio.run(go())


def test_cache_keys_by_family():
    # An A and an AAAA lookup of the SAME host must not clobber each other (the cache-key fix).
    calls = []

    async def resolver(host, family):
        calls.append((host, family))
        return "203.0.113.7" if family == socket.AF_INET else "2001:db8::7"

    async def go():
        cache = DnsCache(expire_s=100, resolve_fn=resolver)
        assert await cache.resolve("a.example.net", socket.AF_INET) == "203.0.113.7"
        assert await cache.resolve("a.example.net", socket.AF_INET6) == "2001:db8::7"
        # Each family is cached independently — the second pair of calls is served from cache.
        assert await cache.resolve("a.example.net", socket.AF_INET) == "203.0.113.7"
        assert await cache.resolve("a.example.net", socket.AF_INET6) == "2001:db8::7"
        assert calls == [
            ("a.example.net", socket.AF_INET),
            ("a.example.net", socket.AF_INET6),
        ]
        assert cache.stats["entries"] == 2

    asyncio.run(go())


def test_default_family_is_ipv4():
    # resolve() without a family resolves A records (AF_INET) — existing callers unchanged.
    seen = []

    async def resolver(host, family):
        seen.append(family)
        return "203.0.113.1"

    async def go():
        cache = DnsCache(resolve_fn=resolver)
        await cache.resolve("a.example.net")
        assert seen == [socket.AF_INET]

    asyncio.run(go())


def test_single_flight_is_per_family():
    # The single-flight lock is keyed by (host, family), so a concurrent A+AAAA burst for the same
    # host coalesces to one lookup PER FAMILY and the two families run CONCURRENTLY. A regression
    # that reverted the lock to a bare-hostname key would serialize the families — caught here
    # deterministically as a timeout (the barrier never releases), not a flaky timing margin.
    started = []

    async def go():
        both_started = asyncio.Event()

        async def slow(host, family):
            started.append(family)
            if {socket.AF_INET, socket.AF_INET6} <= set(started):
                both_started.set()
            # Block until the OTHER family has also entered; serialized families deadlock here.
            await asyncio.wait_for(both_started.wait(), timeout=1.0)
            return "203.0.113.7" if family == socket.AF_INET else "2001:db8::7"

        cache = DnsCache(resolve_fn=slow)
        v4 = [cache.resolve("a.example.net", socket.AF_INET) for _ in range(3)]
        v6 = [cache.resolve("a.example.net", socket.AF_INET6) for _ in range(3)]
        results = await asyncio.gather(*v4, *v6)
        assert results == ["203.0.113.7"] * 3 + ["2001:db8::7"] * 3
        # Six concurrent waiters coalesced into exactly two lookups — one per family.
        assert started.count(socket.AF_INET) == 1
        assert started.count(socket.AF_INET6) == 1

    asyncio.run(go())
