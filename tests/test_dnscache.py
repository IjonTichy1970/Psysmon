"""Tests for the in-process DNS cache."""

from __future__ import annotations

import asyncio

from psysmon.engine.dnscache import DnsCache


class Clock:
    def __init__(self) -> None:
        self.t = 0.0

    def __call__(self) -> float:
        return self.t


def test_caches_within_ttl():
    calls = []

    async def resolver(host):
        calls.append(host)
        return "10.0.0.1"

    async def go():
        cache = DnsCache(expire_s=100, resolve_fn=resolver)
        assert await cache.resolve("a.net") == "10.0.0.1"
        assert await cache.resolve("a.net") == "10.0.0.1"
        assert calls == ["a.net"]  # second hit served from cache
        assert cache.stats == {"hits": 1, "misses": 1, "expired": 0, "entries": 1}

    asyncio.run(go())


def test_ttl_expiry_reresolves():
    calls = []
    clock = Clock()

    async def resolver(host):
        calls.append(host)
        return "10.0.0.1"

    async def go():
        cache = DnsCache(expire_s=100, resolve_fn=resolver, monotonic=clock)
        await cache.resolve("a.net")
        clock.t = 50
        await cache.resolve("a.net")  # still fresh
        clock.t = 200
        await cache.resolve("a.net")  # expired -> re-resolve
        assert calls == ["a.net", "a.net"]
        # The aged-out entry counts as one expiration; the fresh hit at t=50 does not.
        assert cache.stats["expired"] == 1
        assert cache.stats["hits"] == 1 and cache.stats["misses"] == 2

    asyncio.run(go())


def test_expired_counts_each_aging_cumulatively():
    clock = Clock()

    async def resolver(host):
        return "10.0.0.1"

    async def go():
        cache = DnsCache(expire_s=100, resolve_fn=resolver, monotonic=clock)
        await cache.resolve("a.net")    # t=0: first resolve, cached
        clock.t = 200
        await cache.resolve("a.net")    # aged out -> expired #1, re-cached
        clock.t = 400
        await cache.resolve("a.net")    # aged out again -> expired #2
        assert cache.stats["expired"] == 2  # cumulative across periods

    asyncio.run(go())


def test_expired_not_recounted_when_resolution_keeps_failing():
    clock = Clock()
    answers = ["10.0.0.1", None, None]

    async def resolver(host):
        return answers.pop(0) if answers else None

    async def go():
        cache = DnsCache(expire_s=100, resolve_fn=resolver, monotonic=clock)
        await cache.resolve("a.net")    # t=0 -> cached
        clock.t = 200
        await cache.resolve("a.net")    # aged out -> expired=1, but now resolves to None (evicted)
        clock.t = 400
        await cache.resolve("a.net")    # no stale entry left -> NOT re-counted as expired
        assert cache.stats["expired"] == 1

    asyncio.run(go())


def test_single_flight_coalesces():
    started = 0

    async def slow(host):
        nonlocal started
        started += 1
        await asyncio.sleep(0.05)
        return "10.0.0.1"

    async def go():
        cache = DnsCache(resolve_fn=slow)
        results = await asyncio.gather(*[cache.resolve("a.net") for _ in range(5)])
        assert results == ["10.0.0.1"] * 5
        assert started == 1  # one lookup served all five waiters

    asyncio.run(go())


def test_failure_not_cached():
    calls = []

    async def failing(host):
        calls.append(host)
        return None

    async def go():
        cache = DnsCache(resolve_fn=failing)
        assert await cache.resolve("bad.net") is None
        assert await cache.resolve("bad.net") is None
        assert calls == ["bad.net", "bad.net"]  # negative results re-tried
        assert cache.stats["expired"] == 0  # an entry that was never cached can't expire

    asyncio.run(go())
