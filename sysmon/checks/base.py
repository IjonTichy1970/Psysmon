"""Common check plumbing: context, DNS resolve, timeout wrapper, and error mapping.

Every checker is a coroutine ``async def check(node, ctx) -> int`` returning a
:class:`sysmon.status.Status` code. Checkers focus on protocol logic and may raise ordinary
socket/OS exceptions; :func:`perform` wraps a checker with the context's timeout and maps
expected failures to status codes, so individual protocol modules stay thin and never have to
reproduce the same try/except.

Each check's first step is DNS resolution via :func:`resolve` (backed by the shared
:class:`~sysmon.engine.dnscache.DnsCache`); a resolution failure surfaces as ``NO_DNS`` without
the node being dropped — the runtime-resolution fix over the original.
"""

from __future__ import annotations

import asyncio
import errno
import socket
from collections.abc import Awaitable, Callable
from dataclasses import dataclass
from typing import Protocol

from sysmon.config.model import Node
from sysmon.status import Status

DEFAULT_TIMEOUT_S = 10.0


class Resolver(Protocol):
    """Resolves a hostname to an IP string, or ``None`` on failure."""

    async def resolve(self, hostname: str) -> str | None: ...


@dataclass(slots=True)
class CheckContext:
    """Per-run dependencies shared by every checker."""

    resolver: Resolver
    timeout_s: float = DEFAULT_TIMEOUT_S
    source_ip: str | None = None  # outbound bind source (ACL-load-bearing)


class NoDnsError(Exception):
    """Raised by :func:`resolve` when a hostname cannot be resolved."""


# A checker maps (node, ctx) -> Status code.
Checker = Callable[[Node, CheckContext], Awaitable[int]]


async def resolve(node: Node, ctx: CheckContext) -> str:
    """Resolve ``node.hostname`` to an IP, raising :class:`NoDnsError` on failure."""
    ip = await ctx.resolver.resolve(node.hostname)
    if not ip:
        raise NoDnsError(node.hostname)
    return ip


async def open_connection(
    ip: str, port: int, ctx: CheckContext
) -> tuple[asyncio.StreamReader, asyncio.StreamWriter]:
    """Open a TCP connection, binding the configured source IP if set."""
    local_addr = (ctx.source_ip, 0) if ctx.source_ip else None
    return await asyncio.open_connection(ip, port, local_addr=local_addr)


def map_oserror(exc: OSError) -> int:
    """Translate a socket/OS error into a ``Status`` code (matching the original's codes)."""
    if isinstance(exc, ConnectionRefusedError) or exc.errno == errno.ECONNREFUSED:
        return Status.CONN_REFUSED
    if exc.errno == errno.ENETUNREACH:
        return Status.NET_UNREACH
    if exc.errno in (errno.EHOSTUNREACH, errno.EHOSTDOWN):
        return Status.HOST_DOWN
    if exc.errno == errno.ETIMEDOUT:
        return Status.TIMED_OUT
    return Status.CONN_REFUSED


async def perform(checker: Checker, node: Node, ctx: CheckContext) -> int:
    """Run ``checker`` under the context timeout, mapping expected failures to status codes."""
    try:
        async with asyncio.timeout(ctx.timeout_s):
            return await checker(node, ctx)
    except NoDnsError:
        return Status.NO_DNS
    except TimeoutError:
        return Status.TIMED_OUT
    except socket.gaierror:
        return Status.NO_DNS
    except OSError as exc:
        return map_oserror(exc)
