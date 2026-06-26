"""Common check plumbing: context, DNS resolve, timeout wrapper, and error mapping.

Every checker is a coroutine ``async def check(node, ctx) -> int`` returning a
:class:`psysmon.status.Status` code. Checkers focus on protocol logic and may raise ordinary
socket/OS exceptions; :func:`perform` wraps a checker with the context's timeout and maps
expected failures to status codes, so individual protocol modules stay thin and never have to
reproduce the same try/except.

Each check's first step is DNS resolution via :func:`resolve` (backed by the shared
:class:`~psysmon.engine.dnscache.DnsCache`); a resolution failure surfaces as ``NO_DNS`` without
the node being dropped — the runtime-resolution fix over the original.
"""

from __future__ import annotations

import asyncio
import errno
import socket
from collections.abc import AsyncIterator, Awaitable, Callable
from contextlib import asynccontextmanager
from dataclasses import dataclass
from typing import Protocol

import dns.asyncquery
import dns.exception
import dns.message

from psysmon.config.model import DEFAULT_PORT, Node
from psysmon.status import Status

DEFAULT_TIMEOUT_S = 10.0


class Resolver(Protocol):
    """Resolves a hostname to an IP string, or ``None`` on failure."""

    async def resolve(
        self, hostname: str, family: socket.AddressFamily = socket.AF_INET
    ) -> str | None: ...


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


async def resolve(
    node: Node, ctx: CheckContext, *, family: socket.AddressFamily = socket.AF_INET
) -> str:
    """Resolve ``node.hostname`` to an IP, raising :class:`NoDnsError` on failure.

    ``family`` selects the address family — ``AF_INET`` by default, so every existing caller
    resolves IPv4 unchanged; the IPv6 ping path passes ``AF_INET6`` for AAAA resolution.
    """
    ip = await ctx.resolver.resolve(node.hostname, family)
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


def effective_port(node: Node) -> int | None:
    """The node's port, falling back to the check type's default — the single owner of that
    fallback (the parser already assigns it, but hand-built nodes may not)."""
    return node.port or DEFAULT_PORT.get(node.check_type)


@asynccontextmanager
async def open_check_connection(
    node: Node, ctx: CheckContext, *, port: int | None = None
) -> AsyncIterator[tuple[asyncio.StreamReader, asyncio.StreamWriter]]:
    """Resolve + open a TCP connection for a stream check, always tearing it down cleanly.

    Centralizes the resolve -> effective-port -> open_connection scaffolding shared by the
    tcp/smtp/pop3 checks and guarantees the same teardown everywhere (``close()`` +
    ``wait_closed()``), so the contract can't drift between checkers.
    """
    ip = await resolve(node, ctx)
    use_port = port if port is not None else effective_port(node)
    reader, writer = await open_connection(ip, use_port, ctx)
    try:
        yield reader, writer
    finally:
        writer.close()
        await writer.wait_closed()


async def graceful_quit(writer: asyncio.StreamWriter) -> None:
    """Send the line-protocol ``QUIT`` both SMTP and POP3 use to end a session politely."""
    writer.write(b"QUIT\r\n")
    await writer.drain()


async def dns_udp_query(
    query: dns.message.Message, ip: str, ctx: CheckContext, *, port: int
) -> tuple[int | None, dns.message.Message | None]:
    """Send a DNS query over UDP with the kwargs shared by the udp and authoritative-dns checks.

    Returns ``(None, response)`` on success, or ``(status_code, None)`` when the exchange fails:
    a DNS-level timeout -> ``NO_RESPONSE``; any other ``DNSException`` (malformed reply,
    unexpected source, ...) -> ``BAD_RESPONSE``. OS/socket errors propagate to :func:`perform`.
    Centralizing this keeps the exception mapping in one place for both checks.
    """
    try:
        response = await dns.asyncquery.udp(
            query, ip, timeout=ctx.timeout_s, port=port, source=ctx.source_ip
        )
    except dns.exception.Timeout:
        return Status.NO_RESPONSE, None
    except dns.exception.DNSException:
        return Status.BAD_RESPONSE, None
    return None, response
