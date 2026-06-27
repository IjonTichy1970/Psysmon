"""Tests for the check base: error mapping, resolve, and the timeout/perform wrapper.

Also the reference pattern for check tests: ``async def`` tests driving a loopback
``tcp_server`` with the loopback ``check_ctx`` resolver.
"""

from __future__ import annotations

import asyncio
import errno
import socket

import pytest

from psysmon.checks import base
from psysmon.config.model import CheckType, Node
from psysmon.status import Status

from .conftest import FakeResolver


def node(host="h.example.net", port=0):
    return Node(hostname=host, check_type=CheckType.TCP, port=port)


def test_map_oserror():
    assert base.map_oserror(ConnectionRefusedError()) == Status.CONN_REFUSED
    assert base.map_oserror(OSError(errno.ENETUNREACH, "x")) == Status.NET_UNREACH
    assert base.map_oserror(OSError(errno.EHOSTUNREACH, "x")) == Status.HOST_DOWN
    assert base.map_oserror(OSError(errno.ETIMEDOUT, "x")) == Status.TIMED_OUT
    assert base.map_oserror(OSError(errno.EPIPE, "x")) == Status.CONN_REFUSED  # fallback


async def test_resolve_raises_on_failure():
    ctx = base.CheckContext(resolver=FakeResolver(default=None))
    with pytest.raises(base.NoDnsError):
        await base.resolve(node(), ctx)


async def test_resolve_passes_family_to_resolver():
    # Default resolves AF_INET (every existing caller); the v6 ping path passes AF_INET6.
    seen = []

    class SpyResolver:
        async def resolve(self, hostname, family=socket.AF_INET):
            seen.append(family)
            return "203.0.113.9"

    ctx = base.CheckContext(resolver=SpyResolver())
    assert await base.resolve(node(), ctx) == "203.0.113.9"
    assert await base.resolve(node(), ctx, family=socket.AF_INET6) == "203.0.113.9"
    assert seen == [socket.AF_INET, socket.AF_INET6]


async def test_open_check_connection_wraps_tls_for_implicit_tls_types(monkeypatch):
    # pop3s/imaps/ftps connect over TLS (SNI = the hostname); plaintext types don't (#88, #102).
    captured: dict = {}

    async def fake_open(ip, port, ctx, *, tls=False, server_hostname=None):
        captured.update(tls=tls, sni=server_hostname)

        class _RW:
            def close(self):
                pass

            async def wait_closed(self):
                pass

        return _RW(), _RW()

    monkeypatch.setattr(base, "open_connection", fake_open)
    ctx = base.CheckContext(resolver=FakeResolver())

    async with base.open_check_connection(
        Node(hostname="mx.example.net", check_type=CheckType.IMAPS), ctx
    ):
        pass
    assert captured == {"tls": True, "sni": "mx.example.net"}

    async with base.open_check_connection(
        Node(hostname="ftp.example.net", check_type=CheckType.FTPS), ctx
    ):
        pass
    assert captured == {"tls": True, "sni": "ftp.example.net"}  # ftps also implicit-TLS (#102)

    async with base.open_check_connection(
        Node(hostname="mx.example.net", check_type=CheckType.IMAP), ctx
    ):
        pass
    assert captured == {"tls": False, "sni": None}


async def test_perform_success_passthrough(check_ctx):
    async def ok(n, ctx):
        return Status.OK

    assert await base.perform(ok, node(), check_ctx) == Status.OK


async def test_perform_maps_nodns():
    ctx = base.CheckContext(resolver=FakeResolver(default=None))

    async def chk(n, c):
        await base.resolve(n, c)  # raises NoDnsError
        return Status.OK

    assert await base.perform(chk, node(), ctx) == Status.NO_DNS


async def test_perform_maps_oserror(check_ctx):
    async def refused(n, ctx):
        raise ConnectionRefusedError()

    assert await base.perform(refused, node(), check_ctx) == Status.CONN_REFUSED


async def test_perform_times_out():
    ctx = base.CheckContext(resolver=FakeResolver(), timeout_s=0.05)

    async def hang(n, c):
        await asyncio.sleep(10)
        return Status.OK

    assert await base.perform(hang, node(), ctx) == Status.TIMED_OUT


async def test_open_connection_roundtrip(check_ctx, tcp_server):
    async def handler(reader, writer):
        writer.write(b"hi\n")
        await writer.drain()
        writer.close()

    port = await tcp_server(handler)
    ip = await base.resolve(node(port=port), check_ctx)
    reader, writer = await base.open_connection(ip, port, check_ctx)
    line = await reader.readline()
    writer.close()
    await writer.wait_closed()
    assert line == b"hi\n"
