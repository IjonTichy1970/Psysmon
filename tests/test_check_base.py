"""Tests for the check base: error mapping, resolve, and the timeout/perform wrapper.

Also the reference pattern for check tests: ``async def`` tests driving a loopback
``tcp_server`` with the loopback ``check_ctx`` resolver.
"""

from __future__ import annotations

import asyncio
import errno

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
