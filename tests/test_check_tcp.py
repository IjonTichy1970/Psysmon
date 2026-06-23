"""Tests for the TCP connect-reachability check."""

from __future__ import annotations

from psysmon.checks import base, tcp
from psysmon.config.model import CheckType, Node
from psysmon.status import Status

from .conftest import FakeResolver


def node(host: str = "h.net", port: int = 0) -> Node:
    return Node(hostname=host, check_type=CheckType.TCP, port=port)


async def test_tcp_up(check_ctx, tcp_server):
    async def handler(reader, writer):
        writer.close()

    port = await tcp_server(handler)
    assert await base.perform(tcp.check, node(port=port), check_ctx) == Status.OK


async def test_tcp_connection_refused(check_ctx, free_port):
    # On Windows the ProactorEventLoop surfaces a loopback refusal only after the SYN
    # retransmit (~2s), so use a generous timeout to let the real refusal win the race
    # against the deadline (the mapping itself is covered by base's test_perform_maps_oserror).
    ctx = base.CheckContext(resolver=check_ctx.resolver, timeout_s=10.0)
    assert await base.perform(tcp.check, node(port=free_port), ctx) == Status.CONN_REFUSED


async def test_tcp_no_dns():
    ctx = base.CheckContext(resolver=FakeResolver(default=None), timeout_s=2.0)
    assert await base.perform(tcp.check, node(port=80), ctx) == Status.NO_DNS


async def test_tcp_direct_returns_ok(check_ctx, tcp_server):
    async def handler(reader, writer):
        writer.close()

    port = await tcp_server(handler)
    assert await tcp.check(node(port=port), check_ctx) == Status.OK
