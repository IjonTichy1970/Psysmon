"""Tests for the telnet connection/banner check (#106).

Drives the real checker against a loopback server. Up if the server sends any initial data (IAC
negotiation or a banner); an immediate close is No Response. Never authenticates.
"""

from __future__ import annotations

from psysmon.checks import base, telnet
from psysmon.config.model import CheckType, Node
from psysmon.status import Status

from .conftest import FakeResolver


def node(port: int = 0) -> Node:
    return Node(hostname="device.example.net", check_type=CheckType.TELNET, port=port)


async def _send_then_close(data: bytes):
    """A server that sends ``data`` (if any) on connect, then closes."""
    async def handler(reader, writer):
        if data:
            writer.write(data)
            await writer.drain()
        writer.close()

    return handler


async def test_iac_negotiation_is_ok(check_ctx, tcp_server):
    # A real telnet server begins with IAC option negotiation (0xFF ...).
    port = await tcp_server(await _send_then_close(b"\xff\xfd\x03\xff\xfb\x01"))
    assert await telnet.check(node(port=port), check_ctx) == Status.OK


async def test_plaintext_banner_is_ok(check_ctx, tcp_server):
    # Some servers send a login banner/prompt instead — also a live service.
    port = await tcp_server(await _send_then_close(b"\r\nDevice OS 1.0\r\nlogin: "))
    assert await telnet.check(node(port=port), check_ctx) == Status.OK


async def test_immediate_close_is_no_response(check_ctx, tcp_server):
    # Accept the connection then close without sending anything -> No Response.
    port = await tcp_server(await _send_then_close(b""))
    assert await telnet.check(node(port=port), check_ctx) == Status.NO_RESPONSE


async def test_silent_but_open_times_out(tcp_server):
    # A server that accepts and holds the connection open but never speaks reads as Timed Out (the
    # documented limitation: a conformant-yet-quiet telnetd is indistinguishable from a dead port).
    async def silent_open(reader, writer):
        try:
            await reader.read()  # block until the peer (the check) gives up and closes -> EOF
        finally:
            writer.close()

    port = await tcp_server(silent_open)
    ctx = base.CheckContext(resolver=FakeResolver(), timeout_s=0.3)
    assert await base.perform(telnet.check, node(port=port), ctx) == Status.TIMED_OUT


async def test_default_port_used(check_ctx, monkeypatch):
    # port=0 must fall back to the telnet default (23).
    from psysmon.config.model import DEFAULT_PORT

    captured: dict[str, int] = {}

    async def fake_open_connection(ip, port, ctx, *, tls=False, server_hostname=None):
        captured["port"] = port

        class _Reader:
            async def read(self, _n):
                return b"\xff\xfd\x18"

        class _Writer:
            def close(self):
                pass

            async def wait_closed(self):
                pass

        return _Reader(), _Writer()

    monkeypatch.setattr(base, "open_connection", fake_open_connection)
    assert await telnet.check(node(port=0), check_ctx) == Status.OK
    assert captured["port"] == DEFAULT_PORT[CheckType.TELNET] == 23


async def test_perform_no_dns():
    ctx = base.CheckContext(resolver=FakeResolver(default=None), timeout_s=2.0)
    assert await base.perform(telnet.check, node(), ctx) == Status.NO_DNS


async def test_perform_connection_failure(check_ctx, free_port):
    result = await base.perform(telnet.check, node(port=free_port), check_ctx)
    assert result in (Status.CONN_REFUSED, Status.TIMED_OUT, Status.HOST_DOWN)
    assert result != Status.OK
