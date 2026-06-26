"""Tests for the SSH identification-banner check (#96)."""

from __future__ import annotations

from psysmon.checks import base, ssh
from psysmon.config.model import CheckType, Node
from psysmon.status import Status

from .conftest import FakeResolver


def node(host="ssh.example.net", port=22):
    return Node(hostname=host, check_type=CheckType.SSH, port=port)


async def _banner_handler(text: bytes):
    async def handler(reader, writer):
        writer.write(text)
        await writer.drain()
        writer.close()
        await writer.wait_closed()

    return handler


async def test_ok_on_ssh2_banner(check_ctx, tcp_server):
    port = await tcp_server(await _banner_handler(b"SSH-2.0-OpenSSH_9.6\r\n"))
    assert await ssh.check(node(port=port), check_ctx) == Status.OK


async def test_ok_on_ssh199_banner(check_ctx, tcp_server):
    port = await tcp_server(await _banner_handler(b"SSH-1.99-Cisco\r\n"))
    assert await ssh.check(node(port=port), check_ctx) == Status.OK


async def test_bad_response_on_non_ssh(check_ctx, tcp_server):
    port = await tcp_server(await _banner_handler(b"220 this is smtp\r\n"))
    assert await ssh.check(node(port=port), check_ctx) == Status.BAD_RESPONSE


async def test_no_response_on_immediate_close(check_ctx, tcp_server):
    async def handler(reader, writer):
        writer.close()
        await writer.wait_closed()

    port = await tcp_server(handler)
    assert await ssh.check(node(port=port), check_ctx) == Status.NO_RESPONSE


async def test_perform_ok(check_ctx, tcp_server):
    port = await tcp_server(await _banner_handler(b"SSH-2.0-OpenSSH_9.6\r\n"))
    assert await base.perform(ssh.check, node(port=port), check_ctx) == Status.OK


async def test_ok_on_banner_without_newline(check_ctx, tcp_server):
    # A banner with no trailing newline still returns the buffered bytes at EOF -> OK.
    port = await tcp_server(await _banner_handler(b"SSH-2.0-NoNewline"))
    assert await ssh.check(node(port=port), check_ctx) == Status.OK


async def test_bad_response_on_flood_without_newline(check_ctx, tcp_server):
    # A flooding peer (no newline, over the buffer limit) -> ValueError -> BAD_RESPONSE via perform,
    # not an uncaught crash (#96; the guard is shared with smtp/pop3/imap).
    async def handler(reader, writer):
        try:
            for _ in range(4):
                writer.write(b"A" * 65536)
                await writer.drain()
        except (ConnectionError, OSError):
            pass
        writer.close()
        await writer.wait_closed()

    port = await tcp_server(handler)
    assert await base.perform(ssh.check, node(port=port), check_ctx) == Status.BAD_RESPONSE


async def test_perform_conn_refused(free_port):
    ctx = base.CheckContext(resolver=FakeResolver(), timeout_s=10.0)
    assert await base.perform(ssh.check, node(port=free_port), ctx) == Status.CONN_REFUSED
