"""Tests for the SMTP banner check."""

from __future__ import annotations

from psysmon.checks import base, smtp
from psysmon.config.model import CheckType, Node
from psysmon.status import Status

from .conftest import FakeResolver


def node(host="mail.net", port=25):
    return Node(hostname=host, check_type=CheckType.SMTP, port=port)


async def _greeting_handler(text: bytes):
    async def handler(reader, writer):
        writer.write(text)
        await writer.drain()
        # Read whatever the client sends (e.g. QUIT) then close.
        await reader.readline()
        writer.close()
        await writer.wait_closed()

    return handler


async def test_ok_on_220(check_ctx, tcp_server):
    port = await tcp_server(await _greeting_handler(b"220 ready\r\n"))
    assert await smtp.check(node(port=port), check_ctx) == Status.OK


async def test_bad_response_on_other_code(check_ctx, tcp_server):
    port = await tcp_server(await _greeting_handler(b"554 no\r\n"))
    assert await smtp.check(node(port=port), check_ctx) == Status.BAD_RESPONSE


async def test_no_response_on_immediate_close(check_ctx, tcp_server):
    async def handler(reader, writer):
        writer.close()
        await writer.wait_closed()

    port = await tcp_server(handler)
    assert await smtp.check(node(port=port), check_ctx) == Status.NO_RESPONSE


async def test_perform_ok(check_ctx, tcp_server):
    port = await tcp_server(await _greeting_handler(b"220 ready\r\n"))
    assert await base.perform(smtp.check, node(port=port), check_ctx) == Status.OK


async def test_perform_conn_refused(free_port):
    # The Windows Proactor loop can take a couple of seconds to surface the refusal, so give
    # perform() enough headroom that the CONN_REFUSED wins the race against the timeout.
    ctx = base.CheckContext(resolver=FakeResolver(), timeout_s=10.0)
    assert await base.perform(smtp.check, node(port=free_port), ctx) == Status.CONN_REFUSED


async def test_perform_no_dns(free_port):
    ctx = base.CheckContext(resolver=FakeResolver(default=None), timeout_s=2.0)
    assert await base.perform(smtp.check, node(port=free_port), ctx) == Status.NO_DNS
