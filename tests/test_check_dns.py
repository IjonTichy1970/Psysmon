"""Tests for the authoritative DNS check.

Drives :func:`psysmon.checks.dns.check` against a hermetic loopback UDP DNS responder built
with dnspython, covering the OK / BAD_RESPONSE / NO_RESPONSE classifications plus NO_DNS and
the DNS-level timeout path.
"""

from __future__ import annotations

import asyncio
from collections.abc import Callable

import dns.exception
import dns.flags
import dns.message
import dns.rcode
import dns.rdataclass
import dns.rdatatype
import dns.rrset
import pytest

from psysmon.checks import base
from psysmon.checks import dns as dns_check
from psysmon.config.model import CheckType, Node
from psysmon.status import Status

from .conftest import FakeResolver

QUERY_NAME = "host.example.com"


def node(port: int, name: str = QUERY_NAME, host: str = "ns.example.com") -> Node:
    return Node(hostname=host, check_type=CheckType.DNS, port=port, username=name)


class _DnsProtocol(asyncio.DatagramProtocol):
    """Minimal UDP DNS responder; ``reply`` builds a response from the incoming query."""

    def __init__(self, reply: Callable[[dns.message.Message], dns.message.Message]):
        self._reply = reply
        self.transport: asyncio.DatagramTransport | None = None

    def connection_made(self, transport: asyncio.BaseTransport) -> None:
        self.transport = transport  # type: ignore[assignment]

    def datagram_received(self, data: bytes, addr: object) -> None:
        request = dns.message.from_wire(data)
        response = self._reply(request)
        assert self.transport is not None
        self.transport.sendto(response.to_wire(), addr)


@pytest.fixture
async def dns_server():
    """Start loopback UDP DNS responders on demand; ``await start(reply) -> port``."""
    transports: list[asyncio.DatagramTransport] = []
    loop = asyncio.get_running_loop()

    async def start(reply: Callable[[dns.message.Message], dns.message.Message]) -> int:
        transport, _ = await loop.create_datagram_endpoint(
            lambda: _DnsProtocol(reply), local_addr=("127.0.0.1", 0)
        )
        transports.append(transport)
        return transport.get_extra_info("sockname")[1]

    yield start

    for transport in transports:
        transport.close()


def _answering_reply(request: dns.message.Message) -> dns.message.Message:
    response = dns.message.make_response(request)
    qname = request.question[0].name
    rrset = dns.rrset.from_text(qname, 300, dns.rdataclass.IN, dns.rdatatype.A, "127.0.0.1")
    response.answer.append(rrset)
    response.flags |= dns.flags.AA
    return response


def _rcode_reply(rcode: int) -> Callable[[dns.message.Message], dns.message.Message]:
    def reply(request: dns.message.Message) -> dns.message.Message:
        response = dns.message.make_response(request)
        response.set_rcode(rcode)
        return response

    return reply


def _empty_noerror_reply(request: dns.message.Message) -> dns.message.Message:
    # NOERROR with an empty answer section (e.g. a name that exists with no A record).
    return dns.message.make_response(request)


async def test_dns_answer_is_ok(check_ctx, dns_server):
    port = await dns_server(_answering_reply)
    assert await dns_check.check(node(port), check_ctx) == Status.OK


async def test_dns_nxdomain_is_bad_response(check_ctx, dns_server):
    port = await dns_server(_rcode_reply(dns.rcode.NXDOMAIN))
    assert await dns_check.check(node(port), check_ctx) == Status.BAD_RESPONSE


async def test_dns_servfail_is_bad_response(check_ctx, dns_server):
    port = await dns_server(_rcode_reply(dns.rcode.SERVFAIL))
    assert await dns_check.check(node(port), check_ctx) == Status.BAD_RESPONSE


async def test_dns_noerror_no_answer_is_no_response(check_ctx, dns_server):
    port = await dns_server(_empty_noerror_reply)
    assert await dns_check.check(node(port), check_ctx) == Status.NO_RESPONSE


async def test_dns_timeout_is_no_response():
    # A responder that never replies, with a short DNS-level timeout, yields NO_RESPONSE.
    loop = asyncio.get_running_loop()

    async def dead_start() -> int:
        # An open but non-responding UDP endpoint (drops every datagram).
        transport, _ = await loop.create_datagram_endpoint(
            asyncio.DatagramProtocol, local_addr=("127.0.0.1", 0)
        )
        return transport.get_extra_info("sockname")[1]

    port = await dead_start()
    ctx = base.CheckContext(resolver=FakeResolver(), timeout_s=0.2)
    assert await dns_check.check(node(port), ctx) == Status.NO_RESPONSE


async def test_dns_no_dns_via_perform(check_ctx):
    ctx = base.CheckContext(resolver=FakeResolver(default=None), timeout_s=2.0)
    assert await base.perform(dns_check.check, node(53), ctx) == Status.NO_DNS


async def test_dns_bad_response_on_non_timeout_dns_exception(monkeypatch):
    # A non-Timeout DNSException (malformed wire data, unexpected source, ...) must map to
    # BAD_RESPONSE rather than escape uncaught and produce no verdict every tick (issue #26).
    async def boom(*args, **kwargs):
        raise dns.exception.FormError("malformed response")

    monkeypatch.setattr("dns.asyncquery.udp", boom)
    ctx = base.CheckContext(resolver=FakeResolver(), timeout_s=0.3)
    assert await dns_check.check(node(53), ctx) == Status.BAD_RESPONSE


async def test_dns_request_uses_non_recursive_query(check_ctx, dns_server):
    seen: dict[str, object] = {}

    def reply(request: dns.message.Message) -> dns.message.Message:
        seen["rd"] = bool(request.flags & dns.flags.RD)
        seen["qname"] = request.question[0].name.to_text()
        return _answering_reply(request)

    port = await dns_server(reply)
    assert await dns_check.check(node(port), check_ctx) == Status.OK
    assert seen["rd"] is False
    assert seen["qname"] == QUERY_NAME + "."
