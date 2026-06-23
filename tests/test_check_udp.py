"""Tests for the UDP/DNS reachability probe.

Hermetic: a tiny loopback UDP DNS responder is stood up inside each test via
``loop.create_datagram_endpoint`` so no real network or DNS is touched.
"""

from __future__ import annotations

import asyncio

import dns.message
import dns.rdata
import dns.rdataclass
import dns.rdatatype

from psysmon.checks import base, udp
from psysmon.config.model import CheckType, Node
from psysmon.status import Status

from .conftest import FakeResolver


def node(host="dns.example.net", port=53):
    return Node(hostname=host, check_type=CheckType.UDP, port=port)


class _DnsResponder(asyncio.DatagramProtocol):
    """Parses each datagram as a DNS message and replies with a valid response."""

    def __init__(self, *, with_answer: bool = True):
        self._with_answer = with_answer
        self.transport: asyncio.DatagramTransport | None = None

    def connection_made(self, transport: asyncio.BaseTransport) -> None:
        self.transport = transport  # type: ignore[assignment]

    def datagram_received(self, data: bytes, addr) -> None:
        query = dns.message.from_wire(data)
        response = dns.message.make_response(query)
        if self._with_answer:
            qname = query.question[0].name
            rrset = response.find_rrset(
                response.answer, qname, dns.rdataclass.IN, dns.rdatatype.A, create=True
            )
            rrset.add(dns.rdata.from_text("IN", "A", "127.0.0.1"), ttl=60)
        assert self.transport is not None
        self.transport.sendto(response.to_wire(), addr)


async def _start_responder(*, with_answer: bool = True):
    """Bind a loopback UDP DNS responder; return (transport, port)."""
    loop = asyncio.get_running_loop()
    transport, _ = await loop.create_datagram_endpoint(
        lambda: _DnsResponder(with_answer=with_answer),
        local_addr=("127.0.0.1", 0),
    )
    port = transport.get_extra_info("sockname")[1]
    return transport, port


async def test_udp_up_with_answer(check_ctx):
    transport, port = await _start_responder(with_answer=True)
    try:
        assert await udp.check(node(port=port), check_ctx) == Status.OK
    finally:
        transport.close()


async def test_udp_up_empty_response(check_ctx):
    # Any reply means reachable — even a response carrying no answer records.
    transport, port = await _start_responder(with_answer=False)
    try:
        assert await udp.check(node(port=port), check_ctx) == Status.OK
    finally:
        transport.close()


async def test_udp_up_via_perform(check_ctx):
    transport, port = await _start_responder(with_answer=True)
    try:
        assert await base.perform(udp.check, node(port=port), check_ctx) == Status.OK
    finally:
        transport.close()


async def test_udp_no_response(free_port):
    # No responder bound on this port -> dns timeout -> NO_RESPONSE.
    ctx = base.CheckContext(resolver=FakeResolver(), timeout_s=0.3)
    assert await udp.check(node(port=free_port), ctx) == Status.NO_RESPONSE


async def test_udp_no_dns_via_perform():
    ctx = base.CheckContext(resolver=FakeResolver(default=None), timeout_s=2.0)
    assert await base.perform(udp.check, node(), ctx) == Status.NO_DNS
