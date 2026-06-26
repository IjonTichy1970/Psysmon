"""Tests for the ICMP ping check.

The pure framing helpers (checksum / build / parse) run anywhere with no privilege and are
tested directly. The live raw-socket path requires raw-socket capability (root on Linux, admin
on Windows), so it is attempted and ``pytest.skip``-ped when the OS refuses the socket.
"""

from __future__ import annotations

import asyncio
import errno
import logging
import socket
import struct

import pytest

from psysmon.checks import base, ping
from psysmon.config.model import CheckType, Node
from psysmon.privilege import PrivilegeError, drop_privileges
from psysmon.status import Status

from .conftest import FakeResolver


def node(host="h.example.net"):
    return Node(hostname=host, check_type=CheckType.PING)


# --- pure helpers: checksum ---------------------------------------------------------------

def test_checksum_known_vector_all_zeros():
    # All-zero data: one's complement of 0 is 0xFFFF.
    assert ping.icmp_checksum(b"\x00\x00\x00\x00") == 0xFFFF


def test_checksum_known_vector():
    # 0x0001 + 0xF203 + 0xF4F5 + 0xF6F7 = 0x2DDF0; folded -> 0xDDF2; ~ -> 0x220D.
    data = struct.pack("!HHHH", 0x0001, 0xF203, 0xF4F5, 0xF6F7)
    assert ping.icmp_checksum(data) == 0x220D


def test_checksum_odd_length_pads():
    # Odd-length input is padded with a trailing zero byte, not rejected.
    assert ping.icmp_checksum(b"\x12\x34\x56") == ping.icmp_checksum(b"\x12\x34\x56\x00")


def test_checksum_valid_packet_sums_to_zero():
    # A packet that already carries a correct checksum must re-checksum to 0.
    packet = ping.build_echo_request(0x1234, 0x0001, b"abcd")
    assert ping.icmp_checksum(packet) == 0


# --- pure helpers: build / parse round-trip ----------------------------------------------

def _to_echo_reply(request: bytes) -> bytes:
    """Turn an ICMP echo *request* into a *reply* (flip type 8 -> 0, fix checksum)."""
    ident, seq = struct.unpack("!HH", request[4:8])
    payload = request[ping._ECHO_HEADER.size :]
    header = ping._ECHO_HEADER.pack(ping.ICMP_ECHO_REPLY, 0, 0, ident, seq)
    checksum = ping.icmp_checksum(header + payload)
    return ping._ECHO_HEADER.pack(ping.ICMP_ECHO_REPLY, 0, checksum, ident, seq) + payload


def _wrap_ipv4(icmp: bytes, ihl_words: int = 5) -> bytes:
    """Prepend a minimal IPv4 header (ihl_words * 4 bytes) to an ICMP message."""
    version_ihl = (4 << 4) | ihl_words
    header = bytes([version_ihl]) + b"\x00" * (ihl_words * 4 - 1)
    return header + icmp


def test_build_echo_request_header_fields():
    req = ping.build_echo_request(0xABCD, 0x0007, b"hello")
    msg_type, code, _csum, ident, seq = ping._ECHO_HEADER.unpack(req[: ping._ECHO_HEADER.size])
    assert (msg_type, code, ident, seq) == (ping.ICMP_ECHO_REQUEST, 0, 0xABCD, 0x0007)
    assert req[ping._ECHO_HEADER.size :] == b"hello"


def test_build_parse_round_trip():
    req = ping.build_echo_request(0x1111, 0x2222, b"payload")
    reply = _wrap_ipv4(_to_echo_reply(req))
    # parse returns (ident, seq, payload) — the payload is needed to verify the echoed nonce.
    assert ping.parse_echo_reply(reply) == (0x1111, 0x2222, b"payload")


def test_build_parse_round_trip_with_options_header():
    # IPv4 header with options (IHL > 5) must be skipped via the IHL nibble.
    req = ping.build_echo_request(0x0042, 0x0099, b"x")
    reply = _wrap_ipv4(_to_echo_reply(req), ihl_words=6)
    assert ping.parse_echo_reply(reply) == (0x0042, 0x0099, b"x")


def test_parse_returns_empty_payload_for_header_only_reply():
    # A header-only echo reply (no data) parses with an empty payload — the payload slice is
    # well-defined at the edge — which the demux then rejects (b"" cannot echo the nonce).
    reply = _wrap_ipv4(_to_echo_reply(ping.build_echo_request(0x7777, 0x0003, b"")))
    assert ping.parse_echo_reply(reply) == (0x7777, 0x0003, b"")


def test_parse_rejects_non_echo_reply():
    # An echo *request* (type 8) wrapped in IPv4 is not a reply -> None.
    req = ping.build_echo_request(0x1234, 0x0001, b"data")
    assert ping.parse_echo_reply(_wrap_ipv4(req)) is None


def test_parse_rejects_truncated_packet():
    assert ping.parse_echo_reply(b"") is None
    assert ping.parse_echo_reply(b"\x45" + b"\x00" * 10) is None  # short IPv4 datagram


def test_parse_rejects_non_ipv4():
    # Version nibble 6 (IPv6) is not handled here.
    reply = _to_echo_reply(ping.build_echo_request(1, 1, b"z"))
    packet = bytes([(6 << 4) | 5]) + b"\x00" * 19 + reply
    assert ping.parse_echo_reply(packet) is None


# --- pure helpers: IPv6 (ICMPv6) build / parse -------------------------------------------

def _to_echo_reply6(request: bytes) -> bytes:
    """Turn an ICMPv6 echo *request* (type 128) into a *reply* (type 129); checksum stays 0.

    On a raw AF_INET6 socket the kernel fills the checksum and does *not* prepend an IP header,
    so a reply frame is just the 8-byte ICMPv6 header + payload at offset 0 — no IPv4-style wrap.
    """
    ident, seq = struct.unpack("!HH", request[4:8])
    payload = request[ping._ECHO_HEADER.size :]
    return ping._ECHO_HEADER.pack(ping.ICMP6_ECHO_REPLY, 0, 0, ident, seq) + payload


def test_build_echo_request6_header_fields():
    req = ping.build_echo_request6(0xABCD, 0x0007, b"hello")
    msg_type, code, csum, ident, seq = ping._ECHO_HEADER.unpack(req[: ping._ECHO_HEADER.size])
    assert (msg_type, code, ident, seq) == (ping.ICMP6_ECHO_REQUEST, 0, 0xABCD, 0x0007)
    # Checksum left 0 — the kernel computes the real ICMPv6 checksum (over the IPv6 pseudo-header);
    # icmp_checksum must NOT be applied to a v6 frame.
    assert csum == 0
    assert req[ping._ECHO_HEADER.size :] == b"hello"


def test_build_echo_request6_masks_ident_seq_to_16_bits():
    # Over-16-bit ident/seq are masked (& 0xFFFF) — pins the masking a bare builder would skip.
    req = ping.build_echo_request6(0x1_0042, 0x1_0099, b"x")
    _t, _c, _csum, ident, seq = ping._ECHO_HEADER.unpack(req[: ping._ECHO_HEADER.size])
    assert (ident, seq) == (0x0042, 0x0099)


def test_build_parse_round_trip6():
    # No IP header on a raw AF_INET6 socket: the reply parses at offset 0.
    req = ping.build_echo_request6(0x1111, 0x2222, b"payload")
    assert ping.parse_echo_reply6(_to_echo_reply6(req)) == (0x1111, 0x2222, b"payload")


def test_parse6_returns_empty_payload_for_header_only_reply():
    # Header-only reply -> empty payload (the demux then rejects b"" — it can't echo the nonce).
    reply = _to_echo_reply6(ping.build_echo_request6(0x7777, 0x0003, b""))
    assert ping.parse_echo_reply6(reply) == (0x7777, 0x0003, b"")


def test_parse6_rejects_non_echo_reply():
    # An echo *request* (type 128) is not a reply (type 129) -> None.
    assert ping.parse_echo_reply6(ping.build_echo_request6(0x1234, 0x0001, b"data")) is None


def test_parse6_rejects_truncated_packet():
    assert ping.parse_echo_reply6(b"") is None
    assert ping.parse_echo_reply6(b"\x81\x00\x00\x00\x00") is None  # 5 bytes < 8-byte header
    assert ping.parse_echo_reply6(b"\x81" + b"\x00" * 6) is None    # 7 bytes — exact < 8 boundary


def test_parse6_rejects_ipv4_wrapped_packet():
    # The "no IHL skip" invariant: a v4-style reply (IPv4 header + ICMP) fed to the v6 parser
    # reads the IPv4 header's first byte (0x45) as the ICMPv6 type -> not 129 -> None. A raw v6
    # socket never delivers an IP header, so this only guards against cross-wiring the parsers.
    v4_reply = _wrap_ipv4(_to_echo_reply(ping.build_echo_request(0x1, 0x1, b"sixteen-byte-pad!")))
    assert ping.parse_echo_reply6(v4_reply) is None


def test_v4_parser_rejects_ipv6_frame():
    # The mirror: a raw ICMPv6 reply (no IP header, type 129) fed to the v4 parser fails its
    # version>>4 == 4 check (0x81 >> 4 == 8) -> None.
    v6_reply = _to_echo_reply6(ping.build_echo_request6(0x1, 0x1, b"sixteen-byte-pad!"))
    assert ping.parse_echo_reply(v6_reply) is None


# --- counter is monotonic, not random ----------------------------------------------------

def test_counter_increments_and_is_16bit():
    # Consecutive keys step by one through the 32-bit (ident << 16 | seq) space. The starting
    # point is randomized per process (anti-spoofing, #29), so assert the step, not the origin.
    svc = ping.PingService()
    keys = [svc._next_key() for _ in range(5)]
    values = [(ident << 16) | seq for ident, seq in keys]
    assert all(b == (a + 1) & 0xFFFFFFFF for a, b in zip(values, values[1:], strict=False))
    for ident, seq in keys:
        assert 0 <= ident <= 0xFFFF
        assert 0 <= seq <= 0xFFFF


def test_counter_seed_is_randomized():
    # Two fresh services almost certainly start from different (ident, seq) bases (a fixed seed
    # would make both start identical). Collision probability is 2**-32.
    assert ping.PingService()._next_key() != ping.PingService()._next_key()


# --- check() demux + retry logic (no privilege, no real raw socket) ----------------------
#
# The live raw-socket tests below skip on unprivileged/Windows hosts, so the actual
# demux + send/await/retry logic in check() would otherwise be untested. These drive
# check() against a fake socket to assert the real outcomes (OK + UNPINGABLE) anywhere.

class _FakeSocket:
    """Stand-in for the raw ICMP socket: records sends, optionally auto-replies."""

    def __init__(self):
        self.sent: list[tuple[bytes, object]] = []
        self.closed = False
        self.reply_for_sent = True  # if True, the next packet is "answered"
        self.answer_limit = None  # if set, only the first N sends are answered (loss simulation)
        self._answered = 0
        self.reply_src = None  # override the reply's source addr (default: from the target)
        self.mangle = False  # if True, reply with a bumped (ident,seq) that won't match
        self.mangle_payload = False  # if True, reply with the right (ident,seq) but a wrong nonce
        self.strip_payload = False  # if True, reply with the right (ident,seq) but NO payload
        self.pad = b""  # if set, echo the nonce followed by these trailing bytes (padding)
        self._inbox: list[tuple[bytes, tuple]] = []

    def sendto(self, packet, addr):
        self.sent.append((packet, addr))
        answer = self.reply_for_sent
        if answer and self.answer_limit is not None:
            answer = self._answered < self.answer_limit  # drop sends past the loss limit
        if answer:
            self._answered += 1
            # Echo it back as a reply (flip type 8 -> 0), wrapped in an IPv4 header, exactly as
            # the kernel would hand it to the raw socket — from the target's address, unless a
            # source override is set (a different source must STILL be accepted: the nonce, not
            # the address, authenticates the reply).
            src = self.reply_src if self.reply_src is not None else addr
            replied_to = packet
            if self.mangle:
                ident, seq = struct.unpack("!HH", packet[4:8])
                replied_to = ping.build_echo_request((ident + 1) & 0xFFFF, (seq + 1) & 0xFFFF)
            elif self.mangle_payload:
                # Right (ident,seq), but a payload that does not echo our per-probe nonce.
                ident, seq = struct.unpack("!HH", packet[4:8])
                replied_to = ping.build_echo_request(ident, seq, b"not-the-nonce-at-all")
            elif self.strip_payload:
                # Right (ident,seq), but a header-only reply that echoes no payload at all.
                ident, seq = struct.unpack("!HH", packet[4:8])
                replied_to = ping.build_echo_request(ident, seq, b"")
            elif self.pad:
                # Echo our nonce verbatim plus trailing bytes (a padding responder / middlebox).
                ident, seq = struct.unpack("!HH", packet[4:8])
                sent_payload = packet[ping._ECHO_HEADER.size :]
                replied_to = ping.build_echo_request(ident, seq, sent_payload + self.pad)
            self._inbox.append((_wrap_ipv4(_to_echo_reply(replied_to)), src))
        return len(packet)

    def recvfrom(self, _bufsize):
        if self._inbox:
            return self._inbox.pop(0)
        raise BlockingIOError

    def close(self):
        self.closed = True


def _pump_on_send(svc, sock):
    """Emulate add_reader: when a send queues a reply, deliver it to the demux next loop turn."""
    orig_sendto = sock.sendto

    def sendto_then_pump(packet, addr):
        n = orig_sendto(packet, addr)
        if sock._inbox:
            asyncio.get_running_loop().call_soon(svc._on_readable, sock)
        return n

    sock.sendto = sendto_then_pump  # type: ignore[method-assign]


def _install_fake_socket(svc, sock):
    """Wire a fake socket in as the unbound default pool socket and pump it from the loop."""
    svc._socks[None] = sock
    svc._registered.add(None)
    svc._socket_for = lambda source=None: sock  # type: ignore[method-assign]
    _pump_on_send(svc, sock)


def _install_fake_pool(svc, by_source):
    """Wire a {source: _FakeSocket} pool so check() picks a socket by ctx.source_ip (#70)."""
    for source, sock in by_source.items():
        svc._socks[source] = sock
        svc._registered.add(source)
        _pump_on_send(svc, sock)
    svc._socket_for = lambda source=None: by_source[source]  # type: ignore[method-assign]


async def test_check_ok_when_reply_arrives():
    svc = ping.PingService()
    sock = _FakeSocket()
    _install_fake_socket(svc, sock)

    ctx = base.CheckContext(resolver=FakeResolver(), timeout_s=2.0)
    result = await svc.check(node(), ctx)

    assert result == Status.OK
    assert len(sock.sent) == 1  # answered on the first attempt, no retries
    assert not svc._pending  # the future was cleaned up


async def test_check_unpingable_when_no_reply():
    svc = ping.PingService()
    sock = _FakeSocket()
    sock.reply_for_sent = False  # nothing ever answers
    _install_fake_socket(svc, sock)

    ctx = base.CheckContext(resolver=FakeResolver(), timeout_s=0.15)
    result = await svc.check(node(), ctx)

    assert result == Status.UNPINGABLE
    assert len(sock.sent) == 1 + ping._RETRIES  # every attempt was tried
    assert not svc._pending  # all futures cleaned up after timeout


async def test_check_mismatched_reply_ignored_via_real_demux():
    # A reply whose (ident, seq) doesn't match the in-flight probe must NOT satisfy the waiter.
    # This drives the REAL _on_readable demux (recvfrom -> parse_echo_reply -> _pending lookup),
    # not a stub, so the mismatch branch is genuinely exercised -> UNPINGABLE (#44).
    svc = ping.PingService()
    sock = _FakeSocket()
    sock.mangle = True  # the echoed reply carries a bumped (ident,seq) that won't match
    _install_fake_socket(svc, sock)

    ctx = base.CheckContext(resolver=FakeResolver(), timeout_s=0.15)
    result = await svc.check(node(), ctx)

    assert result == Status.UNPINGABLE
    assert not svc._pending  # the unmatched waiters were all cleaned up


async def test_check_reply_from_other_source_is_accepted():
    # A well-formed echo reply that echoes our probe's nonce must satisfy the waiter EVEN IF it
    # arrives from a different source IP than the pinged target. Routers commonly source an echo
    # reply from their egress interface, and asymmetric routing / NAT do the same; the old strict
    # source-IP match (#29) rejected these and read healthy gateways as UNPINGABLE. The per-probe
    # nonce — not the source address — is what authenticates a reply now. Driven through the REAL
    # _on_readable demux (not a mock).
    svc = ping.PingService()
    sock = _FakeSocket()
    sock.reply_src = ("203.0.113.50", 0)  # a different source than the target (cf. the report)
    _install_fake_socket(svc, sock)

    ctx = base.CheckContext(resolver=FakeResolver(default="198.51.100.10"), timeout_s=2.0)
    result = await svc.check(node(), ctx)

    assert result == Status.OK  # different source, but the nonce matched -> up
    assert len(sock.sent) == 1  # answered on the first attempt, no retries
    assert not svc._pending  # waiters cleaned up


async def test_check_reply_with_wrong_nonce_is_rejected():
    # A reply matching the in-flight (ident, seq) but NOT echoing our per-probe nonce must be
    # ignored — this is the anti-forgery check that replaced the strict source-IP match (#29).
    # An off-path host that guessed the (randomized) id/seq still cannot produce the right nonce.
    # Driven through the REAL _on_readable demux (not a mock).
    svc = ping.PingService()
    sock = _FakeSocket()
    sock.mangle_payload = True  # right (ident,seq), wrong payload
    _install_fake_socket(svc, sock)

    ctx = base.CheckContext(resolver=FakeResolver(), timeout_s=0.15)
    result = await svc.check(node(), ctx)

    assert result == Status.UNPINGABLE  # wrong-nonce reply ignored -> probe times out
    assert len(sock.sent) == 1 + ping._RETRIES  # every attempt was tried
    assert not svc._pending  # waiters cleaned up


async def test_check_reply_from_other_source_with_wrong_nonce_is_rejected():
    # The invariant the whole fix rests on: the source address is irrelevant, the NONCE is the
    # gate. A reply from a FOREIGN source AND with a wrong nonce — the exact off-path forgery the
    # nonce defends against (an attacker who guessed (ident,seq) but cannot know the nonce) — must
    # be rejected. This pins BOTH halves at once: dropping the source check (so a router-sourced
    # reply is accepted, #53) did NOT weaken the nonce gate. A regression that re-coupled source
    # handling to acceptance would fail here even though the two single-axis tests still pass.
    svc = ping.PingService()
    sock = _FakeSocket()
    sock.reply_src = ("203.0.113.99", 0)  # foreign source ...
    sock.mangle_payload = True  # ... and a payload that does not echo our nonce
    _install_fake_socket(svc, sock)

    ctx = base.CheckContext(resolver=FakeResolver(default="198.51.100.5"), timeout_s=0.15)
    result = await svc.check(node(), ctx)

    assert result == Status.UNPINGABLE
    assert len(sock.sent) == 1 + ping._RETRIES  # every attempt was tried
    assert not svc._pending


async def test_check_reply_with_padded_nonce_is_accepted():
    # The demux uses payload.startswith(nonce), not ==, so a reply that echoes the nonce followed
    # by trailing bytes (some stacks / middleboxes pad the ICMP payload) is still accepted. This
    # locks in that deliberate prefix tolerance: a future tightening to `==` would silently break
    # padding responders — the same false-UNPINGABLE class as #29 — and this test would catch it.
    svc = ping.PingService()
    sock = _FakeSocket()
    sock.pad = b"-trailing-padding-bytes"
    _install_fake_socket(svc, sock)

    ctx = base.CheckContext(resolver=FakeResolver(), timeout_s=2.0)
    result = await svc.check(node(), ctx)

    assert result == Status.OK  # nonce + padding still matches the nonce prefix -> up
    assert len(sock.sent) == 1  # answered on the first attempt
    assert not svc._pending


async def test_check_reply_with_empty_payload_is_rejected():
    # A well-formed echo reply matching (ident,seq) but carrying NO payload cannot echo the nonce,
    # so it must not resolve the waiter (b"".startswith(nonce) is False). Guards the empty-payload
    # boundary now that the payload — not the source — is the only thing gating a match.
    svc = ping.PingService()
    sock = _FakeSocket()
    sock.strip_payload = True
    _install_fake_socket(svc, sock)

    ctx = base.CheckContext(resolver=FakeResolver(), timeout_s=0.15)
    result = await svc.check(node(), ctx)

    assert result == Status.UNPINGABLE  # header-only reply ignored -> probe times out
    assert not svc._pending


async def test_check_resolve_failure_returns_no_dns_before_socket():
    # resolve() failure maps to NO_DNS (not a raised exception) before any socket work, so the
    # scheduler always gets a verdict; check never sends. (Regression: an escaping exception
    # left ping nodes with no result and silently suppressed their whole subtree — issue #25.)
    svc = ping.PingService()
    sock = _FakeSocket()
    _install_fake_socket(svc, sock)

    ctx = base.CheckContext(resolver=FakeResolver(default=None), timeout_s=2.0)
    assert await svc.check(node(), ctx) == Status.NO_DNS
    assert sock.sent == []  # nothing was sent


async def test_check_unsendable_route_error_maps_to_status():
    # A sendto() that fails with no-route must become a Status code (here HOST_DOWN), never an
    # exception that escapes check() and blacks out the node's whole gated subtree (issue #25).
    svc = ping.PingService()
    sock = _FakeSocket()

    def unreachable(packet, addr):
        raise OSError(errno.EHOSTUNREACH, "No route to host")

    sock.sendto = unreachable  # type: ignore[method-assign]
    _install_fake_socket(svc, sock)  # wraps the raising sendto; the raise still propagates

    ctx = base.CheckContext(resolver=FakeResolver(), timeout_s=0.3)
    assert await svc.check(node(), ctx) == Status.HOST_DOWN
    assert not svc._pending  # the pending future was cleaned up despite the send error


# --- loss-tolerant ping (send_pings / min_pings -> OK / Degraded / Unpingable, #22) -------


def test_invalid_ping_counts_rejected_at_construction():
    # A bad global pair is rejected up front (so the daemon reports a clean startup error).
    with pytest.raises(ValueError):
        ping.PingService(send_pings=2, min_pings=3)  # can't require more replies than sent
    with pytest.raises(ValueError):
        ping.PingService(send_pings=0, min_pings=0)  # both must be >= 1


async def test_loss_tolerant_all_replies_is_ok():
    svc = ping.PingService(send_pings=4, min_pings=3)
    sock = _FakeSocket()  # answers every echo
    _install_fake_socket(svc, sock)

    ctx = base.CheckContext(resolver=FakeResolver(), timeout_s=0.3)
    assert await svc.check(node(), ctx) == Status.OK
    assert len(sock.sent) == 4  # all four echoes were sent (not first-reply-wins)
    assert not svc._pending


async def test_loss_tolerant_partial_loss_is_degraded():
    # 2 of 4 replies, min_pings=3 -> reachable but lossy -> the new DEGRADED code.
    svc = ping.PingService(send_pings=4, min_pings=3)
    sock = _FakeSocket()
    sock.answer_limit = 2
    _install_fake_socket(svc, sock)

    ctx = base.CheckContext(resolver=FakeResolver(), timeout_s=0.3)
    assert await svc.check(node(), ctx) == Status.DEGRADED
    assert len(sock.sent) == 4
    assert not svc._pending


async def test_loss_tolerant_at_threshold_is_ok():
    # received == min_pings exactly -> OK (the boundary is inclusive).
    svc = ping.PingService(send_pings=4, min_pings=2)
    sock = _FakeSocket()
    sock.answer_limit = 2
    _install_fake_socket(svc, sock)

    ctx = base.CheckContext(resolver=FakeResolver(), timeout_s=0.3)
    assert await svc.check(node(), ctx) == Status.OK


async def test_loss_tolerant_total_loss_is_unpingable():
    # Zero replies keeps the unchanged total-loss verdict, not DEGRADED.
    svc = ping.PingService(send_pings=4, min_pings=2)
    sock = _FakeSocket()
    sock.reply_for_sent = False
    _install_fake_socket(svc, sock)

    ctx = base.CheckContext(resolver=FakeResolver(), timeout_s=0.3)
    assert await svc.check(node(), ctx) == Status.UNPINGABLE
    assert len(sock.sent) == 4
    assert not svc._pending


async def test_per_node_counts_override_global_default():
    # The service default is 1/1 (single-probe path), but a node asking for send_pings=3 takes
    # the loss-tolerant path and sends three echoes.
    svc = ping.PingService()  # 1/1 globally
    sock = _FakeSocket()
    sock.answer_limit = 0  # nothing answers
    _install_fake_socket(svc, sock)

    n = Node(hostname="h.example.net", check_type=CheckType.PING, send_pings=3, min_pings=2)
    ctx = base.CheckContext(resolver=FakeResolver(), timeout_s=0.3)
    assert await svc.check(n, ctx) == Status.UNPINGABLE
    assert len(sock.sent) == 3  # the per-node send_pings=3 took effect, not the global 1


async def test_per_node_invalid_counts_are_clamped():
    # A programmatic per-node min_pings > send_pings is clamped to a sane range (not left to mean
    # "can never read up"). The legacy grammar can't produce this; a future per-node config (#3)
    # should reject it at load instead.
    svc = ping.PingService()
    sock = _FakeSocket()  # answers all
    _install_fake_socket(svc, sock)

    n = Node(hostname="h.example.net", check_type=CheckType.PING, send_pings=3, min_pings=9)
    ctx = base.CheckContext(resolver=FakeResolver(), timeout_s=0.3)
    assert await svc.check(n, ctx) == Status.OK  # 3/3 replies, min clamped to 3 -> OK
    assert len(sock.sent) == 3


async def test_default_counts_use_single_probe_path():
    # 1/1 (the default) must still take the unchanged single-probe + retry path, not the
    # loss-tolerant one — first reply wins, exactly one send when answered.
    svc = ping.PingService()  # 1/1
    sock = _FakeSocket()
    _install_fake_socket(svc, sock)

    ctx = base.CheckContext(resolver=FakeResolver(), timeout_s=2.0)
    assert await svc.check(node(), ctx) == Status.OK
    assert len(sock.sent) == 1  # single-probe path: answered on the first attempt, no extra sends


# --- prepare() / lazy reader attach (no privilege, fake socket) --------------------------


class _CountingSocket:
    """Minimal fake raw socket: tracks close + exposes a stable fileno for add_reader."""

    _next_fd = 5000

    def __init__(self):
        _CountingSocket._next_fd += 1
        self._fd = _CountingSocket._next_fd
        self.closed = False

    def fileno(self):
        return self._fd

    def close(self):
        self.closed = True


async def test_prepare_opens_socket_without_attaching_reader(monkeypatch):
    # prepare() opens the raw socket up front (as root would, pre-fork) but does NOT
    # attach the reply reader; the first check attaches it exactly once.
    svc = ping.PingService()
    opens: list[_CountingSocket] = []
    monkeypatch.setattr(svc, "_open_raw",
                        lambda source=None: opens.append(_CountingSocket()) or opens[-1])

    loop = asyncio.get_running_loop()
    adds: list[int] = []
    removes: list[int] = []
    monkeypatch.setattr(loop, "add_reader", lambda fd, *a: adds.append(fd))
    monkeypatch.setattr(loop, "remove_reader", lambda fd: removes.append(fd))

    svc.prepare()
    assert svc._socks.get(None) is not None and None not in svc._registered
    assert len(opens) == 1 and adds == []  # unbound socket open, reader not yet attached

    first = svc._ensure_socket(None)
    assert None in svc._registered and len(adds) == 1  # attached exactly once
    second = svc._ensure_socket(None)
    assert second is first and len(adds) == 1  # idempotent: same socket, no re-attach
    assert len(opens) == 1  # prepare()'s socket was reused, not reopened

    svc.close()
    assert svc._socks == {} and svc._registered == set()
    assert removes == [first.fileno()] and first.closed is True


async def test_prepare_opens_one_socket_per_configured_source(monkeypatch):
    # prepare() pre-opens the unbound default PLUS one socket per declared bound source (#70).
    svc = ping.PingService()
    svc.set_sources(["203.0.113.5", "203.0.113.9"])
    bound: list = []
    monkeypatch.setattr(svc, "_open_raw",
                        lambda source=None: bound.append(source) or _CountingSocket())

    svc.prepare()
    assert set(svc._socks) == {None, "203.0.113.5", "203.0.113.9"}
    assert sorted(b for b in bound if b) == ["203.0.113.5", "203.0.113.9"]
    assert None in bound  # the unbound default was opened too


async def test_ensure_socket_opens_when_prepare_skipped(monkeypatch):
    # If prepare() is never called, the first check still opens AND attaches the reader.
    svc = ping.PingService()
    monkeypatch.setattr(svc, "_open_raw", lambda source=None: _CountingSocket())
    loop = asyncio.get_running_loop()
    adds: list[int] = []
    monkeypatch.setattr(loop, "add_reader", lambda fd, *a: adds.append(fd))
    monkeypatch.setattr(loop, "remove_reader", lambda fd: None)

    svc._ensure_socket(None)
    assert svc._socks.get(None) is not None and None in svc._registered and len(adds) == 1


# --- #70: source-keyed socket pool ------------------------------------------------------

async def test_check_sends_on_the_socket_for_ctx_source():
    # check() picks the pooled socket by ctx.source_ip: a bound source uses its socket; an
    # unset source uses the unbound default. Both still resolve OK via the nonce demux.
    svc = ping.PingService()
    unbound, bound = _FakeSocket(), _FakeSocket()
    _install_fake_pool(svc, {None: unbound, "203.0.113.5": bound})

    r1 = await svc.check(node(), base.CheckContext(
        resolver=FakeResolver(), timeout_s=2.0, source_ip="203.0.113.5"))
    r2 = await svc.check(node(), base.CheckContext(resolver=FakeResolver(), timeout_s=2.0))

    assert r1 == Status.OK and r2 == Status.OK
    assert len(bound.sent) == 1 and len(unbound.sent) == 1  # each went out its own socket


async def test_socket_for_falls_back_to_unbound_when_bind_fails(monkeypatch, caplog):
    # A bound source that can't be opened now (e.g. a reload after privilege drop) falls back to
    # the pre-opened unbound socket, warning once (#70).
    svc = ping.PingService()
    unbound = _CountingSocket()
    svc._socks[None] = unbound
    svc._registered.add(None)

    def boom(source=None):
        if source is not None:
            raise PermissionError("operation not permitted")
        return unbound

    monkeypatch.setattr(svc, "_open_raw", boom)
    with caplog.at_level(logging.WARNING, logger="psysmon.checks.ping"):
        sock = svc._socket_for("203.0.113.5")
    assert sock is unbound and "203.0.113.5" in caplog.text

    caplog.clear()
    assert svc._socket_for("203.0.113.5") is unbound  # still falls back
    assert "203.0.113.5" not in caplog.text           # but warns only once


async def test_socket_for_does_not_retry_a_known_bad_source(monkeypatch):
    # A source recorded as unbindable is fast-pathed to the unbound default with NO further
    # _open_raw attempt — _warned_unbindable is load-bearing, not just cosmetic (#70 review).
    svc = ping.PingService()
    unbound = _CountingSocket()
    svc._socks[None] = unbound
    svc._registered.add(None)
    opens: list = []

    def boom(source=None):
        opens.append(source)
        if source is not None:
            raise PermissionError("operation not permitted")
        return unbound

    monkeypatch.setattr(svc, "_open_raw", boom)
    svc._socket_for("203.0.113.5")  # first: attempts the bind, fails, records it
    svc._socket_for("203.0.113.5")  # second: must NOT attempt _open_raw again
    svc._socket_for("203.0.113.5")
    assert opens == ["203.0.113.5"]  # exactly one bind attempt for the dead source


async def test_prune_closes_dropped_bound_sockets(monkeypatch):
    # On reload, sockets for sources the new config dropped are closed; the unbound default and
    # still-configured sources are kept (#70 review).
    svc = ping.PingService()
    svc.set_sources(["203.0.113.5", "203.0.113.9"])
    monkeypatch.setattr(svc, "_open_raw", lambda source=None: _CountingSocket())
    loop = asyncio.get_running_loop()
    removes: list[int] = []
    monkeypatch.setattr(loop, "add_reader", lambda fd, *a: None)
    monkeypatch.setattr(loop, "remove_reader", lambda fd: removes.append(fd))

    svc.prepare()
    for src in (None, "203.0.113.5", "203.0.113.9"):
        svc._ensure_socket(src)
    dropped = svc._socks["203.0.113.9"]

    svc.prune(["203.0.113.5"])  # 203.0.113.9 no longer configured
    assert set(svc._socks) == {None, "203.0.113.5"}  # unbound + the kept source remain
    assert dropped.closed is True and dropped.fileno() in removes
    assert "203.0.113.9" not in svc._registered


async def test_close_iterates_the_whole_pool(monkeypatch):
    svc = ping.PingService()
    svc.set_sources(["203.0.113.5"])
    monkeypatch.setattr(svc, "_open_raw", lambda source=None: _CountingSocket())
    loop = asyncio.get_running_loop()
    removes: list[int] = []
    monkeypatch.setattr(loop, "add_reader", lambda fd, *a: None)
    monkeypatch.setattr(loop, "remove_reader", lambda fd: removes.append(fd))

    svc.prepare()                       # unbound + the bound source = 2 sockets
    svc._ensure_socket(None)            # register both readers
    svc._ensure_socket("203.0.113.5")
    socks = list(svc._socks.values())
    svc.close()
    assert svc._socks == {} and svc._registered == set()
    assert all(s.closed for s in socks) and len(removes) == 2  # every socket closed + unwired


# --- privilege module --------------------------------------------------------------------

def test_drop_privileges_importable_and_guards():
    # Importable everywhere; without root (or on Windows) it raises a clear error.
    with pytest.raises(PrivilegeError):
        drop_privileges()


# --- live raw-socket path (skipped where unprivileged / unsupported) ----------------------

def _can_open_raw_icmp() -> bool:
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_ICMP)
    except (PermissionError, OSError):
        return False
    s.close()
    return True


async def _raw_icmp_demux_supported() -> bool:
    """Raw socket opens *and* the running loop supports add_reader (not Windows Proactor)."""
    if not _can_open_raw_icmp():
        return False
    s = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_ICMP)
    try:
        asyncio.get_running_loop().add_reader(s.fileno(), lambda: None)
    except NotImplementedError:
        return False
    else:
        asyncio.get_running_loop().remove_reader(s.fileno())
        return True
    finally:
        s.close()


async def test_ping_localhost_ok():
    if not await _raw_icmp_demux_supported():
        pytest.skip("raw ICMP socket not permitted (unprivileged or unsupported OS)")

    ctx = base.CheckContext(resolver=FakeResolver(), timeout_s=2.0)
    svc = ping.PingService()
    try:
        result = await svc.check(node(), ctx)
    finally:
        svc.close()
    assert result == Status.OK


async def test_ping_unpingable_address():
    if not await _raw_icmp_demux_supported():
        pytest.skip("raw ICMP socket not permitted (unprivileged or unsupported OS)")

    # 192.0.2.1 is TEST-NET-1 (RFC 5737): guaranteed never to answer.
    ctx = base.CheckContext(resolver=FakeResolver(default="192.0.2.1"), timeout_s=0.6)
    svc = ping.PingService()
    try:
        result = await svc.check(node(), ctx)
    finally:
        svc.close()
    assert result == Status.UNPINGABLE


async def test_ping_no_dns_propagates():
    # NO_DNS does not need a raw socket: resolve() fails before the socket is opened.
    ctx = base.CheckContext(resolver=FakeResolver(default=None), timeout_s=2.0)
    svc = ping.PingService()
    assert await base.perform(svc.check, node(), ctx) == Status.NO_DNS
    assert svc._socks == {}  # never reached socket creation.
