"""Tests for the ICMP ping check.

The pure framing helpers (checksum / build / parse) run anywhere with no privilege and are
tested directly. The live raw-socket path requires raw-socket capability (root on Linux, admin
on Windows), so it is attempted and ``pytest.skip``-ped when the OS refuses the socket.
"""

from __future__ import annotations

import asyncio
import socket
import struct

import pytest

from psysmon.checks import base, ping
from psysmon.config.model import CheckType, Node
from psysmon.privilege import PrivilegeError, drop_privileges
from psysmon.status import Status

from .conftest import FakeResolver


def node(host="h.net"):
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
    assert ping.parse_echo_reply(reply) == (0x1111, 0x2222)


def test_build_parse_round_trip_with_options_header():
    # IPv4 header with options (IHL > 5) must be skipped via the IHL nibble.
    req = ping.build_echo_request(0x0042, 0x0099, b"x")
    reply = _wrap_ipv4(_to_echo_reply(req), ihl_words=6)
    assert ping.parse_echo_reply(reply) == (0x0042, 0x0099)


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


# --- counter is monotonic, not random ----------------------------------------------------

def test_counter_is_monotonic_16bit():
    svc = ping.PingService()
    keys = [svc._next_key() for _ in range(5)]
    assert keys == [(0, 0), (0, 1), (0, 2), (0, 3), (0, 4)]
    for ident, seq in keys:
        assert 0 <= ident <= 0xFFFF
        assert 0 <= seq <= 0xFFFF


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
        self._inbox: list[bytes] = []

    def sendto(self, packet, addr):
        self.sent.append((packet, addr))
        if self.reply_for_sent:
            # Echo it back as a reply (flip type 8 -> 0), wrapped in an IPv4 header,
            # exactly as the kernel would hand it to the raw socket.
            self._inbox.append(_wrap_ipv4(_to_echo_reply(packet)))
        return len(packet)

    def recv(self, _bufsize):
        if self._inbox:
            return self._inbox.pop(0)
        raise BlockingIOError

    def close(self):
        self.closed = True


def _install_fake_socket(svc, sock):
    """Wire a fake socket into the service and pump it from the running loop."""
    svc._sock = sock

    def ensure(_ctx):
        return sock

    svc._ensure_socket = ensure  # type: ignore[method-assign]

    # Emulate add_reader: whenever a packet is queued, deliver it to the demux callback
    # on the next loop turn. check() schedules this via sendto populating the inbox.
    orig_sendto = sock.sendto

    def sendto_then_pump(packet, addr):
        n = orig_sendto(packet, addr)
        if sock._inbox:
            asyncio.get_running_loop().call_soon(svc._on_readable, sock)
        return n

    sock.sendto = sendto_then_pump  # type: ignore[method-assign]


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


async def test_check_wrong_reply_does_not_resolve():
    # A reply for a *different* (ident, seq) must not satisfy the waiter -> UNPINGABLE.
    svc = ping.PingService()
    sock = _FakeSocket()
    _install_fake_socket(svc, sock)

    # Replace the demux callback with one that feeds a mismatched reply.
    def feed_wrong(_sock):
        wrong = _wrap_ipv4(_to_echo_reply(ping.build_echo_request(0xDEAD, 0xBEEF, b"x")))
        parsed = ping.parse_echo_reply(wrong)
        fut = svc._pending.get(parsed)  # 0xDEAD/0xBEEF is never a real pending key here
        if fut is not None and not fut.done():
            fut.set_result(None)

    svc._on_readable = feed_wrong  # type: ignore[method-assign]

    ctx = base.CheckContext(resolver=FakeResolver(), timeout_s=0.15)
    result = await svc.check(node(), ctx)

    assert result == Status.UNPINGABLE


async def test_check_resolve_failure_propagates_before_socket():
    # resolve() failure raises NoDnsError before any socket work; check never sends.
    svc = ping.PingService()
    sock = _FakeSocket()
    _install_fake_socket(svc, sock)

    ctx = base.CheckContext(resolver=FakeResolver(default=None), timeout_s=2.0)
    with pytest.raises(base.NoDnsError):
        await svc.check(node(), ctx)
    assert sock.sent == []  # nothing was sent


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
    assert svc._sock is None  # never reached socket creation.
