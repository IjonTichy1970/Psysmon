"""ICMP echo ping (Milestone 7).

Reproduces ``icmp.c`` but modern and concurrent: a single shared raw ICMP socket opened
lazily (the first time a ping is actually run), registered with ``loop.add_reader``; outbound
echo requests carry a monotonic 16-bit identifier/sequence, and replies are demultiplexed to
per-(identifier, sequence) futures. The socket is optionally ``bind()``-ed to the configured
source IP (ACL-load-bearing). One unanswered echo after the retry budget -> ``Status.UNPINGABLE``.

The raw socket is *not* opened at import time, so this module imports cleanly without
privilege on both Windows and Linux. It is opened on first use (which requires root / raw-socket
capability) and kept open across a later privilege drop (see :mod:`psysmon.privilege`).

The pure framing helpers (:func:`icmp_checksum`, :func:`build_echo_request`,
:func:`parse_echo_reply`) need no privilege and are unit-tested directly.
"""

from __future__ import annotations

import asyncio
import socket
import struct

from psysmon.checks import base
from psysmon.config.model import Node
from psysmon.status import Status

# ICMP message types we care about.
ICMP_ECHO_REQUEST = 8
ICMP_ECHO_REPLY = 0

_ECHO_HEADER = struct.Struct("!BBHHH")  # type, code, checksum, identifier, sequence
_DEFAULT_PAYLOAD = b"psysmon-ping-payload"
_RETRIES = 2  # total attempts per check = 1 + _RETRIES


def icmp_checksum(data: bytes) -> int:
    """Standard 16-bit one's-complement Internet checksum over ``data``."""
    total = 0
    # Sum 16-bit big-endian words; pad with a trailing zero byte if odd length.
    if len(data) % 2:
        data = data + b"\x00"
    for i in range(0, len(data), 2):
        total += (data[i] << 8) + data[i + 1]
    # Fold carries into the low 16 bits.
    while total >> 16:
        total = (total & 0xFFFF) + (total >> 16)
    return (~total) & 0xFFFF


def build_echo_request(ident: int, seq: int, payload: bytes = _DEFAULT_PAYLOAD) -> bytes:
    """Build an ICMP echo *request* (type 8, code 0) with a valid checksum."""
    ident &= 0xFFFF
    seq &= 0xFFFF
    header = _ECHO_HEADER.pack(ICMP_ECHO_REQUEST, 0, 0, ident, seq)
    checksum = icmp_checksum(header + payload)
    header = _ECHO_HEADER.pack(ICMP_ECHO_REQUEST, 0, checksum, ident, seq)
    return header + payload


def parse_echo_reply(packet: bytes) -> tuple[int, int] | None:
    """Parse a received packet, returning ``(identifier, sequence)`` for an echo reply.

    The kernel hands back the full IPv4 datagram on a raw socket, so the IPv4 header (whose
    length comes from the IHL nibble) is skipped first. Returns ``None`` for any packet that is
    not a well-formed ICMP type-0 echo reply (wrong type, truncated, etc.).
    """
    if len(packet) < 20:  # minimum IPv4 header.
        return None
    version_ihl = packet[0]
    if version_ihl >> 4 != 4:  # only IPv4 here.
        return None
    ihl = (version_ihl & 0x0F) * 4
    if ihl < 20 or len(packet) < ihl + _ECHO_HEADER.size:
        return None
    icmp = packet[ihl:]
    msg_type, _code, _checksum, ident, seq = _ECHO_HEADER.unpack(icmp[: _ECHO_HEADER.size])
    if msg_type != ICMP_ECHO_REPLY:
        return None
    return ident, seq


class PingService:
    """Owns the shared raw ICMP socket and demuxes echo replies by (identifier, sequence)."""

    def __init__(self, source_ip: str | None = None) -> None:
        self._source_ip = source_ip
        self._sock: socket.socket | None = None
        self._reader_registered = False
        self._counter = 0  # monotonic 16-bit id/seq source (NOT random).
        self._pending: dict[tuple[int, int], asyncio.Future[None]] = {}

    # --- socket lifecycle -------------------------------------------------------------

    def _open_raw(self) -> socket.socket:
        """Create the raw ICMP socket and bind the source IP (requires root). No event loop."""
        sock = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_ICMP)
        sock.setblocking(False)
        if self._source_ip:
            sock.bind((self._source_ip, 0))
        return sock

    def prepare(self) -> None:
        """Open the raw socket up front (call as root, before dropping privileges).

        The reply reader is attached later by :meth:`_ensure_socket` once a loop is running.
        """
        if self._sock is None:
            self._sock = self._open_raw()

    def _ensure_socket(self, ctx: base.CheckContext) -> socket.socket:
        """Open (if needed) and register the raw ICMP socket on first use within the loop."""
        if self._sock is None:
            self._sock = self._open_raw()
        if not self._reader_registered:
            try:
                asyncio.get_running_loop().add_reader(
                    self._sock.fileno(), self._on_readable, self._sock
                )
            except NotImplementedError as exc:
                # The Windows Proactor loop has no add_reader; raw ICMP demux is unsupported.
                self._sock.close()
                self._sock = None
                raise OSError("event loop does not support add_reader for raw sockets") from exc
            self._reader_registered = True
        return self._sock

    def close(self) -> None:
        """Unregister and close the raw socket (idempotent)."""
        if self._sock is None:
            return
        if self._reader_registered:
            try:
                asyncio.get_running_loop().remove_reader(self._sock.fileno())
            except RuntimeError:  # no running loop (shutdown) — socket close still suffices.
                pass
            self._reader_registered = False
        self._sock.close()
        self._sock = None

    def _next_key(self) -> tuple[int, int]:
        """Next monotonic (identifier, sequence) pair, wrapping at 16 bits."""
        value = self._counter & 0xFFFFFFFF
        self._counter = (self._counter + 1) & 0xFFFFFFFF
        ident = (value >> 16) & 0xFFFF
        seq = value & 0xFFFF
        return ident, seq

    # --- reply demux ------------------------------------------------------------------

    def _on_readable(self, sock: socket.socket) -> None:
        """``add_reader`` callback: read a packet and wake the matching waiter."""
        try:
            packet = sock.recv(2048)
        except OSError:
            return
        parsed = parse_echo_reply(packet)
        if parsed is None:
            return
        future = self._pending.get(parsed)
        if future is not None and not future.done():
            future.set_result(None)

    # --- public check -----------------------------------------------------------------

    async def check(self, node: Node, ctx: base.CheckContext) -> int:
        """Send an echo request and await a matching reply; success -> OK, else UNPINGABLE."""
        ip = await base.resolve(node, ctx)
        sock = self._ensure_socket(ctx)

        loop = asyncio.get_running_loop()
        # Split the overall budget across attempts so the whole check still fits ctx.timeout_s.
        per_attempt = max(ctx.timeout_s / (1 + _RETRIES), 0.001)

        for _ in range(1 + _RETRIES):
            ident, seq = self._next_key()
            future: asyncio.Future[None] = loop.create_future()
            self._pending[(ident, seq)] = future
            try:
                packet = build_echo_request(ident, seq)
                sock.sendto(packet, (ip, 0))
                try:
                    await asyncio.wait_for(future, per_attempt)
                    return Status.OK
                except TimeoutError:
                    continue
            finally:
                self._pending.pop((ident, seq), None)

        return Status.UNPINGABLE
