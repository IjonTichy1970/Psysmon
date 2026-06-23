"""ICMP echo ping (Milestone 7).

Reproduces ``icmp.c`` but modern and concurrent: a single shared raw ICMP socket opened
lazily (the first time a ping is actually run), registered with ``loop.add_reader``; outbound
echo requests carry a per-process-randomized, monotonic identifier/sequence plus a per-probe
random nonce in the payload, and replies are demultiplexed to per-(identifier, sequence)
futures **only after the reply echoes that nonce back** (the shared socket receives every
inbound echo reply, so matching on id/seq alone would let any host — or a spoofed packet that
guessed the id/seq — forge a host-is-up result). Crucially the reply is *not* required to come
from the pinged address: routers, asymmetric routing, and NAT legitimately source an echo reply
from a different interface/address, and the nonce authenticates the reply without rejecting
those (a strict source-IP match read such healthy gateways as ``UNPINGABLE`` — issue #29 fix).
This assumes the responder echoes our payload back, as RFC 792 requires; the rare host that
truncates the ICMP data below the nonce length would read ``UNPINGABLE`` — virtually all stacks
(Linux/BSD/Windows, Cisco/Juniper) comply. The socket is optionally ``bind()``-ed to the
configured source IP (ACL-load-bearing). One unanswered echo after the retry budget ->
``Status.UNPINGABLE``.

The raw socket is *not* opened at import time, so this module imports cleanly without
privilege on both Windows and Linux. It is opened on first use (which requires root / raw-socket
capability) and kept open across a later privilege drop (see :mod:`psysmon.privilege`).

The pure framing helpers (:func:`icmp_checksum`, :func:`build_echo_request`,
:func:`parse_echo_reply`) need no privilege and are unit-tested directly.
"""

from __future__ import annotations

import asyncio
import errno
import secrets
import socket
import struct

from psysmon.checks import base
from psysmon.config.model import Node
from psysmon.status import Status

# ICMP message types we care about.
ICMP_ECHO_REQUEST = 8
ICMP_ECHO_REPLY = 0

_ECHO_HEADER = struct.Struct("!BBHHH")  # type, code, checksum, identifier, sequence
# Fallback payload for the standalone build_echo_request() framing helper / tests only — real
# probes always send a fresh per-probe random nonce (see _probe), never this fixed value.
_DEFAULT_PAYLOAD = b"psysmon-ping-payload"
_NONCE_LEN = 16  # per-probe random payload that the reply must echo back (anti-forgery, #29)
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


def parse_echo_reply(packet: bytes) -> tuple[int, int, bytes] | None:
    """Parse a received packet, returning ``(identifier, sequence, payload)`` for an echo reply.

    The kernel hands back the full IPv4 datagram on a raw socket, so the IPv4 header (whose
    length comes from the IHL nibble) is skipped first. Returns ``None`` for any packet that is
    not a well-formed ICMP type-0 echo reply (wrong type, truncated, etc.). The payload — the
    bytes after the 8-byte ICMP header — is returned so the caller can verify the echoed nonce.
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
    return ident, seq, icmp[_ECHO_HEADER.size :]


class PingService:
    """Owns the shared raw ICMP socket and demuxes echo replies by (identifier, sequence)."""

    def __init__(self, source_ip: str | None = None) -> None:
        self._source_ip = source_ip
        self._sock: socket.socket | None = None
        self._reader_registered = False
        # id/seq base: randomized per process so an off-path attacker can't predict the
        # in-flight (ident, seq) of a probe and forge a reply (#29). Still monotonic from there.
        self._counter = secrets.randbits(32)
        # (ident, seq) -> (waiter, expected nonce); the nonce gates which replies may resolve it.
        self._pending: dict[tuple[int, int], tuple[asyncio.Future[None], bytes]] = {}

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
        """``add_reader`` callback: read a packet and wake the matching, nonce-verified waiter."""
        try:
            packet, _addr = sock.recvfrom(2048)
        except OSError:
            return
        parsed = parse_echo_reply(packet)
        if parsed is None:
            return
        ident, seq, payload = parsed
        entry = self._pending.get((ident, seq))
        if entry is None:
            return
        future, expected_nonce = entry
        # The reply must echo back the per-probe random nonce we sent. The shared raw socket
        # receives ALL inbound echo replies, so matching (ident, seq) alone would let another
        # host — or a spoofed off-path packet that guessed the (randomized) id/seq — satisfy the
        # waiter and forge a host-is-up result, masking an outage and (via dependency gating)
        # silencing a whole subtree. Only a host that actually received our request can echo the
        # unpredictable nonce. Unlike a strict source-address match, this accepts a legitimate
        # reply sourced from a different address (a router's egress interface, NAT, asymmetric
        # routing) — the false-UNPINGABLE the source check caused on healthy gateways (#29 fix).
        if not payload.startswith(expected_nonce):
            return
        if not future.done():
            future.set_result(None)

    # --- public check -----------------------------------------------------------------

    async def check(self, node: Node, ctx: base.CheckContext) -> int:
        """Send echo requests and await a matching reply, mapping failures to a Status code.

        Unlike the protocol checkers (which run under :func:`base.perform`), ping is dispatched
        directly by the scheduler, so it must translate its *own* expected failures — an
        unresolvable host, an event loop without ``add_reader``, or an un-sendable packet (no
        route to the target) — into a Status code instead of raising. An exception escaping
        here would leave the node with no verdict at all and, because ping nodes gate their
        children, silently suppress the whole subtree during exactly the outage we exist to
        detect (the scheduler's generic handler would log and move on without ever applying a
        result or marking the node checked).
        """
        try:
            ip = await base.resolve(node, ctx)
            sock = self._ensure_socket(ctx)
            return await self._probe(ip, sock, ctx)
        except base.NoDnsError:
            return Status.NO_DNS
        except socket.gaierror:
            return Status.NO_DNS
        except OSError as exc:
            # A ping that can't be sent (no route, or an unsupported event loop) is reported
            # down, not raised. Known route errors keep their specific code; anything else is
            # UNPINGABLE (map_oserror's CONN_REFUSED default is meaningless for ICMP).
            if exc.errno in (
                errno.ENETUNREACH, errno.EHOSTUNREACH, errno.EHOSTDOWN, errno.ETIMEDOUT
            ):
                return base.map_oserror(exc)
            return Status.UNPINGABLE

    async def _probe(self, ip: str, sock: socket.socket, ctx: base.CheckContext) -> int:
        """Send up to ``1 + _RETRIES`` echoes; first reply echoing our nonce -> OK, else down."""
        loop = asyncio.get_running_loop()
        # Split the overall budget across attempts so the whole check still fits ctx.timeout_s.
        per_attempt = max(ctx.timeout_s / (1 + _RETRIES), 0.001)

        for _ in range(1 + _RETRIES):
            ident, seq = self._next_key()
            nonce = secrets.token_bytes(_NONCE_LEN)
            future: asyncio.Future[None] = loop.create_future()
            self._pending[(ident, seq)] = (future, nonce)  # only a reply echoing `nonce` resolves
            try:
                packet = build_echo_request(ident, seq, nonce)
                sock.sendto(packet, (ip, 0))
                try:
                    await asyncio.wait_for(future, per_attempt)
                    return Status.OK
                except TimeoutError:
                    continue
            finally:
                self._pending.pop((ident, seq), None)

        return Status.UNPINGABLE
