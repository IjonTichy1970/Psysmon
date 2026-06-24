"""ICMP echo ping (Milestone 7).

Reproduces ``icmp.c`` but modern and concurrent. Outbound echo requests carry a
per-process-randomized, monotonic identifier/sequence plus a per-probe random nonce in the
payload, and replies are demultiplexed to per-(identifier, sequence) futures **only after the
reply echoes that nonce back** (a raw socket receives every inbound echo reply, so matching on
id/seq alone would let any host — or a spoofed packet that guessed the id/seq — forge a
host-is-up result). Crucially the reply is *not* required to come from the pinged address:
routers, asymmetric routing, and NAT legitimately source an echo reply from a different
interface/address, and the nonce authenticates the reply without rejecting those (a strict
source-IP match read such healthy gateways as ``UNPINGABLE`` — issue #29 fix). This assumes the
responder echoes our payload back, as RFC 792 requires; the rare host that truncates the ICMP
data below the nonce length would read ``UNPINGABLE`` — virtually all stacks (Linux/BSD/Windows,
Cisco/Juniper) comply. One unanswered echo after the retry budget -> ``Status.UNPINGABLE``.

**Source binding (#70).** Ping uses a small *pool* of raw sockets keyed by outbound bind source:
an always-present **unbound** socket (the default — the kernel routes each probe by destination,
which is the right behavior for VPN/dynamic interfaces, and ignores the global ``source_ip``),
plus one socket ``bind()``-ed per distinct configured per-object/per-group ``source`` (an
ACL-load-bearing egress IP). Each probe sends on the socket for its node's resolved source
(carried on ``ctx.source_ip``; ``None`` = unbound). A single (identifier, sequence) keyspace and
one nonce-checked demux serve every socket — a reply may legitimately arrive on a different
socket than it left from (asymmetric routing), so demux stays source-agnostic.

The raw sockets are *not* opened at import time, so this module imports cleanly without privilege
on both Windows and Linux. :meth:`PingService.prepare` opens the whole pool up front (which
requires root / raw-socket capability) and they are kept open across a later privilege drop (see
:mod:`psysmon.privilege`) — a *new* source introduced by a later reload can no longer create a
bound raw socket, so such probes fall back to the unbound socket with a one-time warning.

The pure framing helpers (:func:`icmp_checksum`, :func:`build_echo_request`,
:func:`parse_echo_reply`) need no privilege and are unit-tested directly.
"""

from __future__ import annotations

import asyncio
import errno
import logging
import secrets
import socket
import struct
from collections.abc import Iterable

from psysmon.checks import base
from psysmon.config.model import Node
from psysmon.status import Status, errtostr

logger = logging.getLogger(__name__)

# ICMP message types we care about.
ICMP_ECHO_REQUEST = 8
ICMP_ECHO_REPLY = 0

_ECHO_HEADER = struct.Struct("!BBHHH")  # type, code, checksum, identifier, sequence
# Fallback payload for the standalone build_echo_request() framing helper / tests only — real
# probes always send a fresh per-probe random nonce (see _probe), never this fixed value.
_DEFAULT_PAYLOAD = b"psysmon-ping-payload"
_NONCE_LEN = 16  # per-probe random payload that the reply must echo back (anti-forgery, #29)
_RETRIES = 2  # total attempts per single-probe check = 1 + _RETRIES


def _validate_counts(send_pings: int, min_pings: int) -> tuple[int, int]:
    """Validate a (send_pings, min_pings) pair, raising ``ValueError`` on an invalid combination.

    Both must be >= 1 and ``min_pings`` cannot exceed ``send_pings`` (you can't require more
    replies than you send). Called for the global defaults at construction — so a bad CLI/config
    value is rejected at startup (``main`` reports it as a clean ``psysmon: ...`` error).
    """
    if send_pings < 1 or min_pings < 1:
        raise ValueError(f"send_pings and min_pings must be >= 1 (got {send_pings}/{min_pings})")
    if min_pings > send_pings:
        raise ValueError(f"min_pings ({min_pings}) cannot exceed send_pings ({send_pings})")
    return send_pings, min_pings


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
    """Owns a source-keyed pool of raw ICMP sockets and demuxes echo replies by (ident, seq)."""

    def __init__(
        self, sources: Iterable[str] = (), *, send_pings: int = 1, min_pings: int = 1
    ) -> None:
        # Distinct bound sources to pre-open in prepare() while privileged (#70). The unbound
        # default socket is always present; the scheduler supplies these once it has resolved
        # every ping node's source (see set_sources).
        self._configured_sources: frozenset[str] = frozenset(s for s in sources if s)
        # Global loss-tolerance defaults (#22), validated up front. A per-node Node.send_pings /
        # Node.min_pings overrides these; 1/1 reproduces today's first-reply-wins behavior.
        self._send_pings, self._min_pings = _validate_counts(send_pings, min_pings)
        # The socket pool: bind source (None = unbound) -> raw socket. Readers are registered
        # per socket on first use within the loop; `_registered` tracks which sources are wired.
        self._socks: dict[str | None, socket.socket] = {}
        self._registered: set[str | None] = set()
        self._warned_unbindable: set[str] = set()  # sources we've logged a bind failure for
        # id/seq base: randomized per process so an off-path attacker can't predict the
        # in-flight (ident, seq) of a probe and forge a reply (#29). Still monotonic from there.
        # ONE keyspace across the whole pool, so a reply on any socket resolves the right waiter.
        self._counter = secrets.randbits(32)
        # (ident, seq) -> (waiter, expected nonce); the nonce gates which replies may resolve it.
        self._pending: dict[tuple[int, int], tuple[asyncio.Future[None], bytes]] = {}

    def set_sources(self, sources: Iterable[str]) -> None:
        """Declare the distinct bound sources to pre-open in :meth:`prepare` (#70). The scheduler
        calls this once it has resolved every ping node's source; the unbound default is implicit.
        Has no effect on already-open sockets — a source added after prepare()/privilege drop
        can't bind a new raw socket and falls back to unbound at check time."""
        self._configured_sources = frozenset(s for s in sources if s)

    # --- socket lifecycle -------------------------------------------------------------

    def _open_raw(self, source: str | None) -> socket.socket:
        """Create a raw ICMP socket, bound to ``source`` when given (requires root). No loop."""
        sock = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_ICMP)
        sock.setblocking(False)
        if source:
            sock.bind((source, 0))
        return sock

    def prepare(self) -> None:
        """Open the whole pool up front (call as root, before dropping privileges): the unbound
        default socket plus one socket bound to each configured source. Reply readers are attached
        later by :meth:`_ensure_socket` once a loop is running. A bound source that fails to open
        here is logged and skipped (probes for it fall back to unbound at check time)."""
        for source in (None, *self._configured_sources):
            if source in self._socks:
                continue
            try:
                self._socks[source] = self._open_raw(source)
            except OSError as exc:
                if source is None:
                    raise  # can't even open the unbound socket — a real, surfaced failure
                self._warn_unbindable(source, exc)

    def _ensure_socket(self, source: str | None) -> socket.socket:
        """Return the pooled socket for ``source`` (None = unbound), opening it (if not already)
        and registering its reply reader on first use within the loop. Each socket gets its own
        ``add_reader`` into the shared demux."""
        sock = self._socks.get(source)
        if sock is None:
            sock = self._open_raw(source)
            self._socks[source] = sock
        if source not in self._registered:
            try:
                asyncio.get_running_loop().add_reader(sock.fileno(), self._on_readable, sock)
            except NotImplementedError as exc:
                # The Windows Proactor loop has no add_reader; raw ICMP demux is unsupported.
                sock.close()
                del self._socks[source]
                raise OSError("event loop does not support add_reader for raw sockets") from exc
            self._registered.add(source)
        return sock

    def _socket_for(self, source: str | None) -> socket.socket:
        """The pooled socket to send a probe from. Falls back to the (pre-opened) unbound socket,
        with a one-time warning, if a bound source can't be opened now — e.g. a source introduced
        by a reload after the daemon dropped raw-socket privilege (#70)."""
        if source is not None and source in self._warned_unbindable:
            source = None  # already known-unbindable: straight to the unbound default, no retry
        if source is not None and source not in self._socks:
            try:
                self._socks[source] = self._open_raw(source)
            except OSError as exc:
                self._warn_unbindable(source, exc)
                source = None  # route these probes out the unbound default instead
        return self._ensure_socket(source)

    def _warn_unbindable(self, source: str, exc: OSError) -> None:
        if source not in self._warned_unbindable:
            self._warned_unbindable.add(source)
            logger.warning("ping: cannot bind source %s (%s); routing affected checks unbound "
                           "until restart", source, exc)

    def prune(self, keep: Iterable[str]) -> None:
        """Close pooled BOUND sockets whose source is no longer configured (#70 reload cleanup).

        The unbound default (key ``None``) is always kept. Called from the scheduler on reload so
        a source the new config dropped doesn't keep a raw socket + reader open for the daemon's
        life. Safe mid-flight: an orphaned in-flight probe's result is discarded anyway, and its
        next send on a closed socket is the same caught OSError as a transient route failure.
        """
        keep_set = frozenset(s for s in keep if s)
        for source in [s for s in self._socks if s is not None and s not in keep_set]:
            sock = self._socks.pop(source)
            if source in self._registered:
                try:
                    asyncio.get_running_loop().remove_reader(sock.fileno())
                except RuntimeError:  # no running loop — close still suffices
                    pass
                self._registered.discard(source)
            self._warned_unbindable.discard(source)
            sock.close()

    def close(self) -> None:
        """Unregister and close every pooled socket (idempotent)."""
        for source, sock in self._socks.items():
            if source in self._registered:
                try:
                    asyncio.get_running_loop().remove_reader(sock.fileno())
                except RuntimeError:  # no running loop (shutdown) — socket close still suffices.
                    pass
            sock.close()
        self._socks.clear()
        self._registered.clear()

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
            # ctx.source_ip carries this node's resolved ping bind source (the scheduler resolved
            # per-object/group `source`; #70). None = the unbound default socket.
            sock = self._socket_for(ctx.source_ip)
            send_pings = node.send_pings if node.send_pings is not None else self._send_pings
            min_pings = node.min_pings if node.min_pings is not None else self._min_pings
            # A per-node override bypasses the constructor's validation, so clamp it to a sane
            # range here (else min_pings=0 would read up on total loss, or min_pings>send_pings
            # could never read up). The legacy grammar has no slot for these, so this only guards
            # programmatic / future-config use — a per-node config (#3) should reject at load.
            send_pings = max(1, send_pings)
            min_pings = max(1, min(min_pings, send_pings))
            if send_pings <= 1:
                # Default (and the common case): the unchanged single-probe + retry path, so 1/1
                # is byte-for-byte today's behavior (first reply -> OK, none -> UNPINGABLE).
                return await self._probe(ip, sock, ctx)
            return await self._probe_loss_tolerant(ip, sock, ctx, send_pings, min_pings)
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

    async def _probe_loss_tolerant(
        self, ip: str, sock: socket.socket, ctx: base.CheckContext,
        send_pings: int, min_pings: int,
    ) -> int:
        """Send ``send_pings`` echoes spread across the deadline and map the reply count (#22).

        ``received >= min_pings`` -> OK; ``received == 0`` -> UNPINGABLE (unchanged total-loss
        behavior); ``0 < received < min_pings`` -> DEGRADED (reachable but lossy). Unlike
        :meth:`_probe` (the first-reply-wins default), this sends a fixed number of distinct
        echoes to *measure* loss, so it waits out the full deadline to count every reply rather
        than returning early. Ping isn't bounded by the per-check semaphore, so the longer hold is
        acceptable, and waiting yields an accurate loss percentage a binary probe can't. No new
        sockets: every echo rides the shared raw socket with its own monotonic (ident, seq) +
        nonce, demuxed by the same :meth:`_on_readable`.
        """
        loop = asyncio.get_running_loop()
        deadline = loop.time() + ctx.timeout_s
        spacing = ctx.timeout_s / send_pings  # spread the sends across the budget, not a burst
        keys: list[tuple[int, int]] = []
        futures: list[asyncio.Future[None]] = []
        try:
            for i in range(send_pings):
                ident, seq = self._next_key()
                nonce = secrets.token_bytes(_NONCE_LEN)
                future: asyncio.Future[None] = loop.create_future()
                self._pending[(ident, seq)] = (future, nonce)
                keys.append((ident, seq))
                futures.append(future)
                try:
                    sock.sendto(build_echo_request(ident, seq, nonce), (ip, 0))
                except OSError:
                    # One un-sendable echo (a transient no-route) is just a lost packet; keep
                    # going. A persistent send error simply yields 0 received -> UNPINGABLE.
                    pass
                if i < send_pings - 1:  # space the sends, but never run past the deadline
                    await asyncio.sleep(min(spacing, max(0.0, deadline - loop.time())))
            remaining = max(0.0, deadline - loop.time())
            await asyncio.wait(futures, timeout=remaining)
            received = sum(1 for f in futures if f.done() and not f.cancelled())
        finally:
            for key in keys:
                self._pending.pop(key, None)

        if received >= min_pings:
            result = Status.OK
        elif received == 0:
            result = Status.UNPINGABLE
        else:
            result = Status.DEGRADED
        loss_pct = (send_pings - received) / send_pings * 100.0
        # The measured loss is surfaced via this log line for now. Threading it onto NodeState and
        # into the status page / JSON (for a future %loss page token) is deliberately deferred —
        # the check->scheduler seam returns only a status code, so carrying the number to the
        # output layer is follow-up work, not part of this change (#22).
        logger.debug("ping %s: %d/%d replies (%.0f%% loss) -> %s",
                     ip, received, send_pings, loss_pct, errtostr(result))
        return result
