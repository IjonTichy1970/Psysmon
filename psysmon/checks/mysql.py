"""MySQL / MariaDB initial-handshake check (``CheckType.MYSQL``, #97).

A MySQL/MariaDB/Percona server sends its initial handshake packet immediately on connect — in the
clear, before any optional TLS upgrade — so a plaintext read is enough. The packet is a 4-byte
header (3-byte little-endian payload length + 1-byte sequence id) followed by a payload whose first
byte is the **protocol version** (``0x0a`` for v10, ``0x09`` for v9). A server that is up but
refusing this connection (e.g. "Host 'x' is not allowed to connect" / "Too many connections") sends
an **error packet** instead, whose payload starts ``0xff`` — that still means the service speaks
MySQL and is responding, so it also counts as up. Anything else is a bad response; an empty/short
read means it hung up without a greeting. Connection-level failures propagate as ``OSError`` and are
mapped by :func:`psysmon.checks.base.perform`.

Only the first payload byte is read (so a bogus length can't trigger a large read), and the whole
exchange is bounded by the check timeout. This is a reachability / protocol check, not a login test.
"""

from __future__ import annotations

import asyncio

from psysmon.checks import base
from psysmon.config.model import Node
from psysmon.status import Status

_PROTOCOL_VERSIONS = (0x09, 0x0A)  # initial HandshakeV9 / V10 marker
_ERR_PACKET = 0xFF  # server speaks MySQL but is refusing this connection — still "up"


async def check(node: Node, ctx: base.CheckContext) -> int:
    """Resolve, connect, and validate the MySQL initial-handshake packet."""
    async with base.open_check_connection(node, ctx) as (reader, _writer):
        try:
            header = await reader.readexactly(4)
            length = int.from_bytes(header[:3], "little")
            if length < 1:
                return Status.BAD_RESPONSE  # a zero-length packet is not a handshake
            first = (await reader.readexactly(1))[0]
        except asyncio.IncompleteReadError:
            return Status.NO_RESPONSE  # hung up before a full greeting
    if first in _PROTOCOL_VERSIONS or first == _ERR_PACKET:
        return Status.OK
    return Status.BAD_RESPONSE
