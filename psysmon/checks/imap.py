"""IMAP greeting + optional LOGIN check (``CheckType.IMAP`` / ``IMAPS``).

Opens a connection and reads the server greeting: an untagged ``* OK`` means the server is ready
(up); ``* PREAUTH`` means it is ready *and already authenticated* (also up, no LOGIN attempted);
``* BYE`` or anything else is a bad response; an empty read is no response.

If the node carries both ``username`` and ``password`` (optional for IMAP — decision for #88) and
the greeting was ``* OK``, it additionally performs a tagged ``LOGIN`` and maps the tagged result:
``OK`` -> up, ``NO`` -> bad auth, ``BAD`` (or anything unexpected) -> bad response, a dropped
connection -> no response. A correct password followed by a post-auth drop is deliberately
``NO_RESPONSE`` rather than a credential failure — the same reasoning as the POP3 check.

``imaps`` runs this exact logic over an implicit-TLS connection: :func:`base.open_check_connection`
wraps TLS for the ``IMAPS`` type, so this checker is transport-agnostic. Socket/OS errors propagate
so :func:`base.perform` maps them to the right status code.
"""

from __future__ import annotations

import asyncio

from psysmon.checks import base
from psysmon.config.model import Node
from psysmon.status import Status

_TAG = b"a1"  # tag for our LOGIN command (LOGOUT, if reached, uses a2)


async def _read_tagged(reader: asyncio.StreamReader, tag: bytes) -> bytes:
    """Read response lines until the one tagged ``tag``, skipping untagged ``*`` lines (capability
    announcements and the like). Returns that tagged line, or ``b""`` if the connection drops."""
    while True:
        line = await reader.readline()
        if not line:
            return b""
        if line.startswith(tag + b" "):
            return line


async def check(node: Node, ctx: base.CheckContext) -> int:
    """Validate the IMAP greeting, optionally authenticating with the node's credentials."""
    async with base.open_check_connection(node, ctx) as (reader, writer):
        greeting = await reader.readline()
        if not greeting:  # connection dropped before the greeting
            return Status.NO_RESPONSE
        if greeting.startswith(b"* PREAUTH"):
            return Status.OK  # ready and already authenticated; no LOGIN needed
        if not greeting.startswith(b"* OK"):
            return Status.BAD_RESPONSE  # `* BYE` or anything else: not a ready server

        if not (node.username and node.password):
            return Status.OK  # banner-only check: a ready greeting is enough

        # Optional authenticated check — a tagged LOGIN with quoted arguments, so a space in a
        # credential doesn't split the command.
        writer.write(_TAG + b' LOGIN "' + node.username.encode("utf-8")
                     + b'" "' + node.password.encode("utf-8") + b'"\r\n')
        await writer.drain()
        reply = await _read_tagged(reader, _TAG)
        if not reply:  # accepted the command, then dropped before the tagged result
            return Status.NO_RESPONSE
        result = reply[len(_TAG) + 1:].lstrip()
        if result.startswith(b"OK"):
            await _logout(writer)
            return Status.OK
        if result.startswith(b"NO"):  # credentials rejected
            return Status.BAD_AUTH
        return Status.BAD_RESPONSE  # `BAD` (protocol error) or anything unexpected


async def _logout(writer: asyncio.StreamWriter) -> None:
    """Politely end the session (best-effort; the connection is torn down by the caller anyway)."""
    writer.write(b"a2 LOGOUT\r\n")
    await writer.drain()
