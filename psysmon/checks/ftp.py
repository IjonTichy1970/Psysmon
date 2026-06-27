"""FTP control-channel greeting + optional login check (``CheckType.FTP`` / ``FTPS``).

Opens the control connection and reads the server's reply (RFC 959 reply codes). A ``220``
("service ready") greeting means the server is up and speaking FTP — catching a port-forwarder or
a wedged daemon that a bare ``tcp 21`` connect can't distinguish; a ``421`` (service not available)
or any other non-``220`` reply is a bad response, and an empty read is no response.

If the node carries both ``username`` and ``password`` (optional — decision for #102, mirroring the
mail checks) it then performs FTP's two-step login: ``USER`` → ``331`` ("need password") → ``PASS``
→ ``230`` ("logged in") = up; a ``530`` rejection at either step is ``Bad Auth``. A ``230`` straight
after ``USER`` (no password required, e.g. anonymous) is also up. A connection dropped mid-login is
``No Response`` rather than ``Bad Auth`` — a correct password can be dropped on a post-auth fault,
so reporting a credential failure would misdirect the operator (the same reasoning as the POP3/IMAP
checks).

``ftps`` runs this exact logic over an implicit-TLS connection: :func:`base.open_check_connection`
wraps TLS for the ``FTPS`` type, so this checker is transport-agnostic. Socket/OS errors propagate
so :func:`base.perform` maps them to the right status code.
"""

from __future__ import annotations

import asyncio

from psysmon.checks import base
from psysmon.config.model import Node
from psysmon.status import Status


async def _read_reply(reader: asyncio.StreamReader) -> bytes:
    """Read a (possibly multi-line) FTP reply, returning its first line (``b""`` if dropped).

    A multi-line reply is ``NNN-...`` continuation lines terminated by an ``NNN `` (code + space)
    line of the same code (RFC 959 §4.2). We return the first line — its 3-digit code is the
    verdict — after draining any continuation so a later command's reply isn't misread.
    """
    line = await reader.readline()
    if not line:
        return b""
    if len(line) >= 4 and line[3:4] == b"-":  # multi-line: code immediately followed by '-'
        code = line[:3]
        while True:
            cont = await reader.readline()
            if not cont or cont.startswith(code + b" "):  # final line (or a drop mid-reply)
                break
    return line


async def check(node: Node, ctx: base.CheckContext) -> int:
    """Validate the FTP greeting, optionally authenticating with the node's credentials."""
    async with base.open_check_connection(node, ctx) as (reader, writer):
        greeting = await _read_reply(reader)
        if not greeting:  # connection dropped before the greeting
            return Status.NO_RESPONSE
        if not greeting.startswith(b"220"):  # 421 (unavailable) or anything not a ready greeting
            return Status.BAD_RESPONSE

        if not (node.username and node.password):
            await base.graceful_quit(writer)
            return Status.OK  # banner-only check: a "220" ready greeting is enough (#102)

        writer.write(b"USER " + node.username.encode("utf-8") + b"\r\n")
        await writer.drain()
        user_reply = await _read_reply(reader)
        if not user_reply:  # dropped before answering USER
            return Status.NO_RESPONSE
        if user_reply.startswith(b"230"):  # logged in already (no password needed)
            await base.graceful_quit(writer)
            return Status.OK
        if user_reply.startswith(b"530"):  # username rejected outright
            return Status.BAD_AUTH
        if not user_reply.startswith(b"331"):  # expected "need password"; anything else is odd
            return Status.BAD_RESPONSE

        writer.write(b"PASS " + node.password.encode("utf-8") + b"\r\n")
        await writer.drain()
        pass_reply = await _read_reply(reader)
        if not pass_reply:  # accepted USER, then dropped at PASS (e.g. a post-auth fault)
            return Status.NO_RESPONSE
        if pass_reply.startswith(b"230"):  # logged in
            await base.graceful_quit(writer)
            return Status.OK
        if pass_reply.startswith(b"530"):  # credentials rejected
            return Status.BAD_AUTH
        return Status.BAD_RESPONSE
