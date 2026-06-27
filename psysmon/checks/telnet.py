"""Telnet connection/banner check (``CheckType.TELNET``).

Telnet (port 23) is an old, plaintext protocol with no standardized greeting like SSH's ``SSH-``
banner. A real telnet server, on connect, almost always begins **option negotiation** with an
``IAC`` command (first byte ``0xFF``); some instead send a plaintext login banner/prompt. Either
way it sends *something* unprompted, so this check reads the initial bytes and is **up** if any data
arrives — confirming a live telnet service is answering, beyond what a bare ``tcp 23`` connect can
tell. An empty read (the peer accepted the connection then closed without sending anything) is
``No Response``.

This is a connection/banner check only — like the SSH check, it never authenticates (no
credentials). ``reader.read`` is used rather than ``readline`` because telnet negotiation is binary
(``IAC`` sequences, no newline). A server that stays silent until the *client* speaks would read as
timed-out (rare in practice; most telnetd negotiate immediately). Socket/OS errors propagate so
:func:`base.perform` maps them to the right status code.
"""

from __future__ import annotations

from psysmon.checks import base
from psysmon.config.model import Node
from psysmon.status import Status

_READ_BYTES = 64  # enough to capture the initial IAC negotiation or a banner prefix


async def check(node: Node, ctx: base.CheckContext) -> int:
    """Up if the telnet server sends any initial data (IAC negotiation or a banner)."""
    async with base.open_check_connection(node, ctx) as (reader, _writer):
        data = await reader.read(_READ_BYTES)
    return Status.OK if data else Status.NO_RESPONSE
