"""POP3 authentication check.

Resolves the node, opens a TCP connection, reads the greeting (must be ``+OK``), then performs
a ``USER``/``PASS`` login. ``+OK`` on the password reply means the credentials are accepted
(``OK``); ``-ERR`` means the auth was rejected (``BAD_AUTH``); anything else is ``BAD_RESPONSE``.

Socket/OS errors propagate so that :func:`psysmon.checks.base.perform` maps them to the right
status code; only protocol-level outcomes return an explicit code here.
"""

from __future__ import annotations

from psysmon.checks import base
from psysmon.config.model import Node
from psysmon.status import Status


async def check(node: Node, ctx: base.CheckContext) -> int:
    """Probe a POP3 server, authenticating with ``node.username``/``node.password``."""
    async with base.open_check_connection(node, ctx) as (reader, writer):
        greeting = await reader.readline()
        if not greeting.startswith(b"+OK"):
            return Status.NO_RESPONSE

        writer.write(b"USER " + node.username.encode("utf-8") + b"\r\n")
        await writer.drain()
        await reader.readline()

        writer.write(b"PASS " + node.password.encode("utf-8") + b"\r\n")
        await writer.drain()
        reply = await reader.readline()

        if reply.startswith(b"+OK"):
            await base.graceful_quit(writer)
            return Status.OK
        if reply.startswith(b"-ERR"):
            return Status.BAD_AUTH
        return Status.BAD_RESPONSE
