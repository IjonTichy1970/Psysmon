"""POP3 authentication check.

Resolves the node, opens a TCP connection, reads the greeting (must be ``+OK``), then performs
a ``USER``/``PASS`` login. The ``USER`` reply is checked too: ``-ERR`` (username rejected) is
``BAD_AUTH``; a dropped connection (empty reply) is ``NO_RESPONSE``. On the ``PASS`` reply,
``+OK`` means the credentials are accepted (``OK``); ``-ERR`` means the auth was rejected
(``BAD_AUTH``); a dropped connection is ``NO_RESPONSE``; anything else is ``BAD_RESPONSE``.

A connection that drops mid-auth is deliberately ``NO_RESPONSE``, not ``BAD_AUTH``: a server can
accept a *correct* password and then drop the session on a post-auth fault (a misconfigured
mailbox backend, say), so "no final response" must not be reported as a credential failure —
that would send operators chasing the wrong cause. It is also not ``BAD_RESPONSE``, since no
response arrived at all.

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
        user_reply = await reader.readline()
        if not user_reply:  # connection dropped before answering USER
            return Status.NO_RESPONSE
        if user_reply.startswith(b"-ERR"):  # username rejected; don't bother with PASS
            return Status.BAD_AUTH

        writer.write(b"PASS " + node.password.encode("utf-8") + b"\r\n")
        await writer.drain()
        reply = await reader.readline()

        if reply.startswith(b"+OK"):
            await base.graceful_quit(writer)
            return Status.OK
        if reply.startswith(b"-ERR"):  # credentials rejected
            return Status.BAD_AUTH
        if not reply:  # accepted USER, then dropped at PASS (e.g. a post-auth server fault)
            return Status.NO_RESPONSE
        return Status.BAD_RESPONSE
