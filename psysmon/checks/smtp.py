"""SMTP banner check (``CheckType.SMTP``).

Opens a TCP connection and reads the greeting banner. A ``220`` greeting means the server is
up; an immediate close (empty banner) means the server hung up without greeting; any other
banner is a bad response. Connection-level failures (refused/unreachable/timeout) propagate as
``OSError`` and are mapped by :func:`psysmon.checks.base.perform`.
"""

from __future__ import annotations

from psysmon.checks import base
from psysmon.config.model import Node
from psysmon.status import Status


async def check(node: Node, ctx: base.CheckContext) -> int:
    """Resolve, connect, and validate the SMTP greeting banner."""
    async with base.open_check_connection(node, ctx) as (reader, writer):
        banner = await reader.readline()
        if banner.startswith(b"220"):
            await base.graceful_quit(writer)
            return Status.OK
        if banner == b"":
            return Status.NO_RESPONSE
        return Status.BAD_RESPONSE
