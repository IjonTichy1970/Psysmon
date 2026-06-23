"""SMTP banner check (``CheckType.SMTP``).

Opens a TCP connection and reads the greeting banner. A ``220`` greeting means the server is
up; an immediate close (empty banner) means the server hung up without greeting; any other
banner is a bad response. Connection-level failures (refused/unreachable/timeout) propagate as
``OSError`` and are mapped by :func:`sysmon.checks.base.perform`.
"""

from __future__ import annotations

from sysmon.checks import base
from sysmon.config.model import DEFAULT_PORT, CheckType, Node
from sysmon.status import Status


async def check(node: Node, ctx: base.CheckContext) -> int:
    """Resolve, connect, and validate the SMTP greeting banner."""
    ip = await base.resolve(node, ctx)
    port = node.port or DEFAULT_PORT[CheckType.SMTP]
    reader, writer = await base.open_connection(ip, port, ctx)
    try:
        banner = await reader.readline()
        if banner.startswith(b"220"):
            writer.write(b"QUIT\r\n")
            await writer.drain()
            return Status.OK
        if banner == b"":
            return Status.NO_RESPONSE
        return Status.BAD_RESPONSE
    finally:
        writer.close()
