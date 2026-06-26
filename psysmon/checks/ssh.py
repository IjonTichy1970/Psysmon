"""SSH banner check (``CheckType.SSH``, #96).

Opens a TCP connection and reads the server's SSH identification string. Per RFC 4253 §4.2 the
server sends ``SSH-protoversion-softwareversion\\r\\n`` on connect (it MAY emit other lines first,
but in practice the version string is the first line). A banner starting with ``SSH-`` means the
server speaks SSH (up); an immediate close (empty banner) means it hung up without greeting; any
other banner is a bad response. Connection-level failures (refused/unreachable/timeout) propagate
as ``OSError`` and are mapped by :func:`psysmon.checks.base.perform`.

This is a reachability / protocol check, not a login or key-exchange test.
"""

from __future__ import annotations

from psysmon.checks import base
from psysmon.config.model import Node
from psysmon.status import Status


async def check(node: Node, ctx: base.CheckContext) -> int:
    """Resolve, connect, and validate the SSH identification banner."""
    async with base.open_check_connection(node, ctx) as (reader, _writer):
        banner = await reader.readline()
    if banner.startswith(b"SSH-"):
        return Status.OK
    if banner == b"":
        return Status.NO_RESPONSE
    return Status.BAD_RESPONSE
