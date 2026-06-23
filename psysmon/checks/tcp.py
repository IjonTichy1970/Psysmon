"""TCP connect-reachability check.

A bare TCP connect: resolve the host, open a connection to ``node.port``, close it cleanly,
and report :data:`~psysmon.status.Status.OK`. There is no protocol exchange — the connect
either succeeds or raises a socket error, which :func:`psysmon.checks.base.perform` maps to the
appropriate failure code (refused / unreachable / timed out).
"""

from __future__ import annotations

from psysmon.checks import base
from psysmon.config.model import Node
from psysmon.status import Status


async def check(node: Node, ctx: base.CheckContext) -> int:
    """Return ``OK`` if a TCP connection to ``node.port`` can be established."""
    async with base.open_check_connection(node, ctx):
        return Status.OK
