"""TCP connect-reachability check (Milestone 6).

Opens a TCP connection to ``node.port`` and closes it; success = connected. Maps
refused/unreachable/timeout to the corresponding ``Status`` codes via :mod:`sysmon.checks.base`.

Not yet implemented.
"""

from __future__ import annotations

from sysmon.config.model import Node


async def check(node: Node, deadline: float) -> int:
    raise NotImplementedError("Milestone 6: tcp check")
