"""UDP probe check (Milestone 6).

In production the only UDP checks are DNS (port 53), so the probe sends a minimal DNS query
and treats a well-formed response as up. A clean authoritative-DNS check lives in
:mod:`sysmon.checks.dns`; this module covers the generic legacy ``udp`` type.

Not yet implemented.
"""

from __future__ import annotations

from sysmon.config.model import Node


async def check(node: Node, deadline: float) -> int:
    raise NotImplementedError("Milestone 6: udp check")
