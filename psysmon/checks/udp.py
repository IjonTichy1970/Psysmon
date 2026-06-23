"""UDP probe check (Milestone 6).

In production the only UDP checks are DNS (port 53), so the probe sends a minimal DNS query
and treats *any* response as up — the point is reachability, not correctness, so even a
SERVFAIL or REFUSED rcode proves the server answered. A clean authoritative-DNS check lives
in :mod:`psysmon.checks.dns`; this module covers the generic legacy ``udp`` type.
"""

from __future__ import annotations

import dns.asyncquery
import dns.exception
import dns.message
import dns.rdatatype

from psysmon.checks import base
from psysmon.config.model import Node
from psysmon.status import Status


async def check(node: Node, ctx: base.CheckContext) -> int:
    """Send a UDP DNS query; any reply means the server is reachable (``OK``)."""
    ip = await base.resolve(node, ctx)
    query = dns.message.make_query(node.hostname or ".", dns.rdatatype.A)
    try:
        await dns.asyncquery.udp(
            query,
            ip,
            timeout=ctx.timeout_s,
            port=node.port,
            source=ctx.source_ip,
        )
    except dns.exception.Timeout:
        return Status.NO_RESPONSE
    return Status.OK
