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
    except dns.exception.DNSException:
        # A reachable-but-misbehaving server (malformed wire data, reply from an unexpected
        # source, etc.) raises a non-Timeout DNSException; surface it as a concrete down code
        # rather than letting it escape uncaught and leave the node with no verdict.
        return Status.BAD_RESPONSE
    return Status.OK
