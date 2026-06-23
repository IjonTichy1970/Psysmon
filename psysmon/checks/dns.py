"""Authoritative DNS check (CheckType.DNS, legacy ``authdns``).

A clean reimplementation of the legacy ``authdns`` type using ``dnspython``: send a
non-recursive A query for the configured name (``node.username``) to the target server
(``node.hostname`` resolved via :func:`base.resolve`) and inspect the rcode / answer count.
Replaces the original's BIND ``_res`` fiddling.

Classification:
- rcode other than NOERROR -> ``BAD_RESPONSE``
- NOERROR but no answer records -> ``NO_RESPONSE``
- otherwise -> ``OK``

A DNS-level timeout (``dns.exception.Timeout``) maps to ``NO_RESPONSE`` and any other
``dns.exception.DNSException`` (malformed reply, unexpected source, ...) to ``BAD_RESPONSE``;
DNS resolution of the server host and OS/socket errors propagate to :func:`base.perform`.
"""

from __future__ import annotations

import dns.asyncquery
import dns.exception
import dns.flags
import dns.message
import dns.rcode
import dns.rdatatype

from psysmon.checks import base
from psysmon.config.model import Node
from psysmon.status import Status


async def check(node: Node, ctx: base.CheckContext) -> int:
    """Query the authoritative DNS server at ``node.hostname`` for ``node.username``."""
    ip = await base.resolve(node, ctx)

    q = dns.message.make_query(node.username, dns.rdatatype.A)
    q.flags &= ~dns.flags.RD  # non-recursive: the server must answer authoritatively

    try:
        response = await dns.asyncquery.udp(
            q,
            ip,
            timeout=ctx.timeout_s,
            port=node.port,
            source=ctx.source_ip,
        )
    except dns.exception.Timeout:
        return Status.NO_RESPONSE
    except dns.exception.DNSException:
        # Any other DNS-level failure (malformed/garbled wire data, a reply from an
        # unexpected source, etc.) is a reachable-but-bad server — report BAD_RESPONSE
        # instead of letting it escape uncaught and produce no verdict on every tick.
        return Status.BAD_RESPONSE

    if response.rcode() != dns.rcode.NOERROR:
        return Status.BAD_RESPONSE
    if len(response.answer) == 0:
        return Status.NO_RESPONSE
    return Status.OK
