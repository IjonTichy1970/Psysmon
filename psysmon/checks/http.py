"""HTTP / HTTPS content check (Milestone 6).

GET ``{scheme}://{hostname}:{port}{url}`` and require both a 2xx status and that
``node.url_text`` appears in the response body. For HTTPS, certificate verification is ON by
default (the original did none). TLS failure, non-2xx, or missing text all map to
``Status.BAD_RESPONSE`` to stay within the legacy code set; connection refused/timeout map
as usual.

Note: ``ctx.source_ip`` is NOT applied to HTTP checks — httpx offers no per-request source
bind, and production configs use no http/https check types, so this is acceptable.
"""

from __future__ import annotations

import httpx

from psysmon.checks import base
from psysmon.checks.base import CheckContext
from psysmon.config.model import CheckType, Node
from psysmon.status import Status

# Optional injectable transport for hermetic tests (e.g. httpx.MockTransport). Defaults to
# None so production uses the real network transport.
_TRANSPORT: httpx.AsyncBaseTransport | None = None


def _client(ctx: CheckContext) -> httpx.AsyncClient:
    """Build the AsyncClient, wiring the module-level test transport when present."""
    return httpx.AsyncClient(
        timeout=ctx.timeout_s,
        follow_redirects=True,
        transport=_TRANSPORT,
    )


async def check(node: Node, ctx: CheckContext) -> int:
    """GET the node's URL; OK on 2xx + matching body text, else a failure status."""
    # First step (per the base contract): resolve via the shared DnsCache so an
    # unresolvable host surfaces as NO_DNS rather than being misclassified when httpx's own
    # resolution fails. We still GET by hostname so HTTPS cert verification / SNI / Host
    # header validate against node.hostname. NoDnsError propagates to base.perform -> NO_DNS.
    await base.resolve(node, ctx)
    scheme = "https" if node.check_type == CheckType.HTTPS else "http"
    url = f"{scheme}://{node.hostname}:{node.port}{node.url}"
    try:
        async with _client(ctx) as client:
            response = await client.get(url)
    except httpx.TimeoutException:
        return Status.TIMED_OUT
    except httpx.ConnectError:
        return Status.CONN_REFUSED
    except httpx.HTTPError:
        return Status.BAD_RESPONSE
    if response.status_code in range(200, 300) and node.url_text in response.text:
        return Status.OK
    return Status.BAD_RESPONSE
