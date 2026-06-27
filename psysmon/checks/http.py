"""HTTP / HTTPS content or reachability check (Milestone 6; reachability mode #104).

GET ``{scheme}://{hostname}:{port}{url}``. If ``node.url_text`` is set, require both a 2xx status
and that the text appears in the response body (a content check). If it is ``None`` (no match text
configured), **any** HTTP response — including an error status such as 401/403/5xx — is *up*,
because the server is reachable and speaking HTTP (a protocol-aware reachability probe, like the
mysql check). For HTTPS, certificate verification is ON by default (the original did none), so even
a reachability probe still requires a valid TLS handshake. A TLS failure, a content-check miss, or a
non-HTTP response map to ``Status.BAD_RESPONSE``; connection refused/timeout map as usual.

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
    """GET the node's URL; OK on 2xx + matching body text, or — with no urltext — any HTTP reply."""
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
    if node.url_text is None:
        return Status.OK  # reachability mode: any HTTP response means the server speaks HTTP (#104)
    if response.status_code in range(200, 300) and node.url_text in response.text:
        return Status.OK
    return Status.BAD_RESPONSE
