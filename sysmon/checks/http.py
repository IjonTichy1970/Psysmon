"""HTTP / HTTPS content check (Milestone 6).

Uses ``httpx`` to GET ``node.url`` and asserts ``node.url_text`` appears in the body. For
HTTPS, certificate verification is ON by default (the original did none). TLS failure,
non-2xx, or missing text all map to ``Status.BAD_RESPONSE`` to stay within the legacy code
set; connection refused/timeout map as usual.

Not yet implemented.
"""

from __future__ import annotations

from sysmon.config.model import Node


async def check(node: Node, deadline: float) -> int:
    raise NotImplementedError("Milestone 6: http/https content check")
