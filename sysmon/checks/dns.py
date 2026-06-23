"""Authoritative DNS check (Milestone 6).

A clean reimplementation of the legacy ``authdns`` type using ``dnspython``: send a
non-recursive query for the configured name to the target server and inspect rcode / answer
count / the AA bit. Replaces the original's BIND ``_res`` fiddling.

Not yet implemented.
"""

from __future__ import annotations

from sysmon.config.model import Node


async def check(node: Node, deadline: float) -> int:
    raise NotImplementedError("Milestone 6: authoritative dns check")
