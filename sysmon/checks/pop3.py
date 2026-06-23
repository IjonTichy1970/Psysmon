"""POP3 authenticated check (Milestone 6).

Connects to port 110, sends ``USER``/``PASS`` and expects ``+OK``; ``-ERR`` -> ``BAD_AUTH``.
(Credentials come from the node; the legacy config stores them in cleartext — see security
issue #2.)

Not yet implemented.
"""

from __future__ import annotations

from sysmon.config.model import Node


async def check(node: Node, deadline: float) -> int:
    raise NotImplementedError("Milestone 6: pop3 check")
