"""SMTP banner check (Milestone 6).

Connects to port 25 and expects a ``220`` greeting; sends ``QUIT``. A missing/!``220``
banner -> ``Status.NO_RESPONSE``/``BAD_RESPONSE``.

Not yet implemented.
"""

from __future__ import annotations

from sysmon.config.model import Node


async def check(node: Node, deadline: float) -> int:
    raise NotImplementedError("Milestone 6: smtp check")
