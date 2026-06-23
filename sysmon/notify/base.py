"""Notifier interface and message templating (Milestone 9).

A ``Notifier`` delivers a page for a node. After a successful send (or immediately when a
node has no contact address) the caller sets ``state.contacted`` / ``state.lastcontacted`` —
the act of paging is the dedup point (faithful to ``page.c``).

``render_message`` reproduces the original ``PMESG`` template tokens (``%t`` time, ``%h``
host, ``%w`` what, ``%u`` status string, ``%d`` downtime, ``%m`` my-hostname).

Not yet implemented.
"""

from __future__ import annotations

from typing import Protocol

from sysmon.config.model import Node, NodeState
from sysmon.engine.state import PageIntent


class Notifier(Protocol):
    """Delivers a page for ``node`` given the current ``state`` and page ``intent``."""

    async def send(self, node: Node, state: NodeState, intent: PageIntent) -> bool: ...


def render_message(template: str, node: Node, state: NodeState) -> str:
    """Expand a ``PMESG``-style template into a page body."""
    raise NotImplementedError("Milestone 9: message templating")
