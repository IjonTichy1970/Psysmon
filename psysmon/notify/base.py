"""Notifier interface and message templating.

A ``Notifier`` delivers a page for a node and returns whether the page should count as
"contacted" (delivered, or there was no contact to deliver to) — the scheduler uses that to
set the dedup flag, faithful to the original's "the act of paging is the dedup point".

``render_message`` reproduces the original ``PMESG`` template tokens:
``%m`` my hostname · ``%h`` failed host (with possessive ``'s`` unless it's a ping) ·
``%t`` current time · ``%d`` downtime (DD:HH:MM) · ``%u`` status string · ``%w`` the node's
message/label (blank for a ping).
"""

from __future__ import annotations

from typing import Protocol

from psysmon import timefmt
from psysmon.config.model import Node, NodeState, is_ping_type
from psysmon.engine.state import PageIntent
from psysmon.status import errtostr

# The original config.h default PMESG.
DEFAULT_TEMPLATE = "%t: %h %w is %u %d"


class Notifier(Protocol):
    """Delivers a page for ``node``; returns True if it should count as contacted."""

    async def send(self, node: Node, state: NodeState, intent: PageIntent) -> bool: ...


def render_message(
    template: str, node: Node, state: NodeState, *, myname: str, now_wall: float
) -> str:
    """Expand a ``PMESG``-style template into a page body."""
    is_ping = is_ping_type(node.check_type)
    tokens = {
        "m": myname,
        "h": node.hostname + ("" if is_ping else "'s"),
        "t": timefmt.clock_time(now_wall),
        "d": timefmt.elapsed(state.deathtime, now_wall),
        "u": errtostr(state.lastcheck),
        "w": "" if is_ping else node.label,
    }
    out: list[str] = []
    i = 0
    while i < len(template):
        if template[i] == "%" and i + 1 < len(template):
            out.append(tokens.get(template[i + 1], template[i : i + 2]))
            i += 2
        else:
            out.append(template[i])
            i += 1
    return "".join(out)
