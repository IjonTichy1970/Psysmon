"""JSON status output.

Serializes every monitored node with its live state for dashboards/automation. Unlike the
HTML view, the JSON includes *all* nodes and carries a ``suppressed`` flag, so the blast radius
of a parent outage is queryable even though suppressed children are hidden from the HTML page.

Input is the scheduler's ``node_states()`` — a list of ``(Node, NodeState)``.
"""

from __future__ import annotations

import json

from psysmon.config.model import Node, NodeState
from psysmon.status import Status, errtostr

NodeStates = list[tuple[Node, NodeState]]


def _host(node: Node, state: NodeState) -> dict:
    return {
        "hostname": node.hostname,
        "type": node.check_type.value,
        "port": node.port,
        "label": node.label,
        "contact": node.contact,
        "up": state.lastcheck == Status.OK,
        "status": int(state.lastcheck),
        "status_text": errtostr(state.lastcheck),
        "count": state.downct,
        "notified": state.contacted,
        "suppressed": state.suppressed,
        "deathtime": state.deathtime or None,
        "last_up": state.last_up or None,
    }


def to_json(node_states: NodeStates, *, now_wall: float, indent: int | None = 2) -> str:
    """Return the monitored nodes + live state as a JSON string."""
    hosts = [_host(node, state) for node, state in node_states]
    payload = {
        "generated": now_wall,
        "down": sum(1 for h in hosts if not h["up"] and not h["suppressed"]),
        "total": len(hosts),
        "hosts": hosts,
    }
    return json.dumps(payload, indent=indent)
