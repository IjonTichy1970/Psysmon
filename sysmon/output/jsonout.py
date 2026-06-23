"""JSON status output (Milestone 10).

Serializes the full monitored tree with live state for dashboards/automation. Unlike the
HTML view, the JSON includes *all* nodes and carries a ``suppressed`` flag so the blast
radius of a parent outage is queryable even though suppressed children are hidden from HTML.

Not yet implemented.
"""

from __future__ import annotations

from sysmon.config.model import Node


def to_json(roots: list[Node]) -> str:
    """Return the monitored tree + live state as a JSON string."""
    raise NotImplementedError("Milestone 10: JSON status")
