"""HTML status page render + atomic publish (Milestone 10).

Renders the "Bad Hosts" view — by default only nodes with ``lastcheck != 0`` (down),
suppressed children omitted (owner choice) — as modern HTML5+CSS with a meta-refresh.
Columns match the original: HostName, Type, Port, Count, Notified, Status, Time Failed,
Last Outage.

Atomic publish is preserved from ``textfile.c``: write ``<path><pid>``, ``chmod 0444``,
``rename`` over the target so readers never see a partial file.

Not yet implemented.
"""

from __future__ import annotations

from sysmon.config.model import Node
from sysmon.config.settings import Settings


def render_and_publish(roots: list[Node], settings: Settings) -> None:
    """Render the status page and atomically publish it to ``settings.status_path``."""
    raise NotImplementedError("Milestone 10: HTML status page")
