"""Default SMTP email notifier (Milestone 9).

Sends pages as email via SMTP (configurable host/port; ``mail_from`` and the org hostname
come from settings). Replaces the original's ``popen("/usr/lib/sendmail -t")``.

Not yet implemented.
"""

from __future__ import annotations

from sysmon.config.model import Node, NodeState
from sysmon.config.settings import Settings
from sysmon.engine.state import PageIntent


class SmtpNotifier:
    """Notifier that delivers pages over SMTP."""

    def __init__(self, settings: Settings) -> None:
        self._settings = settings

    async def send(self, node: Node, state: NodeState, intent: PageIntent) -> bool:
        raise NotImplementedError("Milestone 9: SMTP notifier")
