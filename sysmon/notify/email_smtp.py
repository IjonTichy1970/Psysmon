"""Default SMTP email notifier.

Sends pages as email via SMTP, replacing the original's ``popen("/usr/lib/sendmail -t")``.
Host/port, the From address, and the org hostname come from settings. The blocking ``smtplib``
send runs in a worker thread so it never stalls the async engine.

The actual delivery is injectable (``send_fn``) so the notifier is tested hermetically — no
SMTP server required — and the clock is injectable for deterministic message timestamps.
"""

from __future__ import annotations

import asyncio
import logging
import smtplib
import socket
from collections.abc import Awaitable, Callable
from email.message import EmailMessage

from sysmon.config.model import Node, NodeState
from sysmon.config.settings import Settings
from sysmon.engine.state import PageIntent
from sysmon.notify.base import DEFAULT_TEMPLATE, render_message
from sysmon.status import errtostr

logger = logging.getLogger(__name__)

SendFn = Callable[[EmailMessage], Awaitable[None]]

# Bound the blocking SMTP exchange so a hung/black-holing mail server can't pin a worker
# thread forever (smtplib's own default is an infinite socket timeout) and so the node's
# check task — which awaits send() — can't stay in_flight indefinitely.
DEFAULT_SMTP_TIMEOUT_S = 30.0


class SmtpNotifier:
    """Notifier that delivers pages over SMTP."""

    def __init__(
        self,
        settings: Settings,
        *,
        template: str = DEFAULT_TEMPLATE,
        send_fn: SendFn | None = None,
        now_wall: Callable[[], float] | None = None,
        timeout: float = DEFAULT_SMTP_TIMEOUT_S,
    ) -> None:
        self._settings = settings
        self._template = template
        self._send_fn = send_fn
        self._now = now_wall or self._wall_clock
        self._timeout = timeout
        self._myname = settings.org_hostname or socket.gethostname()
        self._from = settings.mail_from or f"sysmon@{self._myname}"

    @staticmethod
    def _wall_clock() -> float:
        import time

        return time.time()

    async def send(self, node: Node, state: NodeState, intent: PageIntent) -> bool:
        # Nobody to page: treat as handled so the state machine dedups (matches the C, which
        # marks an empty-contact node contacted to stop repeating).
        if not node.contact:
            return True
        if not self._settings.notify_enabled:
            logger.info(
                "notifications disabled; would page %s about %s", node.contact, node.hostname
            )
            return True

        try:
            # Built inside the guard: a malformed message (e.g. a CR/LF in the contact
            # address, which EmailMessage rejects to block header injection) must surface as
            # a False return, not escape send() and break the `-> bool` contract.
            message = self._build(node, state, intent)
            if self._send_fn is not None:
                await self._send_fn(message)
            else:
                await asyncio.to_thread(self._smtp_send, message)
        except Exception:
            logger.exception("failed to page %s about %s", node.contact, node.hostname)
            return False  # delivery failed -> not contacted, so it will be retried
        return True

    def _build(self, node: Node, state: NodeState, intent: PageIntent) -> EmailMessage:
        message = EmailMessage()
        message["From"] = self._from
        message["To"] = node.contact
        if intent is PageIntent.RECOVERY:
            message["Subject"] = f"{node.hostname} has recovered"
        else:
            message["Subject"] = f"{node.hostname} is {errtostr(state.lastcheck)}"
        message.set_content(
            render_message(self._template, node, state, myname=self._myname, now_wall=self._now())
        )
        return message

    def _smtp_send(self, message: EmailMessage) -> None:
        source = (self._settings.source_ip, 0) if self._settings.source_ip else None
        with smtplib.SMTP(
            self._settings.smtp_host,
            self._settings.smtp_port,
            timeout=self._timeout,
            source_address=source,
        ) as smtp:
            smtp.send_message(message)
