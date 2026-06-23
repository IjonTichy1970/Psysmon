"""Async monitoring scheduler — the heart of the engine.

Replaces the original serial sweep (``do_watch``/``monitor`` in syswatch.c) with concurrent,
per-host scheduling while preserving dependency suppression and the consecutive-failure
threshold semantics.

Design (Milestone 8):

* A single loop owns a **min-heap keyed by each node's ``next_due``** plus a global
  ``asyncio.Semaphore`` bounding socket/protocol checks. Each tick pops all due+eligible
  nodes, dispatches a tracked ``create_task`` per node, and immediately reschedules
  ``next_due += interval`` (a slow check never delays its own next slot; re-entry guarded by
  an ``in_flight`` flag), then sleeps until the next heap head or a wake event.
* **Dependency suppression** is an explicit eligibility gate: a node is eligible iff every
  ping ancestor currently has ``lastcheck == 0``. Ineligible nodes are re-queued *without*
  being checked, so their state freezes (matching the C tree-walk that never visits the
  subtree). In-flight results whose gate fell before completion are discarded.
* **Ping** is bounded separately via :class:`sysmon.checks.ping.PingService` (one shared raw
  socket), not by the semaphore.

Not yet implemented.
"""

from __future__ import annotations

from sysmon.config.model import Node
from sysmon.config.settings import Settings
from sysmon.engine.clock import Clock


class Scheduler:
    """Owns the due-time heap and dispatches concurrent checks under a concurrency bound."""

    def __init__(self, roots: list[Node], settings: Settings, clock: Clock) -> None:
        self._roots = roots
        self._settings = settings
        self._clock = clock

    async def run(self) -> None:
        """Run the monitoring loop until cancelled."""
        raise NotImplementedError("Milestone 8: async scheduler")
