"""Async monitoring scheduler — the heart of the engine.

Replaces the original serial sweep (``do_watch``/``monitor`` in syswatch.c) with concurrent,
per-host scheduling while preserving dependency suppression and the consecutive-failure
threshold semantics.

Design:

* Each monitored node carries a ``next_due`` (monotonic time) and an ``in_flight`` guard.
  :meth:`Scheduler.tick` dispatches every due, not-in-flight, *eligible* node as a tracked
  ``create_task`` and immediately reschedules it ``+ interval`` (a slow check never delays its
  own next slot). :meth:`Scheduler.run` ticks, then sleeps until the next due time (or a stop).
* **Dependency suppression** is an explicit eligibility gate: a node is eligible iff every
  ping ancestor is currently up (``lastcheck == OK``). An ineligible node is re-queued
  *without* being checked, so its state freezes — matching the C tree-walk that never visits a
  subtree behind a down parent. A node whose ancestor chain contains a *non-ping* is
  unreachable by the original's rules and is dropped from scheduling with a warning.
* A check result is **discarded** if the node's gate fell while the check was in flight
  (re-checked at completion), so a parent going down mid-check can't produce a stale alarm.
* **Ping** runs on the shared :class:`~psysmon.checks.ping.PingService` (one raw socket) and is
  *not* bounded by the per-check semaphore; all other checks are.
* Paging is wired through a :class:`~psysmon.notify.base.Notifier`: on a DOWN intent it pages
  and marks ``contacted``; on RECOVERY it pages the clear; otherwise a still-down contacted
  node is re-paged once ``pageinterval`` has elapsed (eligible nodes only — a fix vs. the C).
"""

from __future__ import annotations

import asyncio
import logging
from collections.abc import Awaitable, Callable
from dataclasses import dataclass

from psysmon.checks import base, dns, http, pop3, smtp, tcp, udp
from psysmon.checks.ping import PingService
from psysmon.config.model import CheckType, Node, NodeState
from psysmon.config.settings import Settings
from psysmon.engine.clock import Clock, SystemClock
from psysmon.engine.dnscache import DnsCache
from psysmon.engine.state import PageIntent, apply_result, maybe_repage
from psysmon.status import Status

logger = logging.getLogger(__name__)

# Upper bound on the idle poll when every node is in flight (or none is scheduled), so the
# loop re-evaluates promptly as slow checks finish without busy-spinning.
_MAX_IDLE_POLL_S = 1.0

# Non-ping check type -> checker coroutine.
_CHECKERS: dict[CheckType, base.Checker] = {
    CheckType.TCP: tcp.check,
    CheckType.UDP: udp.check,
    CheckType.SMTP: smtp.check,
    CheckType.POP3: pop3.check,
    CheckType.DNS: dns.check,
    CheckType.HTTP: http.check,
    CheckType.HTTPS: http.check,
}

# runner(node, ctx) -> status code; the seam between scheduling and check execution.
Runner = Callable[[Node, base.CheckContext], Awaitable[int]]


class _NullNotifier:
    """Default no-op notifier: no delivery, but reports 'contacted' so dedup still works."""

    async def send(self, node: Node, state: NodeState, intent: PageIntent) -> bool:
        return True


@dataclass(slots=True)
class _Scheduled:
    """A monitored node plus its runtime state and scheduling bookkeeping."""

    node: Node
    state: NodeState
    gate: list[_Scheduled]  # ancestor ping nodes; all must be checked-and-up to run
    interval: float
    next_due: float = 0.0
    in_flight: bool = False
    checked: bool = False  # has completed at least one (non-discarded) check


class Scheduler:
    """Drives concurrent per-host checks with dependency suppression and threshold paging."""

    def __init__(
        self,
        roots: list[Node],
        settings: Settings,
        *,
        clock: Clock | None = None,
        resolver: base.Resolver | None = None,
        ping_service: PingService | None = None,
        notifier=None,
        runner: Runner | None = None,
        on_state_change: Callable[[Node, NodeState], None] | None = None,
        stagger: bool = True,
    ) -> None:
        self._settings = settings
        self._clock = clock or SystemClock()
        self._resolver = resolver or DnsCache(settings.dnsexpire_s, settings.dnslog_s)
        self._ping = ping_service or PingService(settings.source_ip)
        self._notifier = notifier or _NullNotifier()
        self._runner = runner or self._default_runner
        self._on_state_change = on_state_change
        self._ctx = base.CheckContext(
            resolver=self._resolver, source_ip=settings.source_ip
        )
        self._default_interval = settings.interval_s
        self._pageinterval_s = settings.pageinterval_min * 60
        self._sem = asyncio.Semaphore(settings.max_concurrency)
        self._stop = asyncio.Event()
        self._tasks: set[asyncio.Task] = set()
        self.warnings: list[str] = []

        self._scheduled = self._flatten(roots)
        self._stagger_due(stagger)

    # --- tree flattening + gate computation -------------------------------------------

    def _flatten(self, roots: list[Node]) -> list[_Scheduled]:
        scheduled: list[_Scheduled] = []

        def walk(node: Node, gate: list[_Scheduled], reachable: bool) -> None:
            if not reachable:
                self.warnings.append(
                    f"{node.hostname} ({node.check_type}) sits behind a non-ping parent and "
                    "can never be reached; not scheduling it"
                )
                return
            state = NodeState(max_down=node.max_down, last_up=self._clock.wall())
            sched = _Scheduled(
                node=node,
                state=state,
                gate=list(gate),
                interval=node.interval or self._default_interval,
            )
            scheduled.append(sched)
            is_ping = node.check_type is CheckType.PING
            child_gate = [*gate, sched] if is_ping else gate
            for child in node.children:
                walk(child, child_gate, is_ping)  # children reachable only behind a ping

        for root in roots:
            walk(root, [], True)
        return scheduled

    def _stagger_due(self, stagger: bool) -> None:
        now = self._clock.monotonic()
        count = len(self._scheduled)
        for i, sched in enumerate(self._scheduled):
            offset = (i / count) * self._default_interval if stagger and count else 0.0
            sched.next_due = now + offset

    # --- eligibility ------------------------------------------------------------------

    def _eligible(self, sched: _Scheduled) -> bool:
        """True iff every ping ancestor has been checked and is currently up.

        Requiring ``checked`` (not just the initial ``lastcheck == 0``) means a child isn't
        probed until its parent ping has a real result — so a node behind a down parent is
        never checked, matching the C sweep instead of leaking one check at startup.
        """
        return all(a.checked and a.state.lastcheck == Status.OK for a in sched.gate)

    # --- the loop ---------------------------------------------------------------------

    async def tick(self) -> None:
        """Dispatch every due, not-in-flight node once (checking it or suppressing it)."""
        now = self._clock.monotonic()
        for sched in self._scheduled:
            if sched.in_flight or sched.next_due > now:
                continue
            sched.next_due = now + sched.interval
            if self._eligible(sched):
                sched.in_flight = True
                task = asyncio.create_task(self._run_check(sched))
                self._tasks.add(task)
                task.add_done_callback(self._tasks.discard)
            else:
                sched.state.suppressed = True

    async def run(self) -> None:
        """Run the monitoring loop until :meth:`stop` (then drain in-flight checks)."""
        self._stop.clear()
        try:
            while not self._stop.is_set():
                await self.tick()
                try:
                    await asyncio.wait_for(self._stop.wait(), timeout=self._next_delay())
                except TimeoutError:
                    pass
        finally:
            await self.drain()

    def stop(self) -> None:
        self._stop.set()

    async def drain(self) -> None:
        """Await all in-flight check tasks (used by tests and on shutdown)."""
        if self._tasks:
            await asyncio.gather(*list(self._tasks), return_exceptions=True)

    def _next_delay(self) -> float:
        """Seconds until the next actionable node is due.

        In-flight nodes are excluded: their ``next_due`` is already in the past (it was
        advanced when they were dispatched) and :meth:`tick` won't re-dispatch them until
        they complete, so counting them would peg the delay at 0 and busy-spin the loop while
        a slow check runs. When nothing is actionable (every node in flight, or none
        scheduled) we poll on a bounded fallback so the loop re-evaluates once those checks
        finish.
        """
        now = self._clock.monotonic()
        due = [s.next_due for s in self._scheduled if not s.in_flight]
        if not due:
            return min(self._default_interval, _MAX_IDLE_POLL_S)
        return max(0.0, min(due) - now)

    # --- check execution + paging -----------------------------------------------------

    async def _default_runner(self, node: Node, ctx: base.CheckContext) -> int:
        if node.check_type is CheckType.PING:
            return await self._ping.check(node, ctx)
        return await base.perform(_CHECKERS[node.check_type], node, ctx)

    async def _run_check(self, sched: _Scheduled) -> None:
        node = sched.node
        try:
            if node.check_type is CheckType.PING:
                code = await self._runner(node, self._ctx)
            else:
                async with self._sem:
                    code = await self._runner(node, self._ctx)
            if not self._eligible(sched):
                return  # gate fell while we ran; discard the stale result
            sched.state.suppressed = False
            transition = apply_result(sched.state, code, self._clock.wall())
            sched.checked = True
            await self._handle_paging(sched, transition)
            if transition.state_changed and self._on_state_change is not None:
                self._on_state_change(node, sched.state)
        except Exception:
            logger.exception("check failed for %s", node.hostname)
        finally:
            sched.in_flight = False

    async def _handle_paging(self, sched: _Scheduled, transition) -> None:
        node, state = sched.node, sched.state
        if transition.intent is PageIntent.DOWN:
            if await self._notifier.send(node, state, PageIntent.DOWN):
                state.contacted = True
                state.lastcontacted = self._clock.monotonic()
        elif transition.intent is PageIntent.RECOVERY:
            await self._notifier.send(node, state, PageIntent.RECOVERY)
        elif state.contacted and maybe_repage(state, self._clock.monotonic(), self._pageinterval_s):
            if await self._notifier.send(node, state, PageIntent.DOWN):
                state.lastcontacted = self._clock.monotonic()

    # --- introspection (for output / tests) -------------------------------------------

    def node_states(self) -> list[tuple[Node, NodeState]]:
        return [(s.node, s.state) for s in self._scheduled]
