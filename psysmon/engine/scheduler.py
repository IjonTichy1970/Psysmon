"""Async monitoring scheduler — the heart of the engine.

Replaces the original serial sweep (``do_watch``/``monitor`` in syswatch.c) with concurrent,
per-host scheduling while preserving dependency suppression and the consecutive-failure
threshold semantics.

Design:

* Nodes are scheduled on a **min-heap keyed by ``next_due``** (monotonic time).
  :meth:`Scheduler.tick` pops every entry due now and either dispatches it as a tracked
  ``create_task`` (eligible) or re-queues it suppressed (ineligible); a dispatched node leaves
  the heap and is re-pushed ``+ interval`` when its check completes, so a slow check never
  delays its own next slot and an in-flight node can't busy-spin the wake timer.
  :meth:`Scheduler.run` ticks, then sleeps until the heap head's due time (or a stop). This is
  O(k log n) in the number actually due per wakeup, vs. the old O(n) scan.
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
import heapq
import logging
from collections.abc import Awaitable, Callable
from dataclasses import dataclass

from psysmon.checks import base, dns, http, pop3, smtp, tcp, udp
from psysmon.checks.ping import PingService
from psysmon.config.model import CheckType, Node, NodeState, type_to_name
from psysmon.config.settings import Settings
from psysmon.engine.clock import Clock, SystemClock
from psysmon.engine.dnscache import DnsCache
from psysmon.engine.state import PageIntent, apply_result, maybe_repage
from psysmon.status import errtostr, is_up

logger = logging.getLogger(__name__)

# Upper bound on the idle poll when every node is in flight (or none is scheduled), so the
# loop re-evaluates promptly as slow checks finish without busy-spinning.
_MAX_IDLE_POLL_S = 1.0

# Floor on a node's check interval. A non-positive interval would re-push a suppressed node at
# the current instant, and since tick() captures `now` once and the suppress branch never
# awaits, the heap loop would spin forever. Keeping every re-push strictly in the future avoids
# that (and 0/negative intervals are nonsensical anyway).
_MIN_INTERVAL_S = 0.01

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
    alive: bool = True  # cleared by reload(); a stale in-flight check on a dead node is dropped


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
        self._slow_check_s = settings.slow_check_s
        self._sem = asyncio.Semaphore(settings.max_concurrency)
        self._stop = asyncio.Event()
        self._dirty = asyncio.Event()
        self._dirty.set()  # render once at startup; thereafter set on real state changes
        self._tasks: set[asyncio.Task] = set()
        self.warnings: list[str] = []

        self._scheduled = self._flatten(roots)
        self._stagger_due(stagger)
        self._build_heap()

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
                interval=max(node.interval or self._default_interval, _MIN_INTERVAL_S),
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

    def _build_heap(self) -> None:
        """(Re)build the due-time min-heap from the current scheduled set.

        Entries are ``(next_due, seq, sched)``; the monotonic ``seq`` tiebreaks equal due times
        so two ``_Scheduled`` objects are never compared. A node is on the heap exactly when it
        is *not* in flight, making :meth:`tick` O(k log n) in the number actually due and
        :meth:`_next_delay` O(1) — replacing the old O(n) scans on every wakeup.
        """
        self._heap_seq = 0
        self._heap: list[tuple[float, int, _Scheduled]] = []
        for sched in self._scheduled:
            self._push(sched)

    def _push(self, sched: _Scheduled) -> None:
        heapq.heappush(self._heap, (sched.next_due, self._heap_seq, sched))
        self._heap_seq += 1

    # --- eligibility ------------------------------------------------------------------

    def _eligible(self, sched: _Scheduled) -> bool:
        """True iff every ping ancestor has been checked and is currently up.

        Requiring ``checked`` (not just the initial ``lastcheck == 0``) means a child isn't
        probed until its parent ping has a real result — so a node behind a down parent is
        never checked, matching the C sweep instead of leaking one check at startup.
        """
        return all(a.checked and is_up(a.state.lastcheck) for a in sched.gate)

    # --- the loop ---------------------------------------------------------------------

    async def tick(self) -> None:
        """Dispatch every node whose ``next_due`` has passed (checking it or suppressing it)."""
        now = self._clock.monotonic()
        while self._heap and self._heap[0][0] <= now:
            _due, _seq, sched = heapq.heappop(self._heap)
            sched.next_due = now + sched.interval  # next slot is interval from dispatch
            if self._eligible(sched):
                sched.in_flight = True
                task = asyncio.create_task(self._run_check(sched))
                self._tasks.add(task)
                task.add_done_callback(self._tasks.discard)
                # off the heap until the check completes (re-pushed in _run_check's finally)
            else:
                sched.state.suppressed = True
                self._push(sched)  # re-queue without checking — its state stays frozen

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

    async def wait_until_dirty(self, timeout: float) -> None:
        """Block until a node's displayed state changes or ``timeout`` elapses, then reset.

        Lets the daemon publish the status file on real transitions (with a periodic floor so
        elapsed-time displays stay fresh) instead of re-rendering on a fixed short interval.
        """
        try:
            await asyncio.wait_for(self._dirty.wait(), timeout)
        except TimeoutError:
            pass
        self._dirty.clear()

    async def drain(self) -> None:
        """Await all in-flight check tasks (used by tests and on shutdown)."""
        if self._tasks:
            await asyncio.gather(*list(self._tasks), return_exceptions=True)

    def _next_delay(self) -> float:
        """Seconds until the next waiting node is due — the heap head, in O(1).

        In-flight nodes are off the heap, so they can't peg the delay to 0 and busy-spin the
        loop while a slow check runs. When nothing is waiting (every node in flight, or none
        scheduled) we poll on a bounded fallback so the loop re-evaluates once checks finish.
        """
        if not self._heap:
            return min(self._default_interval, _MAX_IDLE_POLL_S)
        return max(0.0, self._heap[0][0] - self._clock.monotonic())

    # --- check execution + paging -----------------------------------------------------

    async def _default_runner(self, node: Node, ctx: base.CheckContext) -> int:
        if node.check_type is CheckType.PING:
            return await self._ping.check(node, ctx)
        return await base.perform(_CHECKERS[node.check_type], node, ctx)

    async def _run_check(self, sched: _Scheduled) -> None:
        node = sched.node
        try:
            if node.check_type is CheckType.PING:
                started = self._clock.monotonic()
                code = await self._runner(node, self._ctx)
            else:
                async with self._sem:
                    # Start timing only after acquiring the slot: a check that merely queued
                    # behind the concurrency cap shouldn't read as "ran for N seconds".
                    started = self._clock.monotonic()
                    code = await self._runner(node, self._ctx)
            elapsed = self._clock.monotonic() - started
            if self._slow_check_s > 0 and elapsed >= self._slow_check_s:
                logger.info("Check of %s of %s ran for %.1f seconds",
                            node.hostname, type_to_name(node.check_type), elapsed)
            logger.debug("checked %s of %s -> %s",
                         node.hostname, type_to_name(node.check_type), errtostr(code))
            if not sched.alive:
                return  # config was reloaded mid-check; this node's state is now orphaned
            if not self._eligible(sched):
                # Gate fell while we ran: discard the stale result, but mark suppressed now so
                # status/JSON immediately reflect that the node is gated off (matching tick()'s
                # ineligible branch) instead of showing a stale up host for up to one interval.
                sched.state.suppressed = True
                return
            sched.state.suppressed = False
            transition = apply_result(sched.state, code, self._clock.wall())
            sched.checked = True
            await self._handle_paging(sched, transition)
            if transition.state_changed:
                self._dirty.set()  # wake the status-render loop (publish-on-change)
                if self._on_state_change is not None:
                    self._on_state_change(node, sched.state)
        except Exception:
            logger.exception("check failed for %s", node.hostname)
        finally:
            sched.in_flight = False
            if sched.alive:
                self._push(sched)  # back on the heap for its next slot (dropped if reloaded away)

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

    def dns_stats(self) -> dict[str, int] | None:
        """DNS-cache stats for the periodic ``dnslog`` line, or None if the resolver has none."""
        stats = getattr(self._resolver, "stats", None)
        return stats if isinstance(stats, dict) else None

    @property
    def ping_service(self) -> PingService:
        """The shared ping service (so the daemon can open its raw socket up front)."""
        return self._ping

    # --- config reload (SIGHUP) -------------------------------------------------------

    _CARRIED = ("lastcheck", "downct", "contacted", "lastcontacted", "deathtime", "last_up")

    def reload(self, roots: list[Node]) -> None:
        """Rebuild the monitored tree from new config, preserving live state.

        Nodes still present (matched by hostname/type/port) keep their up/down state and
        counters; new nodes start fresh; removed nodes are dropped. Per-node ``max_down`` comes
        from the *new* config. Global settings (intervals, paths) are not re-applied here — a
        restart is needed for those.
        """
        previous = {
            (s.node.hostname, s.node.check_type, s.node.port): s for s in self._scheduled
        }
        # Orphan the outgoing scheduled objects: any check still in flight against one of them
        # completes into _run_check's ``not sched.alive`` guard and is discarded rather than
        # paging or mutating state that has already been carried onto the new objects.
        for old in self._scheduled:
            old.alive = False
        self.warnings = []
        self._scheduled = self._flatten(roots)
        seen: set[tuple[str, CheckType, int]] = set()
        for sched in self._scheduled:
            key = (sched.node.hostname, sched.node.check_type, sched.node.port)
            if key in seen:
                self.warnings.append(
                    f"duplicate node {sched.node.hostname} ({sched.node.check_type}"
                    f" port {sched.node.port}) in the new config; both will be scheduled "
                    "and share the carried-over state"
                )
            seen.add(key)
            old = previous.get(key)
            if old is not None:
                for field_name in self._CARRIED:
                    setattr(sched.state, field_name, getattr(old.state, field_name))
                sched.checked = old.checked
        self._stagger_due(True)
        self._build_heap()  # rebuild the queue for the new scheduled set (old entries dropped)
