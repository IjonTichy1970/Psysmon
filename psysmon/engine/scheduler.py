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
  ping ancestor is currently *reachable* (up, or — with loss-tolerant ping — degraded; a lossy
  router still forwards, so its subtree is not masked). An ineligible node is re-queued *without*
  being checked, so its state freezes — matching the C tree-walk that never visits a subtree
  behind a down parent. A node whose ancestor chain contains a *non-ping* is unreachable by the
  original's rules and is dropped from scheduling with a warning.
* A check result is **discarded** if the node's gate fell while the check was in flight
  (re-checked at completion), so a parent going down mid-check can't produce a stale alarm.
* **Ping** runs on the shared :class:`~psysmon.checks.ping.PingService` (a source-keyed pool of
  raw sockets, #70) and is *not* bounded by the per-check semaphore; all other checks are.
* Paging is wired through a :class:`~psysmon.notify.base.Notifier`: on a DOWN intent it pages
  and marks ``contacted``; on RECOVERY it pages the clear; otherwise a still-down contacted
  node is re-paged once ``pageinterval`` has elapsed (eligible nodes only — a fix vs. the C).
"""

from __future__ import annotations

import asyncio
import heapq
import logging
from collections.abc import Awaitable, Callable
from dataclasses import dataclass, replace

from psysmon.checks import base, dns, http, pop3, smtp, tcp, udp
from psysmon.checks.ping import PingService
from psysmon.config.model import SOURCE_AUTO, CheckType, Node, NodeState, type_to_name
from psysmon.config.settings import Settings
from psysmon.engine.clock import Clock, SystemClock
from psysmon.engine.dnscache import DnsCache
from psysmon.engine.state import PageIntent, apply_result, maybe_repage
from psysmon.status import errtostr, is_reachable

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


def _as_int(value: object) -> int:
    # bool is an int subclass, so guard it out: a JSON `true` must not pass as a status/count.
    if isinstance(value, bool) or not isinstance(value, int):
        raise TypeError
    return value


def _as_float(value: object) -> float:
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        raise TypeError
    return float(value)


def _as_bool(value: object) -> bool:
    if not isinstance(value, bool):
        raise TypeError
    return value


_MAX_NOTE_LEN = 1024  # cap an operator note (#68): bounds rendering + a hand-edited state file


def _as_note(value: object) -> str | None:
    if value is None:
        return None
    if not isinstance(value, str):
        raise TypeError
    return value[:_MAX_NOTE_LEN]


def _validated_carry(record: dict) -> dict | None:
    """Type-check a persisted record's carried fields; None if any is missing or wrong-typed.

    A corrupt or hand-edited state file must degrade to a fresh start, never crash or wedge the
    state machine: a string ``downct`` would raise ``TypeError`` inside ``apply_result`` (caught
    by the scheduler's broad handler, leaving the node retrying every interval forever), and a
    wrong-typed ``lastcheck`` would mis-render or distort the up/down comparison. A bad record is
    skipped wholesale rather than half-restored. ``lastcontacted`` is intentionally absent: import
    rebases it to the live monotonic clock regardless of the persisted value.
    """
    try:
        return {
            "lastcheck": _as_int(record["lastcheck"]),
            "downct": _as_int(record["downct"]),
            "contacted": _as_bool(record["contacted"]),
            "deathtime": _as_float(record["deathtime"]),
            "last_up": _as_float(record["last_up"]),
            "acked": _as_bool(record["acked"]),
            "note": _as_note(record["note"]),
        }
    except (KeyError, TypeError):
        return None


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
    source: str | None = None  # resolved outbound bind source (#70); None = unbound
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
        self._ping = ping_service or PingService(
            send_pings=settings.send_pings, min_pings=settings.min_pings
        )
        self._notifier = notifier or _NullNotifier()
        self._runner = runner or self._default_runner
        self._on_state_change = on_state_change
        self._ctx = base.CheckContext(
            resolver=self._resolver, source_ip=settings.source_ip
        )
        self._default_interval = settings.interval_s
        self._pageinterval_s = settings.pageinterval_min * 60
        self._slow_check_s = settings.slow_check_s
        self._page_on_degraded = settings.page_on_degraded
        self._contact_on_default = settings.contact_on  # global default; per-object override wins
        self._sem = asyncio.Semaphore(settings.max_concurrency)
        self._stop = asyncio.Event()
        self._dirty = asyncio.Event()
        self._dirty.set()  # render once at startup; thereafter set on real state changes
        self._tasks: set[asyncio.Task] = set()
        self.warnings: list[str] = []

        self._scheduled = self._flatten(roots)
        # Tell the ping service which bound sources to pre-open (while still privileged) so each
        # configured per-object/group ping source gets its own raw socket in the pool (#70).
        self._ping.set_sources(self._collect_ping_sources())
        self._stagger_due(stagger)
        self._build_heap()

    # --- tree flattening + gate computation -------------------------------------------

    def _collect_ping_sources(self) -> set[str]:
        """Distinct bound sources among scheduled ping nodes — the bound sockets the ping pool
        must pre-open (the unbound default is implicit). Unset/`auto` ping nodes contribute none."""
        return {s.source for s in self._scheduled
                if s.node.check_type is CheckType.PING and s.source}

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
                source=self._effective_source(node),
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
        """True iff every ping ancestor has been checked and is currently reachable.

        Requiring ``checked`` (not just the initial ``lastcheck == 0``) means a child isn't
        probed until its parent ping has a real result — so a node behind a down parent is
        never checked, matching the C sweep instead of leaking one check at startup. Reachable is
        up *or* degraded (:func:`is_reachable`): a lossy-but-answering router still forwards, so
        gating its children off would hide genuine outages behind it (#22).
        """
        return all(a.checked and is_reachable(a.state.lastcheck) for a in sched.gate)

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

    def _effective_source(self, node: Node) -> str | None:
        """Resolve a node's outbound bind source (#70): the per-object/group token on
        ``node.source``, else the per-type default. Returns the local IP to bind, or ``None`` to
        leave the check unbound (the kernel routes by destination).

        ``auto`` -> unbound; an explicit IP -> bind (ping and connection checks alike); unset ->
        ping defaults unbound (ignoring the global ``source_ip``), every other check defaults to
        the global ``source_ip``.
        """
        tok = node.source
        if tok == SOURCE_AUTO:
            return None
        if tok:
            return tok
        if node.check_type is CheckType.PING:
            return None
        return self._settings.source_ip

    def _ctx_for(self, sched: _Scheduled) -> base.CheckContext:
        """The CheckContext for a non-ping check — the shared default unless this node resolved to
        a different outbound source (#70). Reused unchanged in the common (global-source) case."""
        if sched.source == self._ctx.source_ip:
            return self._ctx
        return replace(self._ctx, source_ip=sched.source)

    async def _default_runner(self, node: Node, ctx: base.CheckContext) -> int:
        if node.check_type is CheckType.PING:
            return await self._ping.check(node, ctx)
        return await base.perform(_CHECKERS[node.check_type], node, ctx)

    async def _run_check(self, sched: _Scheduled) -> None:
        node = sched.node
        try:
            if node.check_type is CheckType.PING:
                started = self._clock.monotonic()
                # ctx.source_ip carries this node's resolved ping source; the PingService picks the
                # matching pooled socket (None = unbound, ping's default regardless of source_ip).
                code = await self._runner(node, self._ctx_for(sched))
            else:
                async with self._sem:
                    # Start timing only after acquiring the slot: a check that merely queued
                    # behind the concurrency cap shouldn't read as "ran for N seconds".
                    started = self._clock.monotonic()
                    code = await self._runner(node, self._ctx_for(sched))
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
            transition = apply_result(
                sched.state, code, self._clock.wall(), page_on_degraded=self._page_on_degraded
            )
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
        # contact_on gates which transitions actually page. "both" (the default) preserves the
        # historical behavior. A per-object value overrides the global default.
        contact_on = node.contact_on or self._contact_on_default
        if transition.intent is PageIntent.DOWN:
            if state.acked:
                # Acknowledged (#68): suppress the down page, but mark contacted so a later
                # recovery still pages (subject to contact_on). acked auto-clears on recovery.
                state.contacted = True
                state.lastcontacted = self._clock.monotonic()
            elif contact_on in ("down", "both"):
                if await self._notifier.send(node, state, PageIntent.DOWN):
                    state.contacted = True
                    state.lastcontacted = self._clock.monotonic()
            elif contact_on == "up":
                # Don't page on the way down, but mark contacted so the recovery still pages
                # (apply_result only emits RECOVERY for a node that was contacted).
                state.contacted = True
                state.lastcontacted = self._clock.monotonic()
            # "none": page on neither transition — leave contacted clear (no re-page, no recovery).
        elif transition.intent is PageIntent.RECOVERY:
            # acked was cleared by apply_result on the up-transition, so contact_on alone decides.
            if contact_on in ("up", "both"):
                await self._notifier.send(node, state, PageIntent.RECOVERY)
        elif state.contacted and maybe_repage(state, self._clock.monotonic(), self._pageinterval_s):
            if not state.acked and contact_on in ("down", "both"):
                if await self._notifier.send(node, state, PageIntent.DOWN):
                    state.lastcontacted = self._clock.monotonic()
            else:  # acked, or "up": no re-page; advance the clock so we don't recheck every tick.
                # ("none" never reaches here — it stays uncontacted, so maybe_repage is False.)
                state.lastcontacted = self._clock.monotonic()

    # --- introspection (for output / tests) -------------------------------------------

    def node_states(self) -> list[tuple[Node, NodeState]]:
        return [(s.node, s.state) for s in self._scheduled]

    # --- runtime control (#68 ack/notes; driven by the control plane #69) -------------

    def _match(self, hostname: str, type_value: str, port: int) -> list[_Scheduled]:
        """Scheduled nodes with this (hostname, type-as-string, port) key (duplicates allowed)."""
        return [
            s for s in self._scheduled
            if s.node.hostname == hostname
            and s.node.check_type.value == type_value
            and s.node.port == port
        ]

    def ack(self, hostname: str, type_value: str, port: int) -> int:
        """Acknowledge an object's outage (#68): suppress its paging while down (auto-clears on
        recovery). Returns the number of matched nodes. Synchronous — no await between lookup and
        write — so a concurrent reload can't orphan the mutation."""
        matches = self._match(hostname, type_value, port)
        for sched in matches:
            sched.state.acked = True
        if matches:
            self._dirty.set()  # re-render the status page to show the ack
        return len(matches)

    def set_note(self, hostname: str, type_value: str, port: int, text: str | None) -> int:
        """Set (or clear, when empty/None) an object's operator note (#68); returns match count."""
        note = text[:_MAX_NOTE_LEN] if text else None
        matches = self._match(hostname, type_value, port)
        for sched in matches:
            sched.state.note = note
        if matches:
            self._dirty.set()
        return len(matches)

    def dns_stats(self) -> dict[str, int] | None:
        """DNS-cache stats for the periodic ``dnslog`` line, or None if the resolver has none."""
        stats = getattr(self._resolver, "stats", None)
        return stats if isinstance(stats, dict) else None

    @property
    def ping_service(self) -> PingService:
        """The shared ping service (so the daemon can open its raw socket up front)."""
        return self._ping

    # --- state persistence (savestate, #21) -------------------------------------------

    def export_state(self) -> list[dict]:
        """Serialize the carried runtime fields per node for on-disk persistence (#21).

        Emits one record per scheduled node — keyed by ``(hostname, type, port)`` like the
        SIGHUP merge — carrying exactly :data:`_CARRIED`. The type is stored as its string value
        so the record is plain JSON. Config-derived fields (``max_down``, contacts, intervals)
        and the transient ``suppressed`` flag are deliberately *not* persisted: they come from
        the config and the live gate on load and must not be resurrected from a stale file.
        """
        records: list[dict] = []
        for sched in self._scheduled:
            record = {
                "hostname": sched.node.hostname,
                "type": sched.node.check_type.value,
                "port": sched.node.port,
            }
            for field_name in self._CARRIED:
                record[field_name] = getattr(sched.state, field_name)
            records.append(record)
        return records

    def import_state(self, records: list[dict], *, now_mono: float | None = None) -> int:
        """Merge persisted ``records`` into the current node set, returning the match count (#21).

        Mirrors :meth:`reload`'s carried-field merge: a node still present (matched by
        ``(hostname, type, port)``) restores its up/down state and counters; a record with no
        matching node is dropped; a node new in the config keeps its fresh state. So a node that
        was DOWN and already contacted before the restart stays contacted and is not re-paged on
        the first post-restart sweep.

        ``lastcontacted`` is special: it is a *monotonic* timestamp, and a fresh process starts a
        new monotonic clock, so the persisted value is meaningless here. It is rebased to "now",
        which means a restored, still-contacted outage waits a fresh ``pageinterval`` before
        re-paging — never an immediate duplicate page, never a never-again page. ``checked`` is
        left ``False`` so each restored node is re-confirmed by its first real check (and its
        children stay gated until then) rather than trusting the snapshot's reachability.
        """
        if now_mono is None:
            now_mono = self._clock.monotonic()
        current = {
            (s.node.hostname, s.node.check_type.value, s.node.port): s for s in self._scheduled
        }
        matched = 0
        skipped = 0
        for record in records:
            key = (record.get("hostname"), record.get("type"), record.get("port"))
            sched = current.get(key)
            if sched is None:
                continue  # in the state file but absent from the current config -> drop
            carried = _validated_carry(record)
            if carried is None:
                skipped += 1  # malformed/wrong-typed fields -> skip wholesale, leave node fresh
                continue
            for field_name, value in carried.items():
                setattr(sched.state, field_name, value)
            sched.state.lastcontacted = now_mono  # rebase the monotonic re-page timer
            matched += 1
        if skipped:
            logger.warning("ignored %d state record(s) with malformed fields", skipped)
        return matched

    # --- config reload (SIGHUP) -------------------------------------------------------

    _CARRIED = (
        "lastcheck", "downct", "contacted", "lastcontacted", "deathtime", "last_up", "acked", "note"
    )

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
        # Refresh the configured ping-source set for the new tree, and close pooled sockets for
        # sources the new config dropped. (New sources aren't opened — prepare() already ran
        # pre-privilege-drop; a brand-new source falls back to unbound at check time.)
        ping_sources = self._collect_ping_sources()
        self._ping.set_sources(ping_sources)
        self._ping.prune(ping_sources)
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
