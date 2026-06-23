"""Simulated-clock tests for the async scheduler.

Time is driven by a ManualClock; checks run through an injected scripted runner and a fake
notifier, so every scheduling/suppression/paging behavior is asserted deterministically
without real network or wall-clock waits.
"""

from __future__ import annotations

import asyncio
from collections import Counter

from psysmon.config.model import CheckType, Node
from psysmon.config.settings import Settings
from psysmon.engine.clock import ManualClock, SystemClock
from psysmon.engine.scheduler import Scheduler
from psysmon.engine.state import PageIntent
from psysmon.status import Status


def settings(**kw) -> Settings:
    s = Settings()
    s.interval_s = 10.0
    s.max_concurrency = 10
    s.pageinterval_min = 1  # 60s re-page
    for k, v in kw.items():
        setattr(s, k, v)
    return s


def node(host, ctype=CheckType.PING, *, children=None, max_down=2) -> Node:
    return Node(hostname=host, check_type=ctype, max_down=max_down, children=children or [])


class ScriptedRunner:
    """Returns a per-host status code (mutable between ticks) and counts calls."""

    def __init__(self, codes=None):
        self.codes = codes or {}
        self.calls: Counter[str] = Counter()

    async def __call__(self, node, ctx):
        self.calls[node.hostname] += 1
        return self.codes.get(node.hostname, Status.OK)


class FakeNotifier:
    def __init__(self, deliver=True):
        self.deliver = deliver
        self.sent: list[tuple[str, PageIntent]] = []

    async def send(self, node, state, intent):
        self.sent.append((node.hostname, intent))
        return self.deliver

    def count(self, intent) -> int:
        return sum(1 for _, i in self.sent if i is intent)


def make(roots, runner, clock, notifier=None, **skw) -> tuple[Scheduler, FakeNotifier]:
    notifier = notifier or FakeNotifier()
    sched = Scheduler(
        roots, settings(**skw), clock=clock, runner=runner, notifier=notifier, stagger=False
    )
    return sched, notifier


async def tick_drain(sched):
    await sched.tick()
    await sched.drain()


def state_of(sched, host):
    return next(st for nd, st in sched.node_states() if nd.hostname == host)


# --- threshold paging -----------------------------------------------------------------

async def test_pages_once_at_threshold():
    clock = ManualClock()
    runner = ScriptedRunner({"r": Status.UNPINGABLE})
    sched, notifier = make([node("r", max_down=2)], runner, clock)

    await tick_drain(sched)  # t=0: downct 1, no page
    assert notifier.count(PageIntent.DOWN) == 0
    clock.advance(10)
    await tick_drain(sched)  # t=10: downct 2 -> DOWN
    assert notifier.count(PageIntent.DOWN) == 1
    clock.advance(10)
    await tick_drain(sched)  # t=20: still down, contacted -> no repeat
    assert notifier.count(PageIntent.DOWN) == 1
    assert state_of(sched, "r").contacted is True


async def test_recovery_pages_once():
    clock = ManualClock()
    runner = ScriptedRunner({"r": Status.UNPINGABLE})
    sched, notifier = make([node("r", max_down=1)], runner, clock)

    await tick_drain(sched)  # down + paged immediately (max_down=1)
    assert notifier.count(PageIntent.DOWN) == 1
    runner.codes["r"] = Status.OK
    clock.advance(10)
    await tick_drain(sched)  # recovers
    assert notifier.count(PageIntent.RECOVERY) == 1
    st = state_of(sched, "r")
    assert st.contacted is False and st.lastcheck == Status.OK


# --- dependency suppression -----------------------------------------------------------

async def test_parent_down_freezes_children():
    clock = ManualClock()
    child = node("c", CheckType.TCP)
    parent = node("p", CheckType.PING, children=[child], max_down=1)
    runner = ScriptedRunner({"p": Status.UNPINGABLE})  # child would be OK if checked
    sched, _ = make([parent], runner, clock)

    for _ in range(4):  # several sweeps with the parent down (t = 0, 10, 20, 30)
        await tick_drain(sched)
        clock.advance(10)

    assert runner.calls["c"] == 0  # child never checked behind a down parent
    cstate = state_of(sched, "c")
    assert cstate.suppressed is True
    assert cstate.lastcheck == Status.OK  # state frozen at its initial value


async def test_child_resumes_when_parent_recovers():
    clock = ManualClock()
    child = node("c", CheckType.TCP)
    parent = node("p", CheckType.PING, children=[child], max_down=1)
    runner = ScriptedRunner({"p": Status.UNPINGABLE})
    sched, _ = make([parent], runner, clock)

    clock.advance(0)
    await tick_drain(sched)  # parent checked down; child suppressed
    clock.advance(10)
    await tick_drain(sched)
    assert runner.calls["c"] == 0

    runner.codes["p"] = Status.OK  # parent recovers
    clock.advance(10)
    await tick_drain(sched)  # parent up + checked
    clock.advance(10)
    await tick_drain(sched)  # child now eligible -> checked
    assert runner.calls["c"] >= 1


async def test_unreachable_behind_non_ping_is_not_scheduled():
    # A child behind a non-ping (tcp) parent can never be reached in the original's model.
    child = node("c", CheckType.TCP)
    parent = node("p", CheckType.TCP, children=[child])
    sched, _ = make([parent], ScriptedRunner(), ManualClock())
    hosts = {nd.hostname for nd, _ in sched.node_states()}
    assert hosts == {"p"}
    assert any("can never be reached" in w for w in sched.warnings)


# --- re-page --------------------------------------------------------------------------

async def test_repage_after_interval():
    clock = ManualClock()
    runner = ScriptedRunner({"r": Status.UNPINGABLE})
    sched, notifier = make([node("r", max_down=1)], runner, clock, pageinterval_min=1)

    await tick_drain(sched)  # t=0: down + paged (lastcontacted=0)
    assert notifier.count(PageIntent.DOWN) == 1
    clock.advance(30)
    await tick_drain(sched)  # t=30: 30 < 60, no re-page
    assert notifier.count(PageIntent.DOWN) == 1
    clock.advance(40)
    await tick_drain(sched)  # t=70: 70 > 60 -> re-page
    assert notifier.count(PageIntent.DOWN) == 2


async def test_down_but_eligible_node_is_rechecked_and_repages():
    # A node that is itself down but whose ancestors are up stays eligible: it must be
    # re-checked every interval and re-page after pageinterval (it is NOT suppressed).
    clock = ManualClock()
    runner = ScriptedRunner({"r": Status.UNPINGABLE})
    sched, notifier = make([node("r", max_down=2)], runner, clock, pageinterval_min=1)

    await tick_drain(sched)  # t=0: downct 1
    clock.advance(10)
    await tick_drain(sched)  # t=10: downct 2 -> DOWN paged (lastcontacted=10)
    assert notifier.count(PageIntent.DOWN) == 1
    st = state_of(sched, "r")
    assert st.contacted is True and st.suppressed is False

    # Keep ticking while still down: re-checked every interval, no re-page until >60s elapsed.
    for _ in range(20, 80, 10):
        clock.advance(10)
        await tick_drain(sched)
    assert runner.calls["r"] == 8  # one check per interval at t=0,10,...,70
    assert notifier.count(PageIntent.DOWN) == 1  # 70 - 10 = 60, not yet strictly > 60

    clock.advance(10)
    await tick_drain(sched)  # t=80: 80 - 10 = 70 > 60 -> re-page
    assert notifier.count(PageIntent.DOWN) == 2


async def test_deep_suppression_chain_freezes_and_recovers():
    # 3 levels: g(ping) -> p(ping) -> c(tcp). g down must freeze BOTH p and c; when g
    # recovers, p resumes, and once p is checked-and-up, c (the grandchild) resumes too.
    clock = ManualClock()
    child = node("c", CheckType.TCP)
    parent = node("p", CheckType.PING, children=[child], max_down=1)
    grandparent = node("g", CheckType.PING, children=[parent], max_down=1)
    runner = ScriptedRunner({"g": Status.UNPINGABLE})
    sched, _ = make([grandparent], runner, clock)

    for _ in range(4):  # grandparent down through several sweeps
        await tick_drain(sched)
        clock.advance(10)
    assert runner.calls["p"] == 0  # parent frozen behind down grandparent
    assert runner.calls["c"] == 0  # grandchild frozen too
    assert state_of(sched, "p").suppressed is True
    assert state_of(sched, "c").suppressed is True

    runner.codes["g"] = Status.OK  # grandparent recovers
    for _ in range(4):  # g checked up -> p eligible -> p checked up -> c eligible
        await tick_drain(sched)
        clock.advance(10)
    assert runner.calls["p"] >= 1  # parent resumed
    assert runner.calls["c"] >= 1  # grandchild resumed once its full chain is up
    assert state_of(sched, "c").suppressed is False


async def test_multiple_roots_independent():
    # Two independent roots: one down (and freezing its child), one up (its child runs).
    clock = ManualClock()
    down_child = node("dc", CheckType.TCP)
    down_root = node("dr", CheckType.PING, children=[down_child], max_down=1)
    up_child = node("uc", CheckType.TCP)
    up_root = node("ur", CheckType.PING, children=[up_child], max_down=1)
    runner = ScriptedRunner({"dr": Status.UNPINGABLE})  # ur defaults OK
    sched, _ = make([down_root, up_root], runner, clock)

    for _ in range(3):
        await tick_drain(sched)
        clock.advance(10)

    assert runner.calls["dc"] == 0  # child of the down root is suppressed
    assert state_of(sched, "dc").suppressed is True
    assert runner.calls["uc"] >= 1  # child of the up root runs normally
    assert state_of(sched, "uc").lastcheck == Status.OK


# --- concurrency / robustness ---------------------------------------------------------


async def test_slow_inflight_node_does_not_busy_spin_next_delay():
    # Regression: a slow check whose next_due is already in the past must not peg _next_delay
    # at 0 (which would busy-spin run()). In-flight nodes are excluded from the wake-time calc.
    clock = ManualClock()
    n = node("s", CheckType.TCP)
    sched, _ = make([n], ScriptedRunner(), clock, interval_s=10.0)

    s0 = next(s for s in sched._scheduled if s.node.hostname == "s")
    s0.in_flight = True
    s0.next_due = -100.0  # overdue, but in flight -> must be ignored by _next_delay
    clock.advance(50)
    # With the node excluded, no actionable node remains -> bounded idle poll, not 0.
    assert sched._next_delay() > 0.0

    s0.in_flight = False  # once it completes, the overdue node drives an immediate wake
    assert sched._next_delay() == 0.0

async def test_hung_check_does_not_stall_others():
    clock = ManualClock()
    gate = asyncio.Event()

    class HangA(ScriptedRunner):
        async def __call__(self, node, ctx):
            self.calls[node.hostname] += 1
            if node.hostname == "a":
                await gate.wait()  # hang until released
            return self.codes.get(node.hostname, Status.OK)

    runner = HangA({"b": Status.UNPINGABLE})
    sched, _ = make([node("a", CheckType.TCP), node("b", CheckType.TCP)], runner, clock)

    await sched.tick()  # spawns both concurrently
    await asyncio.sleep(0.02)  # b completes while a hangs
    assert state_of(sched, "b").lastcheck == Status.UNPINGABLE  # b ran + applied its result
    assert runner.calls["a"] == 1  # a started but is still blocked (not stalling b)
    gate.set()
    await sched.drain()


async def test_stale_result_discarded_when_gate_falls():
    clock = ManualClock()
    gate = asyncio.Event()

    class HangChild(ScriptedRunner):
        async def __call__(self, node, ctx):
            self.calls[node.hostname] += 1
            if node.hostname == "c":
                await gate.wait()
                return Status.UNPINGABLE  # a "down" result that must be discarded
            return Status.OK

    child = node("c", CheckType.TCP)
    parent = node("p", CheckType.PING, children=[child], max_down=5)
    runner = HangChild()
    sched, _ = make([parent], runner, clock)

    await tick_drain(sched)  # t=0: parent checked up; child suppressed (parent not yet checked)
    clock.advance(10)
    await sched.tick()  # t=10: parent + child both spawned; child blocks on gate
    await asyncio.sleep(0.02)  # let parent finish, child reach the gate
    state_of(sched, "p").lastcheck = Status.UNPINGABLE  # parent goes down mid-child-check
    gate.set()
    await sched.drain()
    # The child's down result arrived after its gate fell, so it must be discarded.
    assert state_of(sched, "c").lastcheck == Status.OK


async def test_discarded_stale_result_marks_node_suppressed():
    # A node that is checked-and-up (suppressed=False) is re-dispatched; its gate falls during
    # the in-flight window. The discarded result must also flip suppressed=True so status/JSON
    # don't show a stale up host until the next tick (#37).
    clock = ManualClock()
    gate = asyncio.Event()

    class ChildHangsOnSecondCheck(ScriptedRunner):
        async def __call__(self, node, ctx):
            self.calls[node.hostname] += 1
            if node.hostname == "c" and self.calls["c"] >= 2:
                await gate.wait()  # block only the second check of the child
            return Status.OK

    child = node("c", CheckType.TCP)
    parent = node("p", CheckType.PING, children=[child], max_down=5)
    runner = ChildHangsOnSecondCheck()
    sched, _ = make([parent], runner, clock)

    await tick_drain(sched)   # t=0: parent checked up; child suppressed (parent not yet checked)
    clock.advance(10)
    await tick_drain(sched)   # t=10: child eligible -> checked OK -> suppressed=False
    assert state_of(sched, "c").suppressed is False

    clock.advance(10)
    await sched.tick()        # t=20: parent + child dispatched; child blocks on the gate
    await asyncio.sleep(0.02)
    state_of(sched, "p").lastcheck = Status.UNPINGABLE  # parent goes down mid-child-check
    gate.set()
    await sched.drain()

    assert state_of(sched, "c").suppressed is True       # discard path flipped it (was False)
    assert state_of(sched, "c").lastcheck == Status.OK   # stale down result still discarded


async def test_reload_discards_inflight_result_and_does_not_page():
    # A check in flight when SIGHUP reload swaps the scheduled set is orphaned: it must NOT
    # page or mutate the carried-over state, else it pages against dead state and the fresh
    # node re-pages the same outage (issue #27).
    clock = ManualClock()
    gate = asyncio.Event()

    class HangRoot(ScriptedRunner):
        async def __call__(self, node, ctx):
            self.calls[node.hostname] += 1
            await gate.wait()
            return Status.UNPINGABLE  # would cross threshold and page if applied

    runner = HangRoot()
    sched, notifier = make([node("r", max_down=1)], runner, clock)

    await sched.tick()  # dispatch r; it blocks on the gate, still in flight
    await asyncio.sleep(0.02)
    sched.reload([node("r", max_down=1)])  # SIGHUP-equivalent: rebuild while the check runs
    gate.set()
    await sched.drain()  # the orphaned check completes here

    assert notifier.count(PageIntent.DOWN) == 0  # the stale down result did not page
    assert state_of(sched, "r").lastcheck == Status.OK  # fresh carried state, not clobbered
    assert state_of(sched, "r").downct == 0


# --- run() smoke ----------------------------------------------------------------------

async def test_run_loop_smoke():
    runner = ScriptedRunner()
    sched = Scheduler(
        [node("r", CheckType.TCP)], settings(interval_s=0.01), clock=SystemClock(),
        runner=runner, notifier=FakeNotifier(), stagger=False,
    )
    task = asyncio.create_task(sched.run())
    await asyncio.sleep(0.05)
    sched.stop()
    await asyncio.wait_for(task, timeout=1.0)
    assert runner.calls["r"] >= 1
