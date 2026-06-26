"""Simulated-clock tests for the async scheduler.

Time is driven by a ManualClock; checks run through an injected scripted runner and a fake
notifier, so every scheduling/suppression/paging behavior is asserted deterministically
without real network or wall-clock waits.
"""

from __future__ import annotations

import asyncio
import logging
from collections import Counter

from psysmon.config.model import SOURCE_AUTO, CheckType, Node
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


# --- operational logging (#59) --------------------------------------------------------

async def test_slow_check_is_logged(caplog):
    clock = ManualClock()

    async def slow(node, ctx):
        clock.advance(31)  # the check "ran" 31s on the (manual) clock
        return Status.OK

    sched, _ = make([node("slow.example.net", CheckType.TCP)], slow, clock, slow_check_s=30.0)
    with caplog.at_level(logging.INFO, logger="psysmon.engine.scheduler"):
        await tick_drain(sched)
    assert "Check of slow.example.net of tcp ran for 31.0 seconds" in caplog.text


async def test_fast_check_is_not_logged_as_slow(caplog):
    clock = ManualClock()
    sched, _ = make(
        [node("fast.example.net", CheckType.TCP)], ScriptedRunner(), clock, slow_check_s=30.0)
    with caplog.at_level(logging.INFO, logger="psysmon.engine.scheduler"):
        await tick_drain(sched)
    assert "ran for" not in caplog.text


async def test_slow_check_threshold_zero_disables(caplog):
    clock = ManualClock()

    async def slow(node, ctx):
        clock.advance(99)
        return Status.OK

    sched, _ = make([node("slow.example.net", CheckType.TCP)], slow, clock, slow_check_s=0.0)
    with caplog.at_level(logging.INFO, logger="psysmon.engine.scheduler"):
        await tick_drain(sched)
    assert "ran for" not in caplog.text  # 0 disables the slow-check log


async def test_per_check_result_logged_at_debug(caplog):
    clock = ManualClock()
    sched, _ = make(
        [node("h.example.net", CheckType.TCP)],
        ScriptedRunner({"h.example.net": Status.CONN_REFUSED}), clock,
    )
    with caplog.at_level(logging.DEBUG, logger="psysmon.engine.scheduler"):
        await tick_drain(sched)
    assert "checked h.example.net of tcp -> Conn Ref" in caplog.text


async def test_per_check_result_not_logged_at_info(caplog):
    # The per-check result line is DEBUG-gated; at the default info level it must NOT appear —
    # this is what makes the leveled logging actually leveled.
    clock = ManualClock()
    sched, _ = make([node("h.example.net", CheckType.TCP)], ScriptedRunner(), clock)
    with caplog.at_level(logging.INFO, logger="psysmon.engine.scheduler"):
        await tick_drain(sched)
    assert "checked h.example.net" not in caplog.text


async def test_queue_wait_does_not_count_as_slow(caplog):
    # A check that merely waits for a concurrency slot must NOT be logged "slow" — only its own
    # execution time counts (#59 review). max_concurrency=1: a holder pins the only slot for 40s
    # while a do-nothing waiter queues behind it; the waiter's own probe is instant.
    clock = ManualClock()
    holder_in = asyncio.Event()
    release = asyncio.Event()

    async def runner(nd, ctx):
        if nd.hostname == "holder":
            holder_in.set()
            await release.wait()  # pin the only slot
        return Status.OK

    sched, _ = make(
        [node("holder", CheckType.TCP), node("waiter", CheckType.TCP)],
        runner, clock, max_concurrency=1, slow_check_s=30.0,
    )
    with caplog.at_level(logging.INFO, logger="psysmon.engine.scheduler"):
        await sched.tick()       # dispatch both; one holds the slot, the other queues
        await holder_in.wait()
        clock.advance(40)        # 40s elapse while the waiter is blocked on the semaphore
        release.set()
        await sched.drain()
    assert "Check of waiter" not in caplog.text  # queue-wait is not "ran for"
    assert "Check of holder of tcp ran for 40.0 seconds" in caplog.text  # genuine 40s of work


def test_dns_stats_exposes_resolver_stats():
    sched, _ = make([], ScriptedRunner(), ManualClock())  # default DnsCache resolver
    stats = sched.dns_stats()
    assert stats is not None and {"hits", "misses", "expired", "entries"} <= set(stats)


def test_dns_stats_none_when_resolver_has_no_stats():
    class _NoStats:
        async def resolve(self, host):
            return "127.0.0.1"

    sched = Scheduler([], settings(), resolver=_NoStats(), runner=ScriptedRunner())
    assert sched.dns_stats() is None


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


# --- contact_on (which transitions page) ----------------------------------------------

async def test_contact_on_down_suppresses_recovery_page():
    clock = ManualClock()
    n = node("r", max_down=1)
    n.contact_on = "down"
    runner = ScriptedRunner({"r": Status.UNPINGABLE})
    sched, notifier = make([n], runner, clock)
    await tick_drain(sched)  # down -> DOWN page
    assert notifier.count(PageIntent.DOWN) == 1
    runner.codes["r"] = Status.OK
    clock.advance(10)
    await tick_drain(sched)  # recovers -> no recovery page (contact_on=down)
    assert notifier.count(PageIntent.RECOVERY) == 0
    assert state_of(sched, "r").contacted is False  # still cleared on recovery


async def test_contact_on_up_pages_only_on_recovery():
    clock = ManualClock()
    n = node("r", max_down=1)
    n.contact_on = "up"
    runner = ScriptedRunner({"r": Status.UNPINGABLE})
    sched, notifier = make([n], runner, clock)
    await tick_drain(sched)  # down -> NO down page, but contacted so recovery can fire
    assert notifier.count(PageIntent.DOWN) == 0
    assert state_of(sched, "r").contacted is True
    runner.codes["r"] = Status.OK
    clock.advance(10)
    await tick_drain(sched)  # recovers -> RECOVERY page
    assert notifier.count(PageIntent.RECOVERY) == 1
    assert state_of(sched, "r").contacted is False


async def test_contact_on_none_never_pages():
    clock = ManualClock()
    n = node("r", max_down=1)
    n.contact_on = "none"
    runner = ScriptedRunner({"r": Status.UNPINGABLE})
    sched, notifier = make([n], runner, clock)
    await tick_drain(sched)  # down -> nothing, not contacted
    assert notifier.sent == [] and state_of(sched, "r").contacted is False
    runner.codes["r"] = Status.OK
    clock.advance(10)
    await tick_drain(sched)  # recovers -> still nothing
    assert notifier.count(PageIntent.RECOVERY) == 0


async def test_contact_on_down_still_repages():
    clock = ManualClock()
    n = node("r", max_down=1)
    n.contact_on = "down"
    runner = ScriptedRunner({"r": Status.UNPINGABLE})
    sched, notifier = make([n], runner, clock)  # pageinterval 60s
    await tick_drain(sched)
    assert notifier.count(PageIntent.DOWN) == 1
    clock.advance(61)
    await tick_drain(sched)  # past the re-page interval, still down -> re-page (down is allowed)
    assert notifier.count(PageIntent.DOWN) == 2


async def test_contact_on_global_default_with_per_object_override():
    clock = ManualClock()
    glob = node("g", max_down=1)  # no per-object contact_on -> uses the global default
    over = node("o", max_down=1)
    over.contact_on = "both"  # overrides the global
    runner = ScriptedRunner({"g": Status.UNPINGABLE, "o": Status.UNPINGABLE})
    sched, notifier = make([glob, over], runner, clock, contact_on="down")  # global default down
    await tick_drain(sched)  # both page on down
    assert ("g", PageIntent.DOWN) in notifier.sent and ("o", PageIntent.DOWN) in notifier.sent
    runner.codes["g"] = Status.OK
    runner.codes["o"] = Status.OK
    clock.advance(10)
    await tick_drain(sched)  # recover: g (global down) -> no recovery; o (both) -> recovery
    assert ("g", PageIntent.RECOVERY) not in notifier.sent
    assert ("o", PageIntent.RECOVERY) in notifier.sent


# --- ack / notes (#68) ----------------------------------------------------------------

async def test_ack_suppresses_repage_but_recovery_still_pages():
    clock = ManualClock()
    runner = ScriptedRunner({"r": Status.UNPINGABLE})
    sched, notifier = make([node("r", max_down=1)], runner, clock)  # pageinterval 60s
    await tick_drain(sched)  # down -> DOWN page, contacted
    assert notifier.count(PageIntent.DOWN) == 1
    assert sched.ack("r", "ping", 0) == 1  # operator acks the outage
    assert state_of(sched, "r").acked is True
    clock.advance(61)
    await tick_drain(sched)  # past the re-page interval, still down -> SUPPRESSED by the ack
    assert notifier.count(PageIntent.DOWN) == 1
    runner.codes["r"] = Status.OK
    clock.advance(10)
    await tick_drain(sched)  # recovers -> recovery still pages; ack auto-cleared
    assert notifier.count(PageIntent.RECOVERY) == 1
    assert state_of(sched, "r").acked is False


async def test_ack_before_outage_suppresses_the_initial_down_page():
    clock = ManualClock()
    runner = ScriptedRunner({"r": Status.OK})
    sched, notifier = make([node("r", max_down=1)], runner, clock)
    await tick_drain(sched)  # up
    assert sched.ack("r", "ping", 0) == 1  # pre-ack (e.g. a maintenance window)
    runner.codes["r"] = Status.UNPINGABLE
    clock.advance(10)
    await tick_drain(sched)  # down + acked -> no down page, but contacted so recovery can fire
    assert notifier.count(PageIntent.DOWN) == 0
    st = state_of(sched, "r")
    assert st.acked is True and st.contacted is True


def test_set_note_clears_on_empty_and_reports_no_match():
    clock = ManualClock()
    sched, _ = make([node("r", max_down=1)], ScriptedRunner(), clock)
    assert sched.set_note("r", "ping", 0, "vendor ticket 4711") == 1
    assert state_of(sched, "r").note == "vendor ticket 4711"
    assert sched.set_note("r", "ping", 0, "") == 1  # empty clears
    assert state_of(sched, "r").note is None
    assert sched.ack("nope", "ping", 0) == 0  # unknown object -> no match


async def test_ack_and_note_survive_reload():
    clock = ManualClock()
    sched, _ = make([node("r", max_down=1)], ScriptedRunner({"r": Status.UNPINGABLE}), clock)
    sched.ack("r", "ping", 0)
    sched.set_note("r", "ping", 0, "known flaky")
    sched.reload([node("r", max_down=1)])  # SIGHUP-style rebuild with a fresh config object
    st = state_of(sched, "r")
    assert st.acked is True and st.note == "known flaky"


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


async def test_degraded_parent_does_not_suppress_children():
    # A loss-tolerant ping that returns DEGRADED is still reachable: a lossy router forwards, so
    # its children must keep being checked — suppressing them would mask real outages behind it.
    clock = ManualClock()
    child = node("c", CheckType.TCP)
    parent = node("p", CheckType.PING, children=[child], max_down=1)
    runner = ScriptedRunner({"p": Status.DEGRADED, "c": Status.UNPINGABLE})
    sched, _ = make([parent], runner, clock)

    await tick_drain(sched)  # parent checked -> degraded (reachable); child becomes eligible
    clock.advance(10)
    await tick_drain(sched)  # child gets checked behind the degraded-but-reachable parent

    assert runner.calls["c"] >= 1
    assert state_of(sched, "p").lastcheck == Status.DEGRADED
    assert state_of(sched, "c").suppressed is False


# --- multi-parent OR / any-path dependencies (#62) ------------------------------------

def _sched_of(sched, host):
    return next(s for s in sched._scheduled if s.node.hostname == host)


def _dag_two_parents(runner, clock):
    """c (tcp) depends on BOTH a and b (pings) — a shared child of two ping roots."""
    c = node("c", CheckType.TCP)
    a = node("a", CheckType.PING, children=[c], max_down=1)
    b = node("b", CheckType.PING, children=[c], max_down=1)
    return make([a, b], runner, clock)


def test_multi_parent_child_scheduled_exactly_once():
    sched, _ = _dag_two_parents(ScriptedRunner({}), ManualClock())
    assert sum(1 for nd, _ in sched.node_states() if nd.hostname == "c") == 1  # de-duped
    assert {s.node.hostname for s in _sched_of(sched, "c").gate} == {"a", "b"}  # both parents


async def test_multi_parent_or_one_path_up_keeps_child_checked():
    clock = ManualClock()
    runner = ScriptedRunner({"a": Status.UNPINGABLE, "b": Status.OK})  # a down, b up
    sched, _ = _dag_two_parents(runner, clock)
    for _ in range(4):
        await tick_drain(sched)
        clock.advance(10)
    assert runner.calls["c"] >= 1  # reachable via b despite a down
    assert state_of(sched, "c").suppressed is False


async def test_multi_parent_or_all_paths_down_suppresses_child():
    clock = ManualClock()
    runner = ScriptedRunner({"a": Status.UNPINGABLE, "b": Status.UNPINGABLE})
    sched, _ = _dag_two_parents(runner, clock)
    for _ in range(4):
        await tick_drain(sched)
        clock.advance(10)
    assert runner.calls["c"] == 0  # both paths down -> suppressed
    assert state_of(sched, "c").suppressed is True


async def test_multi_parent_resumes_when_either_path_recovers():
    clock = ManualClock()
    runner = ScriptedRunner({"a": Status.UNPINGABLE, "b": Status.UNPINGABLE})
    sched, _ = _dag_two_parents(runner, clock)
    for _ in range(3):
        await tick_drain(sched)
        clock.advance(10)
    assert runner.calls["c"] == 0
    runner.codes["b"] = Status.OK  # only b recovers
    for _ in range(3):
        await tick_drain(sched)
        clock.advance(10)
    assert runner.calls["c"] >= 1  # reachable via b alone


async def test_multi_parent_degraded_path_counts_as_reachable():
    clock = ManualClock()
    runner = ScriptedRunner({"a": Status.UNPINGABLE, "b": Status.DEGRADED})  # a down, b lossy
    sched, _ = _dag_two_parents(runner, clock)
    for _ in range(4):
        await tick_drain(sched)
        clock.advance(10)
    assert runner.calls["c"] >= 1  # a degraded-but-forwarding path keeps c reachable
    assert state_of(sched, "c").suppressed is False


def test_multi_parent_waits_when_only_checked_path_is_down():
    # OR with `checked` INSIDE the any(): a down+checked parent must not freeze a child whose other
    # parent is still unchecked — the child WAITS until some parent is checked-and-reachable.
    sched, _ = _dag_two_parents(ScriptedRunner({}), ManualClock())
    a_s, b_s, c_s = _sched_of(sched, "a"), _sched_of(sched, "b"), _sched_of(sched, "c")
    a_s.checked, a_s.state.lastcheck = True, Status.UNPINGABLE  # a checked + down
    b_s.checked = False                                         # b not yet checked
    assert sched._eligible(c_s) is False                       # waits, doesn't leak a probe
    b_s.checked, b_s.state.lastcheck = True, Status.OK          # b reports up
    assert sched._eligible(c_s) is True                        # now reachable via b


async def test_multi_parent_transitive_or_through_grandparents():
    clock = ManualClock()
    c = node("c", CheckType.TCP)
    a = node("a", CheckType.PING, children=[c], max_down=1)
    b = node("b", CheckType.PING, children=[c], max_down=1)
    g1 = node("g1", CheckType.PING, children=[a], max_down=1)
    g2 = node("g2", CheckType.PING, children=[b], max_down=1)
    runner = ScriptedRunner({"g1": Status.UNPINGABLE, "g2": Status.OK})  # a-path dead, b-path lives
    sched, _ = make([g1, g2], runner, clock)
    for _ in range(6):
        await tick_drain(sched)
        clock.advance(10)
    assert runner.calls["c"] >= 1  # OR composes transitively: c reachable via g2 -> b


def test_multi_parent_mixed_ping_and_non_ping_uses_the_ping_path():
    # c deps a (ping) and x (tcp). The non-ping x contributes no path, but a does -> c is scheduled
    # gated only by a, with NO spurious "behind a non-ping parent" warning.
    c = node("c", CheckType.TCP)
    a = node("a", CheckType.PING, children=[c])
    x = node("x", CheckType.TCP, children=[c])
    sched, _ = make([a, x], ScriptedRunner({}), ManualClock())
    assert sum(1 for nd, _ in sched.node_states() if nd.hostname == "c") == 1
    assert {s.node.hostname for s in _sched_of(sched, "c").gate} == {"a"}  # only the ping gates
    assert not any("non-ping parent" in w for w in sched.warnings)  # no spurious warning


def test_ping6_parent_gates_children_like_ping():
    # A ping6 parent opens a dependency gate exactly like an IPv4 ping parent (is_ping_type, not a
    # PING-only special-case): its child is gated by it, with no "non-ping parent" warning (#24).
    c = node("c", CheckType.TCP)
    a = node("a", CheckType.PING6, children=[c])
    sched, _ = make([a], ScriptedRunner({}), ManualClock())
    assert {s.node.hostname for s in _sched_of(sched, "c").gate} == {"a"}
    assert not any("non-ping parent" in w for w in sched.warnings)


def test_all_non_ping_parents_drops_with_warning():
    # c deps only x (tcp): no ping path at all -> dropped + warned (path-relative non-ping rule).
    c = node("c", CheckType.TCP)
    x = node("x", CheckType.TCP, children=[c])
    sched, _ = make([x], ScriptedRunner({}), ManualClock())
    assert all(nd.hostname != "c" for nd, _ in sched.node_states())  # c not scheduled
    assert any("non-ping parent" in w for w in sched.warnings)


def test_multi_parent_transitive_diamond_flattens_once():
    # a->b, a->c, b->d, c->d: d is reached via two intermediate ping parents. It must flatten to one
    # _Scheduled whose gate accumulates BOTH b and c (de-dup + gate merge across a diamond).
    d = node("d", CheckType.TCP)
    b = node("b", CheckType.PING, children=[d])
    c = node("c", CheckType.PING, children=[d])
    a = node("a", CheckType.PING, children=[b, c])
    sched, _ = make([a], ScriptedRunner({}), ManualClock())
    assert sum(1 for nd, _ in sched.node_states() if nd.hostname == "d") == 1  # de-duped
    assert {s.node.hostname for s in _sched_of(sched, "d").gate} == {"b", "c"}  # both parents


def test_multi_parent_open_path_not_vetoed_by_unchecked_parent():
    # Symmetric to the WAIT test: one parent checked+UP keeps the child eligible even while the
    # other parent is still unchecked — an unchecked parent neither opens a path nor VETOES one.
    sched, _ = _dag_two_parents(ScriptedRunner({}), ManualClock())
    a_s, b_s, c_s = _sched_of(sched, "a"), _sched_of(sched, "b"), _sched_of(sched, "c")
    a_s.checked, a_s.state.lastcheck = True, Status.OK  # a checked + up
    b_s.checked = False                                 # b not yet checked
    assert sched._eligible(c_s) is True  # reachable via a; an unchecked b is no veto


async def test_multi_parent_non_ping_provides_no_phantom_path():
    # c deps a (ping) and x (tcp), with the non-ping parent FIRST in the forest. When the ping path
    # a goes DOWN, c must be suppressed — the non-ping x must not provide a phantom open path (#62).
    clock = ManualClock()
    c = node("c", CheckType.TCP)
    a = node("a", CheckType.PING, children=[c], max_down=1)
    x = node("x", CheckType.TCP, children=[c])
    runner = ScriptedRunner({"a": Status.UNPINGABLE})  # the only real (ping) path is down
    sched, _ = make([x, a], runner, clock)  # non-ping parent first (behind_non_ping path)
    for _ in range(4):
        await tick_drain(sched)
        clock.advance(10)
    assert runner.calls["c"] == 0  # no phantom path via x
    assert state_of(sched, "c").suppressed is True


def test_reachable_on_cyclic_gate_terminates_and_is_correct():
    # Defence-in-depth: the parser breaks dep cycles, but if one ever reached the gate graph,
    # `_reachable` must TERMINATE and still return the true any-path result (not a wrong False).
    r = node("r", CheckType.PING)
    x = node("x", CheckType.PING)
    y = node("y", CheckType.PING)
    sched, _ = make([r, x, y], ScriptedRunner({}), ManualClock())
    r_s, x_s, y_s = _sched_of(sched, "r"), _sched_of(sched, "x"), _sched_of(sched, "y")
    for s in (r_s, x_s, y_s):
        s.checked, s.state.lastcheck = True, Status.OK  # all up + checked
    x_s.gate, y_s.gate = [y_s], [x_s]                    # a pure x<->y cycle, no exit to a root
    assert sched._reachable(x_s) is False               # unreachable -- and must not hang
    y_s.gate = [x_s, r_s]                               # give the cycle a real exit via the up root
    assert sched._reachable(x_s) is True                # live path x <- y <- r despite the cycle


def test_flatten_and_eligible_handle_a_very_deep_dep_chain():
    # `_flatten` and `_reachable` are both iterative, so a dependency chain far deeper than Python's
    # recursion limit builds and evaluates without overflowing (the old recursive walk raised
    # RecursionError around depth 1000).
    depth = 2000
    cur = node("leaf", CheckType.TCP)
    for i in range(depth):
        cur = node(f"p{i}", CheckType.PING, children=[cur])  # each node parents the previous one
    sched, _ = make([cur], ScriptedRunner({}), ManualClock())  # cur is the chain root
    assert sum(1 for _ in sched.node_states()) == depth + 1  # whole chain built, no RecursionError
    assert sched._eligible(_sched_of(sched, "leaf")) is False  # nothing checked yet -> waits


def test_reload_keeps_live_config_when_flatten_fails():
    # reload() builds the new set BEFORE retiring the old, so a failing _flatten leaves the running
    # config fully intact — no half-mutation that would silently stop monitoring.
    sched, _ = make([node("p", CheckType.PING)], ScriptedRunner({}), ManualClock())
    old_scheduled = sched._scheduled

    def boom(_roots):
        raise RuntimeError("flatten failed")

    sched._flatten = boom
    raised = False
    try:
        sched.reload([node("q", CheckType.PING)])
    except RuntimeError:
        raised = True
    assert raised
    assert sched._scheduled is old_scheduled       # the live set is unchanged
    assert all(s.alive for s in sched._scheduled)  # old objects were NOT retired into a blind spot


def test_down_parents_reports_a_down_parent_of_a_reachable_child():
    # A multi-parent child up via one path, with the other parent down, is "partially degraded":
    # still reachable (#62), but node_states() reports the down parent (#81).
    sched, _ = _dag_two_parents(ScriptedRunner({}), ManualClock())
    a_s, b_s, c_s = _sched_of(sched, "a"), _sched_of(sched, "b"), _sched_of(sched, "c")
    a_s.checked, a_s.state.lastcheck = True, Status.UNPINGABLE  # a down
    b_s.checked, b_s.state.lastcheck = True, Status.OK          # b up
    states = {nd.hostname: st for nd, st in sched.node_states()}
    assert states["c"].down_parents == ["a"]  # the one down parent is reported
    assert sched._eligible(c_s) is True        # c is still reachable via b
    assert states["a"].down_parents == []      # a root has no parents


def test_down_parents_excludes_up_and_unchecked_parents():
    sched, _ = _dag_two_parents(ScriptedRunner({}), ManualClock())
    a_s, b_s = _sched_of(sched, "a"), _sched_of(sched, "b")
    a_s.checked, a_s.state.lastcheck = True, Status.OK
    b_s.checked, b_s.state.lastcheck = True, Status.OK
    assert {nd.hostname: st for nd, st in sched.node_states()}["c"].down_parents == []  # both up
    a_s.checked = False  # an UNCHECKED parent is unknown, not "down"
    assert {nd.hostname: st for nd, st in sched.node_states()}["c"].down_parents == []


def test_down_parents_is_not_persisted():
    # down_parents is derived/display-only and must never reach the savestate carry.
    sched, _ = _dag_two_parents(ScriptedRunner({}), ManualClock())
    a_s = _sched_of(sched, "a")
    a_s.checked, a_s.state.lastcheck = True, Status.UNPINGABLE
    sched.node_states()  # populate the field
    assert all("down_parents" not in rec for rec in sched.export_state())


async def test_degraded_does_not_page_by_default_through_scheduler():
    clock = ManualClock()
    runner = ScriptedRunner({"r": Status.DEGRADED})
    sched, notifier = make([node("r", max_down=1)], runner, clock)  # page_on_degraded default off
    await tick_drain(sched)
    assert notifier.count(PageIntent.DOWN) == 0  # informational by default — no page
    assert state_of(sched, "r").lastcheck == Status.DEGRADED


async def test_page_on_degraded_setting_escalates_through_scheduler():
    clock = ManualClock()
    runner = ScriptedRunner({"r": Status.DEGRADED})
    sched, notifier = make([node("r", max_down=1)], runner, clock, page_on_degraded=True)
    await tick_drain(sched)  # the setting routes DEGRADED through normal escalation -> page
    assert notifier.count(PageIntent.DOWN) == 1


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


def test_nonpositive_interval_is_floored():
    # A non-positive check interval is floored to a positive minimum: a 0 interval would re-push
    # a suppressed node at `now` and spin tick() forever (the heap loop never awaits). Guarding
    # the floor here keeps that re-push strictly in the future.
    sched, _ = make([node("p", CheckType.PING)], ScriptedRunner(), ManualClock(), interval_s=0)
    assert sched._scheduled[0].interval > 0


async def test_inflight_node_excluded_from_next_delay():
    # A dispatched (in-flight) node leaves the scheduling heap, so it can't peg _next_delay to 0
    # and busy-spin run() while a slow check runs; only waiting nodes count toward the next wake.
    # Once it completes and is re-queued overdue, _next_delay drops to 0 so it dispatches promptly.
    clock = ManualClock()
    gate = asyncio.Event()

    class Hang(ScriptedRunner):
        async def __call__(self, node, ctx):
            self.calls[node.hostname] += 1
            await gate.wait()
            return Status.OK

    sched, _ = make([node("s", CheckType.TCP)], Hang(), clock, interval_s=10.0)
    await sched.tick()  # dispatch "s"; now in flight and off the heap, blocked on the gate
    clock.advance(50)
    assert sched._next_delay() > 0.0  # nothing waiting -> bounded idle poll, not a 0-spin

    gate.set()
    await sched.drain()  # "s" completes, re-queued at next_due=10 (overdue now at t=50)
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


# --- concurrency cap (max_concurrency) ------------------------------------------------


class _ConcurrencyRunner(ScriptedRunner):
    """Tracks how many checks are inside the runner at once; blocks until released."""

    def __init__(self):
        super().__init__()
        self.current = 0
        self.peak = 0
        self.release = asyncio.Event()

    async def __call__(self, node, ctx):
        self.calls[node.hostname] += 1
        self.current += 1
        self.peak = max(self.peak, self.current)
        await self.release.wait()
        self.current -= 1
        return Status.OK


async def test_semaphore_bounds_concurrent_checks():
    # max_concurrency caps how many non-ping checks run at once. With cap=2 and 4 eligible
    # nodes, never more than 2 are inside the check simultaneously (regression guard: deleting
    # the `async with self._sem` would let all 4 in).
    clock = ManualClock()
    runner = _ConcurrencyRunner()
    nodes = [node(h, CheckType.TCP) for h in ("a", "b", "c", "d")]
    sched, _ = make(nodes, runner, clock, max_concurrency=2)

    await sched.tick()         # all 4 due + eligible -> dispatched
    await asyncio.sleep(0.02)  # the 2 the semaphore admits enter the check; the others block
    assert runner.current == 2 and runner.peak == 2

    runner.release.set()
    await sched.drain()
    assert runner.peak == 2                      # never exceeded the cap
    assert sum(runner.calls.values()) == 4       # all four ran, eventually


async def test_ping_bypasses_concurrency_cap():
    # PING shares one raw socket and is NOT bounded by max_concurrency: all pings run at once
    # even under cap=1 (regression guard: routing ping through the semaphore would serialize it).
    clock = ManualClock()
    runner = _ConcurrencyRunner()
    nodes = [node(h, CheckType.PING) for h in ("p1", "p2", "p3", "p4")]
    sched, _ = make(nodes, runner, clock, max_concurrency=1)

    await sched.tick()
    await asyncio.sleep(0.02)
    assert runner.current == 4 and runner.peak == 4  # unbounded despite cap=1

    runner.release.set()
    await sched.drain()


# --- #70: per-object / per-group source threaded into non-ping checks ------------------

class _CtxRecorder:
    """Records the ctx.source_ip each check received, keyed by hostname."""

    def __init__(self):
        self.seen: dict[str, str | None] = {}

    async def __call__(self, node, ctx):
        self.seen[node.hostname] = ctx.source_ip
        return Status.OK


def test_effective_source_resolution():
    # Unit-test the resolver across the matrix (ping defaults unbound; others -> global source_ip;
    # auto -> unbound; an explicit IP binds either family).
    clock = ManualClock()
    sched, _ = make([node("p", CheckType.PING)], ScriptedRunner(), clock, source_ip="192.0.2.1")
    es = sched._effective_source

    def n(ctype, source=None):
        return Node(hostname="h", check_type=ctype, source=source)

    assert es(n(CheckType.PING)) is None                          # ping unset -> unbound
    assert es(n(CheckType.PING, SOURCE_AUTO)) is None             # ping auto -> unbound
    assert es(n(CheckType.PING, "203.0.113.5")) == "203.0.113.5"  # ping explicit IP -> bind
    assert es(n(CheckType.TCP)) == "192.0.2.1"                    # others -> global source_ip
    assert es(n(CheckType.TCP, SOURCE_AUTO)) is None              # auto opts out of the global
    assert es(n(CheckType.TCP, "203.0.113.9")) == "203.0.113.9"   # explicit IP wins


async def test_per_node_source_threaded_into_non_ping_ctx():
    clock = ManualClock()
    rec = _CtxRecorder()
    roots = [
        Node(hostname="bound", check_type=CheckType.TCP, port=80, source="203.0.113.5"),
        Node(hostname="free", check_type=CheckType.TCP, port=80, source=SOURCE_AUTO),
        Node(hostname="default", check_type=CheckType.TCP, port=80),
    ]
    sched, _ = make(roots, rec, clock, source_ip="192.0.2.1")
    await tick_drain(sched)
    assert rec.seen["bound"] == "203.0.113.5"  # per-object IP binds
    assert rec.seen["free"] is None            # auto -> unbound despite the global source_ip
    assert rec.seen["default"] == "192.0.2.1"  # inherits the global source_ip


async def test_no_global_source_leaves_non_ping_unbound():
    clock = ManualClock()
    rec = _CtxRecorder()
    sched, _ = make([Node(hostname="d", check_type=CheckType.TCP, port=80)], rec, clock)
    await tick_drain(sched)
    assert rec.seen["d"] is None  # no global source_ip set -> unbound


def test_scheduler_collects_bound_ping_sources_for_the_pool():
    # The scheduler hands the PingService the distinct BOUND ping sources to pre-open, split by
    # family: a ping6 node's IPv6 source feeds the v6 pool, not the v4 collection (#70/#24).
    # `auto`, unset, and non-ping nodes contribute none.
    clock = ManualClock()
    roots = [
        Node(hostname="a", check_type=CheckType.PING, source="203.0.113.5"),
        Node(hostname="b", check_type=CheckType.PING, source=SOURCE_AUTO),
        Node(hostname="c", check_type=CheckType.PING),
        Node(hostname="d", check_type=CheckType.TCP, port=80, source="198.51.100.9"),
        Node(hostname="e", check_type=CheckType.PING6, source="2001:db8::5"),
    ]
    sched, _ = make(roots, ScriptedRunner(), clock, source_ip="192.0.2.1")
    assert sched.ping_service._v4.configured == frozenset({"203.0.113.5"})
    assert sched.ping_service._v6.configured == frozenset({"2001:db8::5"})
    assert sched.ping_service._v6.enabled is True  # a ping6 node enables the v6 pool
