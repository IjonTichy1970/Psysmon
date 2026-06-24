"""Tests for daemon orchestration: config build, SIGHUP reload, and the serve loop."""

from __future__ import annotations

import asyncio
import logging
import logging.handlers
import time
from pathlib import Path

from psysmon import daemon
from psysmon.config.model import CheckType, Node, NodeState
from psysmon.config.settings import Settings
from psysmon.daemon import build, load_roots, main, serve
from psysmon.engine.clock import ManualClock, SystemClock
from psysmon.engine.scheduler import Scheduler
from psysmon.engine.statestore import StateStore
from psysmon.status import Status

SAMPLE = (
    "config statusfile html /var/www/psysmon/status.html\n"
    "config numfailures 4\n"
    "rtr.example.net ping rtr.example.net noc@example.net {\n"
    "   rtr.example.net tcp 22 ssh noc@example.net\n"
    "}\n"
)


class _FakeSched:
    """Minimal scheduler stand-in for the periodic logging helpers (#59)."""

    def __init__(self, states=None, stats=None):
        self._states = states or []
        self._stats = stats

    def node_states(self):
        return self._states

    def dns_stats(self):
        return self._stats


def test_log_dns_stats_line(caplog):
    sched = _FakeSched(stats={"hits": 10, "misses": 3, "expired": 2, "entries": 5})
    with caplog.at_level(logging.INFO, logger="psysmon"):
        daemon._log_dns_stats(sched)
    assert "dnscache periodic - 10 hits 3 misses 2 expired" in caplog.text


def test_log_dns_stats_skips_when_no_stats(caplog):
    with caplog.at_level(logging.INFO, logger="psysmon"):
        daemon._log_dns_stats(_FakeSched(stats=None))
    assert "dnscache" not in caplog.text


def test_log_heartbeat_counts(caplog):
    def st(lastcheck, suppressed=False):
        return NodeState(lastcheck=lastcheck, suppressed=suppressed)

    states = [
        (Node(hostname="a", check_type=CheckType.PING), st(Status.OK)),                 # up
        (Node(hostname="b", check_type=CheckType.PING), st(Status.UNPINGABLE)),         # down
        (Node(hostname="c", check_type=CheckType.TCP), st(Status.CONN_REFUSED, True)),  # suppressed
        (Node(hostname="d", check_type=CheckType.TCP), st(Status.OK, True)),            # suppressed
    ]
    with caplog.at_level(logging.INFO, logger="psysmon"):
        daemon._log_heartbeat(_FakeSched(states))
    assert "monitoring 4 hosts - 1 up, 1 down, 2 suppressed" in caplog.text


async def test_periodic_disabled_when_interval_zero():
    calls = []
    await daemon._periodic(0, lambda: calls.append(1))
    assert calls == []  # non-positive interval returns immediately, never calls fn


async def test_periodic_survives_fn_exception():
    # A raising fn must not kill the loop, so one bad stats call doesn't stop heartbeats forever.
    calls = []

    def fn():
        calls.append(1)
        if len(calls) == 1:
            raise RuntimeError("boom")

    task = asyncio.create_task(daemon._periodic(0.001, fn))
    try:
        await asyncio.sleep(0.05)
    finally:
        task.cancel()
        await asyncio.gather(task, return_exceptions=True)
    assert len(calls) >= 2  # looped past the first-call exception


def test_apply_log_level_sets_root_level():
    root = logging.getLogger()
    saved = root.level
    try:
        for level, expected in (("warning", logging.WARNING), ("info", logging.INFO),
                                ("debug", logging.DEBUG)):
            s = Settings()
            s.log_level = level
            daemon._apply_log_level(s)
            assert root.level == expected
    finally:
        root.setLevel(saved)


def test_heartbeat_counts_never_checked_as_up(caplog):
    # A never-checked node (default NodeState, lastcheck == 0) counts as up, matching is_up.
    states = [(Node(hostname="new", check_type=CheckType.PING), NodeState())]
    with caplog.at_level(logging.INFO, logger="psysmon"):
        daemon._log_heartbeat(_FakeSched(states))
    assert "monitoring 1 hosts - 1 up, 0 down, 0 suppressed" in caplog.text


def test_load_roots(tmp_path):
    cfg = tmp_path / "psysmon.conf"
    cfg.write_text(SAMPLE, encoding="utf-8")
    s = Settings()
    s.config_path = str(cfg)
    roots, overrides, warnings = load_roots(s)
    assert [r.hostname for r in roots] == ["rtr.example.net"]
    assert roots[0].children[0].check_type is CheckType.TCP
    assert overrides["status_path"] == "/var/www/psysmon/status.html"
    assert warnings == []


def test_build_merges_cli_over_file_over_defaults(tmp_path):
    cfg = tmp_path / "psysmon.conf"
    cfg.write_text(SAMPLE, encoding="utf-8")
    sched, settings = build(["-f", str(cfg), "--interval", "5", "--no-notify"])

    assert len(sched.node_states()) == 2  # ping + its tcp child
    assert settings.status_html is True and settings.status_path == "/var/www/psysmon/status.html"
    assert settings.numfailures == 4  # from the config file
    assert settings.interval_s == 5.0  # CLI overrides
    assert settings.notify_enabled is False  # CLI flag
    # the position-dependent numfailures reached the nodes
    assert all(st.max_down == 4 for _, st in sched.node_states())


def test_reload_preserves_live_state():
    child = Node("c", CheckType.TCP, port=22)
    parent = Node("p", CheckType.PING, children=[child])
    sched = Scheduler([parent], Settings(), clock=ManualClock(), stagger=False)

    pstate = next(st for nd, st in sched.node_states() if nd.hostname == "p")
    pstate.lastcheck = Status.UNPINGABLE
    pstate.downct = 5
    pstate.contacted = True
    pstate.deathtime = 123.0

    # New config: p stays, its child c is gone, a new host q appears.
    sched.reload([Node("p", CheckType.PING), Node("q", CheckType.PING)])

    states = {nd.hostname: st for nd, st in sched.node_states()}
    assert set(states) == {"p", "q"}  # c removed, q added
    assert states["p"].lastcheck == Status.UNPINGABLE  # live state carried over
    assert states["p"].downct == 5 and states["p"].contacted is True
    assert states["p"].deathtime == 123.0
    assert states["q"].lastcheck == Status.OK and states["q"].contacted is False  # fresh


async def test_serve_renders_status_and_stops(tmp_path):
    settings = Settings()
    settings.status_path = str(tmp_path / "status.html")
    settings.interval_s = 10.0

    async def runner(node, ctx):
        return Status.UNPINGABLE if node.hostname == "rtr" else Status.OK

    node = Node("rtr", CheckType.PING, max_down=1)
    sched = Scheduler([node], settings, clock=SystemClock(), runner=runner, stagger=False)

    task = asyncio.create_task(serve(sched, settings))
    await asyncio.sleep(0.1)  # let it tick (down) and render
    sched.stop()
    await asyncio.wait_for(task, timeout=2.0)  # serve drains + does a final render

    out = Path(settings.status_path).read_text()
    assert "rtr" in out and "Unpingable" in out


def test_reload_carries_checked_flag_so_children_stay_gated():
    # A carried-over parent ping keeps gating its children: after reload it stays
    # ``checked`` + up, so its child remains eligible without re-probing the parent first.
    child = Node("c", CheckType.TCP, port=22)
    parent = Node("p", CheckType.PING, children=[child])
    sched = Scheduler([parent], Settings(), clock=ManualClock(), stagger=False)

    psched = next(s for s in sched._scheduled if s.node.hostname == "p")
    psched.checked = True
    psched.state.lastcheck = Status.OK
    cbefore = next(s for s in sched._scheduled if s.node.hostname == "c")
    assert sched._eligible(cbefore) is True

    sched.reload([Node("p", CheckType.PING, children=[Node("c", CheckType.TCP, port=22)])])

    pafter = next(s for s in sched._scheduled if s.node.hostname == "p")
    cafter = next(s for s in sched._scheduled if s.node.hostname == "c")
    assert pafter.checked is True  # the checked flag was carried over
    assert sched._eligible(cafter) is True  # so the child is still gated-open, not re-probed

    # A *fresh* parent (no carry) has not been checked yet -> its child is gated off.
    fresh = Scheduler(
        [Node("p2", CheckType.PING, children=[Node("c2", CheckType.TCP, port=22)])],
        Settings(), clock=ManualClock(), stagger=False,
    )
    c2 = next(s for s in fresh._scheduled if s.node.hostname == "c2")
    assert fresh._eligible(c2) is False


def test_reload_duplicate_keys_carry_state_to_both():
    # Two stanzas collapsing to the same (hostname,type,port) key must both be scheduled (no
    # silent drop), warn, AND both receive the carried-over live state the warning promises
    # (#48). Seed a pre-existing 'dup' with distinctive state so the carry-over branch runs.
    sched = Scheduler([Node("dup", CheckType.PING)], Settings(), clock=ManualClock(), stagger=False)
    st = next(s for nd, s in sched.node_states() if nd.hostname == "dup")
    st.lastcheck = Status.UNPINGABLE
    st.downct = 4
    st.contacted = True
    st.deathtime = 99.0

    sched.reload([Node("dup", CheckType.PING), Node("dup", CheckType.PING)])

    states = [s for nd, s in sched.node_states() if nd.hostname == "dup"]
    assert len(states) == 2  # both still scheduled (no silent drop)
    for s in states:  # the carried state reached BOTH duplicates, not just one
        assert s.lastcheck == Status.UNPINGABLE and s.downct == 4
        assert s.contacted is True and s.deathtime == 99.0
    assert any("duplicate node" in w for w in sched.warnings)


async def test_reload_loop_applies_a_good_config(tmp_path):
    # End-to-end SIGHUP path: _reload_loop waits on the flag, re-reads + reparses the file, and
    # calls scheduler.reload, carrying live state for surviving nodes (#45) — not just a direct
    # scheduler.reload() call.
    cfg = tmp_path / "psysmon.conf"
    cfg.write_text("p ping p noc@x\n", encoding="utf-8")
    settings = Settings()
    settings.config_path = str(cfg)
    sched = Scheduler([Node("p", CheckType.PING)], settings, clock=ManualClock(), stagger=False)
    pstate = next(s for nd, s in sched.node_states() if nd.hostname == "p")
    pstate.downct = 7
    pstate.lastcheck = Status.UNPINGABLE

    flag = asyncio.Event()
    task = asyncio.create_task(daemon._reload_loop(sched, settings, flag))
    try:
        cfg.write_text("p ping p noc@x\nq ping q noc@x\n", encoding="utf-8")  # add q
        flag.set()
        await asyncio.sleep(0.05)
        states = {nd.hostname: s for nd, s in sched.node_states()}
        assert set(states) == {"p", "q"}                  # reloaded: q added, c-less p survives
        assert states["p"].downct == 7                    # live state carried for surviving p
        assert states["p"].lastcheck == Status.UNPINGABLE
    finally:
        task.cancel()
        await asyncio.gather(task, return_exceptions=True)


async def test_reload_loop_keeps_old_config_on_parse_failure(tmp_path):
    # If the new config fails to load, _reload_loop logs and KEEPS the running config (#45).
    cfg = tmp_path / "psysmon.conf"
    cfg.write_text("p ping p noc@x\n", encoding="utf-8")
    settings = Settings()
    settings.config_path = str(cfg)
    sched = Scheduler([Node("p", CheckType.PING)], settings, clock=ManualClock(), stagger=False)

    flag = asyncio.Event()
    task = asyncio.create_task(daemon._reload_loop(sched, settings, flag))
    try:
        cfg.write_text("hosts:\n  - a\n", encoding="utf-8")  # detected MODERN -> load_roots raises
        flag.set()
        await asyncio.sleep(0.05)
        hosts = {nd.hostname for nd, _ in sched.node_states()}
        assert hosts == {"p"}  # the failed reload left the previous config in place
    finally:
        task.cancel()
        await asyncio.gather(task, return_exceptions=True)


def test_main_missing_config_returns_clean_error(capsys):
    rc = main(["-f", "/no/such/psysmon.conf", "-d"])
    assert rc == 1  # not a traceback
    err = capsys.readouterr().err
    assert "config file not found" in err


def test_main_invalid_ping_counts_clean_error(tmp_path, capsys):
    # An invalid --send-pings/--min-pings pair is rejected at startup as a clean 'psysmon: ...'
    # error (PingService validates in build(), main() catches ValueError), not a traceback (#22).
    cfg = tmp_path / "psysmon.conf"
    cfg.write_text("p ping p noc@x\n", encoding="utf-8")
    rc = main(["-f", str(cfg), "-d", "--send-pings", "2", "--min-pings", "3"])
    assert rc == 1
    assert "psysmon:" in capsys.readouterr().err


def test_main_deeply_nested_config_is_clean_error(tmp_path, capsys):
    # A pathologically deep config is reported as a clean 'psysmon: ...' error + exit 1, not an
    # uncaught RecursionError/ParseError traceback at startup (#36).
    from psysmon.config import legacy

    depth = legacy._MAX_NESTING_DEPTH + 5
    lines = [f"p{i} ping p{i} {{" for i in range(depth)] + ["x ping x"] + ["}"] * depth
    cfg = tmp_path / "deep.conf"
    cfg.write_text("\n".join(lines) + "\n", encoding="utf-8")

    rc = main(["-f", str(cfg), "-d"])
    assert rc == 1
    assert "psysmon:" in capsys.readouterr().err


# --- logging / daemonization (issues #30, #31) ----------------------------------------


def test_setup_syslog_wires_handler_and_drops_stderr(monkeypatch):
    # syslog_facility must actually configure a SysLogHandler (issue #30); a real socket is
    # avoided by faking SysLogHandler. "none"/unknown add nothing; a valid facility adds the
    # syslog handler and drops the stderr handler (which goes to /dev/null once backgrounded).
    real_facilities = logging.handlers.SysLogHandler.facility_names
    created: list[object] = []

    class FakeSyslog(logging.Handler):
        facility_names = real_facilities

        def __init__(self, address=None, facility=None):
            super().__init__()
            self.facility = facility
            created.append(self)

        def emit(self, record):  # pragma: no cover - never actually logs in the test
            pass

    monkeypatch.setattr(logging.handlers, "SysLogHandler", FakeSyslog)

    root = logging.getLogger()
    saved = root.handlers[:]
    try:
        root.handlers = [logging.StreamHandler()]  # pretend basicConfig() installed stderr

        none_s = Settings()
        none_s.syslog_facility = "none"
        daemon._setup_syslog(none_s)
        assert created == [] and len(root.handlers) == 1  # disabled: nothing changes

        bogus_s = Settings()
        bogus_s.syslog_facility = "does-not-exist"
        daemon._setup_syslog(bogus_s)
        assert created == []  # unknown facility: warn, add nothing

        ok_s = Settings()
        ok_s.syslog_facility = "local0"
        daemon._setup_syslog(ok_s)
        assert len(created) == 1
        assert created[0].facility == real_facilities["local0"]
        assert any(isinstance(h, FakeSyslog) for h in root.handlers)
        assert not any(type(h) is logging.StreamHandler for h in root.handlers)  # stderr dropped
    finally:
        root.handlers = saved


def test_daemonize_redirects_stdio(monkeypatch):
    # After detaching, stdio must be redirected to /dev/null so backgrounded output isn't lost
    # (issue #31). Fork/setsid/open/dup2 are faked so nothing actually forks.
    calls: dict[str, object] = {"setsid": 0, "dup2": [], "closed": []}
    monkeypatch.setattr(daemon.os, "fork", lambda: 0, raising=False)  # act as the child
    monkeypatch.setattr(
        daemon.os, "setsid", lambda: calls.__setitem__("setsid", calls["setsid"] + 1),
        raising=False,
    )
    monkeypatch.setattr(daemon.os, "open", lambda path, flags: 7)  # fake /dev/null fd
    monkeypatch.setattr(daemon.os, "dup2", lambda src, dst: calls["dup2"].append((src, dst)))
    monkeypatch.setattr(daemon.os, "close", lambda fd: calls["closed"].append(fd))

    daemon._daemonize()

    assert calls["setsid"] == 1
    assert calls["dup2"] == [(7, 0), (7, 1), (7, 2)]  # stdin/stdout/stderr all redirected
    assert calls["closed"] == [7]  # the spare /dev/null fd is closed


# --- state persistence wiring (savestate, #21) ----------------------------------------


def _down_record(hostname="p"):
    return {
        "hostname": hostname, "type": "ping", "port": 0, "lastcheck": int(Status.UNPINGABLE),
        "downct": 5, "contacted": True, "lastcontacted": 0.0, "deathtime": 5.0, "last_up": 1.0,
    }


def test_restore_state_imports_from_file(tmp_path):
    settings = Settings()
    settings.state_path = str(tmp_path / "state.json")
    StateStore(settings.state_path).save([_down_record()], now_wall=time.time())

    sched = Scheduler([Node("p", CheckType.PING)], settings, clock=ManualClock(), stagger=False)
    daemon._restore_state(sched, settings)

    st = next(s for nd, s in sched.node_states() if nd.hostname == "p")
    assert st.lastcheck == int(Status.UNPINGABLE) and st.contacted is True


def test_restore_state_noop_when_disabled(tmp_path):
    settings = Settings()  # state_path is None -> persistence off, no disk touch
    sched = Scheduler([Node("p", CheckType.PING)], settings, clock=ManualClock(), stagger=False)
    daemon._restore_state(sched, settings)
    st = next(s for nd, s in sched.node_states() if nd.hostname == "p")
    assert st.lastcheck == Status.OK  # untouched, started fresh


async def test_serve_saves_state_on_stop(tmp_path):
    settings = Settings()
    settings.state_path = str(tmp_path / "state.json")
    settings.interval_s = 10.0
    settings.statesave_s = 0  # disable the periodic flush; the final flush on stop must still run

    async def runner(node, ctx):
        return Status.UNPINGABLE

    sched = Scheduler(
        [Node("p", CheckType.PING, max_down=1)],
        settings, clock=SystemClock(), runner=runner, stagger=False,
    )
    task = asyncio.create_task(serve(sched, settings))
    await asyncio.sleep(0.1)  # let it tick the node down
    sched.stop()
    await asyncio.wait_for(task, timeout=2.0)

    records = StateStore(settings.state_path).load(now_wall=time.time())
    assert any(r["hostname"] == "p" and r["lastcheck"] == int(Status.UNPINGABLE) for r in records)


def test_save_state_callback_writes_current_state(tmp_path):
    # The callback serve() schedules on the periodic timer (and the final flush) exports and
    # writes the live state, so an ungraceful exit loses at most one interval's worth.
    state_path = str(tmp_path / "state.json")
    sched = Scheduler([Node("p", CheckType.PING)], Settings(), clock=ManualClock(), stagger=False)
    st = next(s for nd, s in sched.node_states() if nd.hostname == "p")
    st.lastcheck = Status.UNPINGABLE
    st.downct = 3

    daemon._save_state(sched, StateStore(state_path))

    records = StateStore(state_path).load(now_wall=time.time())
    assert any(r["hostname"] == "p" and r["downct"] == 3 for r in records)


async def test_serve_cleans_up_helper_tasks_on_stop(tmp_path):
    # serve() must cancel + await its render/reload helpers on exit, leaving no stray tasks.
    settings = Settings()
    settings.status_path = str(tmp_path / "status.html")
    settings.interval_s = 10.0

    async def runner(node, ctx):
        return Status.OK

    sched = Scheduler(
        [Node("h", CheckType.PING, max_down=1)],
        settings, clock=SystemClock(), runner=runner, stagger=False,
    )
    before = set(asyncio.all_tasks())
    task = asyncio.create_task(serve(sched, settings))
    await asyncio.sleep(0.05)
    sched.stop()
    await asyncio.wait_for(task, timeout=2.0)

    leaked = set(asyncio.all_tasks()) - before - {asyncio.current_task()}
    assert leaked == set()  # no orphaned render/reload helper tasks
    assert Path(settings.status_path).exists()  # final render happened
