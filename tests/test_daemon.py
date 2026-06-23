"""Tests for daemon orchestration: config build, SIGHUP reload, and the serve loop."""

from __future__ import annotations

import asyncio
import logging
import logging.handlers
from pathlib import Path

from psysmon import daemon
from psysmon.config.model import CheckType, Node
from psysmon.config.settings import Settings
from psysmon.daemon import build, load_roots, main, serve
from psysmon.engine.clock import ManualClock, SystemClock
from psysmon.engine.scheduler import Scheduler
from psysmon.status import Status

SAMPLE = (
    "config statusfile html /var/www/psysmon/status.html\n"
    "config numfailures 4\n"
    "rtr.example.net ping rtr.example.net noc@example.net {\n"
    "   rtr.example.net tcp 22 ssh noc@example.net\n"
    "}\n"
)


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


def test_reload_warns_on_duplicate_keys():
    sched = Scheduler([Node("p", CheckType.PING)], Settings(), clock=ManualClock(), stagger=False)
    # Two stanzas collapsing to the same (hostname, type, port) key.
    sched.reload([Node("dup", CheckType.PING), Node("dup", CheckType.PING)])
    assert len(sched.node_states()) == 2  # both still scheduled (no silent drop)
    assert any("duplicate node" in w for w in sched.warnings)


def test_main_missing_config_returns_clean_error(capsys):
    rc = main(["-f", "/no/such/psysmon.conf", "-d"])
    assert rc == 1  # not a traceback
    err = capsys.readouterr().err
    assert "config file not found" in err


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
