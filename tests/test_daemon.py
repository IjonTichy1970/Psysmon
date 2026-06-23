"""Tests for daemon orchestration: config build, SIGHUP reload, and the serve loop."""

from __future__ import annotations

import asyncio
from pathlib import Path

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
