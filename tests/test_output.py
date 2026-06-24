"""Tests for the HTML/text status page and the JSON output."""

from __future__ import annotations

import json
import os
import stat
import sys
from html.parser import HTMLParser
from pathlib import Path

import pytest

from psysmon import timefmt
from psysmon.config.model import CheckType, Node, NodeState
from psysmon.config.settings import Settings
from psysmon.engine.clock import ManualClock
from psysmon.engine.scheduler import Scheduler
from psysmon.notify.base import DEFAULT_TEMPLATE, render_message
from psysmon.output.jsonout import to_json
from psysmon.output.statuspage import publish, render_and_publish, render_html, render_text
from psysmon.status import Status

NOW = 1781827570.0


def ns(host, ctype=CheckType.PING, lastcheck=Status.OK, *, port=0, downct=0, contacted=False,
       suppressed=False, deathtime=0.0, last_up=0.0, label="", contact=""):
    node = Node(hostname=host, check_type=ctype, port=port, label=label, contact=contact)
    state = NodeState(lastcheck=lastcheck, downct=downct, contacted=contacted,
                      suppressed=suppressed, deathtime=deathtime, last_up=last_up)
    return (node, state)


def html_for(states, **kw):
    opts = dict(org_hostname="mon.example.net", refresh_s=30, show_up_also=False,
                logo_url="psysmon-logo.png", now_wall=NOW)
    opts.update(kw)
    return render_html(states, **opts)


# --- HTML ------------------------------------------------------------------------------

def test_html_shows_down_hides_up_and_suppressed():
    states = [
        ns("down.net", CheckType.PING, Status.UNPINGABLE, downct=3,
           deathtime=NOW - 100, last_up=NOW - 100),
        ns("up.net", CheckType.TCP, Status.OK, port=22),
        ns("hidden.net", CheckType.TCP, Status.CONN_REFUSED, suppressed=True),
    ]
    h = html_for(states)
    assert "down.net" in h
    assert "up.net" not in h       # up hidden by default
    assert "hidden.net" not in h   # suppressed always hidden
    assert 'src="psysmon-logo.png"' in h
    assert 'http-equiv="refresh" content="30"' in h
    assert "mon.example.net" in h
    assert "Unpingable" in h
    assert "host down" in h


def test_html_show_up_also():
    h = html_for([ns("up.net", CheckType.TCP, Status.OK, port=22)], show_up_also=True)
    assert "up.net" in h


def test_html_all_operational_when_none_down():
    h = html_for([ns("up.net", CheckType.TCP, Status.OK)])
    assert "All systems operational" in h


def test_html_degraded_row_uses_its_own_badge():
    # A degraded (loss-tolerant ping, #22) node is not up, so it shows on the down-only page —
    # but with its own badge class, not the red "down" one.
    h = html_for([ns("lossy.net", CheckType.PING, Status.DEGRADED, last_up=NOW - 50)])
    assert "lossy.net" in h
    assert "badge degraded" in h
    assert ">Degraded<" in h


def test_html_escapes_hostname():
    h = html_for([ns("<script>evil", CheckType.PING, Status.UNPINGABLE, deathtime=NOW)])
    assert "<script>evil" not in h
    assert "&lt;script&gt;evil" in h


def test_html_escapes_attributes_and_title():
    """A quote in logo_url or org_hostname must not break out of its attribute / element."""
    h = html_for(
        [ns("h.net", CheckType.PING, Status.UNPINGABLE, deathtime=NOW)],
        org_hostname='org"<x>&',
        logo_url='x" onerror=alert(1) y',
    )
    # logo_url goes into src="..." — the closing quote must be escaped, no attribute breakout.
    assert 'onerror=alert(1)' not in h or '&quot; onerror' in h
    assert 'src="x&quot; onerror=alert(1) y"' in h
    # org_hostname appears in <title> and the sub-header — both escaped.
    assert 'org"<x>&' not in h
    assert "org&quot;&lt;x&gt;&amp;" in h
    parser = HTMLParser()
    parser.feed(h)  # still well-formed after the hostile input
    parser.close()


def test_html_is_well_formed():
    h = html_for([ns("a.net", CheckType.PING, Status.UNPINGABLE, deathtime=NOW, last_up=NOW)])
    parser = HTMLParser()
    parser.feed(h)  # must not raise
    parser.close()
    assert h.startswith("<!DOCTYPE html>")


# --- text ------------------------------------------------------------------------------

def test_text_lists_down_only():
    states = [ns("down.net", CheckType.PING, Status.UNPINGABLE),
              ns("up.net", CheckType.TCP, Status.OK)]
    t = render_text(states, org_hostname="o", show_up_also=False, now_wall=NOW)
    assert "down.net" in t and "up.net" not in t


def test_last_outage_never_for_node_never_up():
    """A node down at first sight (last_up == 0) shows "Never", not a span since the epoch."""
    states = [ns("new.net", CheckType.PING, Status.UNPINGABLE, deathtime=NOW, last_up=0.0)]
    t = render_text(states, org_hostname="o", show_up_also=False, now_wall=NOW)
    assert "Never" in t
    # And not the bogus ~20000-day elapsed-since-epoch value.
    assert timefmt.elapsed(0.0, NOW) not in t
    h = html_for(states)
    assert "Never" in h
    assert timefmt.elapsed(0.0, NOW) not in h


# --- atomic publish --------------------------------------------------------------------

def test_publish_writes_and_overwrites_readonly(tmp_path):
    path = str(tmp_path / "status.html")
    publish("<html>one</html>", path)
    assert Path(path).read_text() == "<html>one</html>"
    assert not list(tmp_path.glob("*.tmp"))  # temp cleaned up by rename
    # Republish: the previous file is read-only (0o444); this must still succeed.
    publish("<html>two</html>", path)
    assert Path(path).read_text() == "<html>two</html>"
    assert not list(tmp_path.glob("*.tmp"))


@pytest.mark.skipif(sys.platform == "win32", reason="POSIX mode bits not meaningful on Windows")
def test_publish_leaves_file_readonly_posix(tmp_path):
    path = str(tmp_path / "status.html")
    publish("hi", path)
    mode = stat.S_IMODE(os.stat(path).st_mode)
    assert mode == 0o444  # published file is read-only for everyone
    assert not (mode & stat.S_IWUSR)


def test_publish_cleans_up_temp_on_write_failure(tmp_path, monkeypatch):
    """A mid-write exception must not leave a stray *.tmp behind, nor clobber the target."""
    path = str(tmp_path / "status.html")
    publish("good", path)  # establish an existing (read-only) target

    import psysmon.output.statuspage as sp

    real_fdopen = os.fdopen

    def exploding_fdopen(fd, *a, **k):
        handle = real_fdopen(fd, *a, **k)
        orig_write = handle.write

        def boom(_s):
            orig_write(b"partial")  # publish() now writes bytes via the shared atomic writer
            raise OSError("disk full")

        handle.write = boom
        return handle

    monkeypatch.setattr(sp.os, "fdopen", exploding_fdopen)
    with pytest.raises(OSError):
        publish("this fails", path)
    assert not list(tmp_path.glob("*.tmp"))  # no leftover temp
    assert Path(path).read_text() == "good"  # original target untouched


def test_publish_uses_unpredictable_temp_name(tmp_path):
    """The temp file is not the predictable <path>.<pid>.tmp (closes the symlink-race, #28)."""
    path = str(tmp_path / "status.html")
    predictable = tmp_path / f"status.html.{os.getpid()}.tmp"

    seen: list[str] = []
    real_replace = os.replace

    def spy_replace(src, dst):
        seen.append(os.path.basename(src))
        return real_replace(src, dst)

    import psysmon.output.statuspage as sp

    orig = sp.os.replace
    sp.os.replace = spy_replace  # capture the temp name actually used
    try:
        publish("<html>x</html>", path)
    finally:
        sp.os.replace = orig

    assert Path(path).read_text() == "<html>x</html>"
    assert not predictable.exists()  # the old predictable name is never created
    # The temp name carries random characters between the prefix and suffix, not just the pid.
    assert seen and seen[0] != f"status.html.{os.getpid()}.tmp"
    assert seen[0].startswith("status.html.") and seen[0].endswith(".tmp")


@pytest.mark.skipif(not hasattr(os, "symlink"), reason="symlinks unsupported")
def test_publish_does_not_follow_a_preplaced_symlink(tmp_path):
    """mkstemp's O_EXCL + unpredictable name means a pre-placed symlink is never written through.

    Simulates the attack target: a sensitive file the symlink would point at. Because the temp
    name is unpredictable, publish() never opens the attacker's path at all; the sensitive file
    is left untouched and the status file is written normally.
    """
    sensitive = tmp_path / "victim"
    sensitive.write_text("SECRET")
    path = str(tmp_path / "status.html")
    # An attacker pre-creates the *old* predictable temp name as a symlink to the victim.
    attacker_link = tmp_path / f"status.html.{os.getpid()}.tmp"
    try:
        os.symlink(sensitive, attacker_link)
    except (OSError, NotImplementedError):
        pytest.skip("cannot create symlinks in this environment")

    publish("<html>status</html>", path)

    assert sensitive.read_text() == "SECRET"  # victim untouched: the link was never followed
    assert Path(path).read_text() == "<html>status</html>"


def test_render_and_publish_html(tmp_path):
    s = Settings()
    s.status_path = str(tmp_path / "s.html")
    s.status_html = True
    s.org_hostname = "org"
    states = [ns("d.net", CheckType.PING, Status.UNPINGABLE, deathtime=NOW, last_up=NOW)]
    render_and_publish(states, s, now_wall=NOW)
    out = Path(s.status_path).read_text()
    assert "<!DOCTYPE html>" in out and "d.net" in out


def test_render_and_publish_text(tmp_path):
    s = Settings()
    s.status_path = str(tmp_path / "s.txt")
    s.status_html = False
    states = [ns("d.net", CheckType.PING, Status.UNPINGABLE, deathtime=NOW, last_up=NOW)]
    render_and_publish(states, s, now_wall=NOW)
    out = Path(s.status_path).read_text()
    assert "d.net" in out and "<html" not in out.lower()


def test_render_and_publish_noop_without_path():
    render_and_publish([], Settings())  # status_path is None -> no file, no error


# --- logo auto-deploy (#58) ------------------------------------------------------------

_PNG_MAGIC = b"\x89PNG\r\n\x1a\n"


def _bundled_logo() -> bytes:
    from importlib import resources

    return resources.files("psysmon.assets").joinpath("psysmon-logo.png").read_bytes()


def test_bundled_logo_is_loadable():
    # The logo must ship as an importable package resource so the daemon can deploy it at runtime.
    data = _bundled_logo()
    assert data.startswith(_PNG_MAGIC) and len(data) > 1000


def test_render_and_publish_html_deploys_logo(tmp_path):
    # On HTML publish the daemon drops the logo next to the status file (the page references it by
    # a relative src), so a fresh deploy renders without the old manual copy step (#58).
    s = Settings()
    s.status_path = str(tmp_path / "s.html")
    s.status_html = True
    render_and_publish([ns("d.net", CheckType.PING, Status.UNPINGABLE, deathtime=NOW)],
                       s, now_wall=NOW)
    logo = tmp_path / "psysmon-logo.png"
    assert logo.exists()
    assert logo.read_bytes() == _bundled_logo()  # the bundled asset, verbatim


def test_render_and_publish_does_not_overwrite_existing_logo(tmp_path):
    # An operator's custom logo already in place must be preserved, never clobbered (#58).
    s = Settings()
    s.status_path = str(tmp_path / "s.html")
    s.status_html = True
    custom = tmp_path / "psysmon-logo.png"
    custom.write_bytes(b"CUSTOM-LOGO-BYTES")
    render_and_publish([ns("d.net", CheckType.PING, Status.UNPINGABLE, deathtime=NOW)],
                       s, now_wall=NOW)
    assert custom.read_bytes() == b"CUSTOM-LOGO-BYTES"


def test_render_and_publish_text_does_not_deploy_logo(tmp_path):
    # Text output doesn't reference the logo, so none should be written next to it.
    s = Settings()
    s.status_path = str(tmp_path / "s.txt")
    s.status_html = False
    render_and_publish([ns("d.net", CheckType.PING, Status.UNPINGABLE, deathtime=NOW)],
                       s, now_wall=NOW)
    assert not (tmp_path / "psysmon-logo.png").exists()


def test_logo_deploy_failure_never_blocks_publish(tmp_path, monkeypatch):
    # The logo deploy is strictly best-effort: if the bundled asset can't be loaded OR can't be
    # written, the status page must still publish (#58). Locks that contract against a future
    # narrowing of the guards in _ensure_logo. (Separate status paths per phase so we never have
    # to delete the 0o444 file Windows won't unlink.)
    import psysmon.output.statuspage as sp

    states = [ns("d.net", CheckType.PING, Status.UNPINGABLE, deathtime=NOW)]

    def settings_for(name):
        s = Settings()
        s.status_path = str(tmp_path / name)
        s.status_html = True
        return s

    # (a) bundled resource unavailable -> swallowed; status file still written.
    def boom_files(_pkg):
        raise ModuleNotFoundError("no assets")

    monkeypatch.setattr(sp.resources, "files", boom_files)
    sa = settings_for("a.html")
    render_and_publish(states, sa, now_wall=NOW)  # must not raise
    assert Path(sa.status_path).read_text().startswith("<!DOCTYPE html>")
    monkeypatch.undo()

    # (b) logo write fails while the status write succeeds -> swallowed; status file still written.
    real_atomic = sp._atomic_write

    def fail_logo_write(path, data):
        if path.endswith("psysmon-logo.png"):
            raise OSError("disk full")
        return real_atomic(path, data)

    monkeypatch.setattr(sp, "_atomic_write", fail_logo_write)
    sb = settings_for("b.html")
    render_and_publish(states, sb, now_wall=NOW)  # must not raise
    assert Path(sb.status_path).read_text().startswith("<!DOCTYPE html>")

    assert not (tmp_path / "psysmon-logo.png").exists()  # neither failure left a logo behind


# --- JSON ------------------------------------------------------------------------------

def test_json_includes_all_nodes_with_suppressed_flag():
    states = [
        ns("down.net", CheckType.PING, Status.UNPINGABLE, downct=2),
        ns("hidden.net", CheckType.TCP, Status.CONN_REFUSED, suppressed=True),
        ns("up.net", CheckType.TCP, Status.OK, port=22),
    ]
    data = json.loads(to_json(states, now_wall=NOW))
    assert data["total"] == 3
    assert data["down"] == 1  # only the visible down node counts (suppressed excluded)
    hosts = {h["hostname"]: h for h in data["hosts"]}
    assert set(hosts) == {"down.net", "hidden.net", "up.net"}
    assert hosts["hidden.net"]["suppressed"] is True  # full blast radius queryable in JSON
    assert hosts["up.net"]["up"] is True
    assert hosts["down.net"]["status_text"] == "Unpingable"


def test_json_marks_degraded_node():
    states = [
        ns("lossy.net", CheckType.PING, Status.DEGRADED),
        ns("up.net", CheckType.TCP, Status.OK, port=22),
    ]
    hosts = {h["hostname"]: h for h in json.loads(to_json(states, now_wall=NOW))["hosts"]}
    assert hosts["lossy.net"]["degraded"] is True and hosts["lossy.net"]["up"] is False
    assert hosts["lossy.net"]["status"] == int(Status.DEGRADED)
    assert hosts["lossy.net"]["status_text"] == "Degraded"
    assert hosts["up.net"]["degraded"] is False


def test_json_down_count_excludes_suppressed_and_up():
    """`down` counts only nodes that are down AND not suppressed; up + suppressed don't count."""
    states = [
        ns("d1", CheckType.PING, Status.UNPINGABLE),                 # counts
        ns("d2", CheckType.PING, Status.HOST_DOWN),                  # counts
        ns("d_supp", CheckType.PING, Status.UNPINGABLE, suppressed=True),  # excluded (suppressed)
        ns("up1", CheckType.TCP, Status.OK, port=22),               # excluded (up)
        ns("up_supp", CheckType.TCP, Status.OK, suppressed=True),   # excluded (up + suppressed)
    ]
    data = json.loads(to_json(states, now_wall=NOW))
    assert data["total"] == 5
    assert data["down"] == 2


# --- integration with the scheduler ----------------------------------------------------

def test_credentials_never_leak_into_any_output():
    # POP3 credentials live in the config (issue #2); they must never appear in the JSON, the
    # HTML/text status page, or a rendered alert message (#46). Locks down the non-leak invariant
    # against a future field-loop/template change that might start dumping them.
    secret = "s3cr3t-p@ss"
    node = Node(
        hostname="mail.example.net", check_type=CheckType.POP3, port=110,
        username="systest", password=secret, label="pop3", contact="noc@example.net",
    )
    state = NodeState(lastcheck=Status.BAD_AUTH, downct=3, deathtime=NOW, last_up=NOW - 50)
    states = [(node, state)]

    outputs = [
        to_json(states, now_wall=NOW),
        render_html(states, org_hostname="o", refresh_s=30, show_up_also=True,
                    logo_url="logo.png", now_wall=NOW),
        render_text(states, org_hostname="o", show_up_also=True, now_wall=NOW),
        render_message(DEFAULT_TEMPLATE, node, state, myname="mon", now_wall=NOW),
    ]
    for out in outputs:
        assert secret not in out


async def test_scheduler_states_render(tmp_path):
    clock = ManualClock()

    async def runner(node, ctx):
        return Status.UNPINGABLE if node.hostname == "rtr" else Status.OK

    s = Settings()
    s.interval_s = 10
    s.status_path = str(tmp_path / "out.html")
    s.org_hostname = "mon.example.net"
    node = Node(hostname="rtr", check_type=CheckType.PING, max_down=1)
    sched = Scheduler([node], s, clock=clock, runner=runner, stagger=False)
    await sched.tick()
    await sched.drain()
    render_and_publish(sched.node_states(), s, now_wall=NOW)
    assert "rtr" in Path(s.status_path).read_text()


# --- timefmt ---------------------------------------------------------------------------

def test_timefmt_never_when_zero():
    assert timefmt.clock_time(0, never_if_zero=True) == "Never"
    # Without the flag, zero is a real (epoch) timestamp, not "Never".
    assert timefmt.clock_time(0) != "Never"


def test_timefmt_duration_clamps_negative():
    assert timefmt.duration(-1) == "00:00:00"
    assert timefmt.duration(-999999) == "00:00:00"


def test_timefmt_elapsed_clamps_when_now_before_since():
    # Clock skew: now earlier than since -> 0, never a negative/huge span.
    assert timefmt.elapsed(2000.0, 1000.0) == "00:00:00"


def test_timefmt_duration_shape_and_large():
    assert timefmt.duration(0) == "00:00:00"
    assert timefmt.duration(86400 + 3600 + 60) == "01:01:01"
    # >99-day spans widen the day field rather than truncating.
    assert timefmt.duration(100 * 86400) == "100:00:00"
