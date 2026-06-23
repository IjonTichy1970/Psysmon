"""Tests for message templating and the SMTP notifier (hermetic — no SMTP server)."""

from __future__ import annotations

from psysmon.config.model import CheckType, Node, NodeState
from psysmon.config.settings import Settings
from psysmon.engine.clock import ManualClock
from psysmon.engine.scheduler import Scheduler
from psysmon.engine.state import PageIntent
from psysmon.notify.base import render_message
from psysmon.notify.email_smtp import SmtpNotifier
from psysmon.status import Status

# A fixed epoch for deterministic timestamps: 2026-06-22 16:06:10 local.
FIXED_NOW = 1781827570.0


def settings(**kw):
    s = Settings()
    s.smtp_host, s.smtp_port = "mail.test", 2525
    s.org_hostname = "mon.example.net"
    s.notify_enabled = True
    for k, v in kw.items():
        setattr(s, k, v)
    return s


def ping_node(contact="noc@example.net"):
    return Node(hostname="rtr.example.net", check_type=CheckType.PING, contact=contact)


def tcp_node(contact="noc@example.net"):
    return Node(hostname="web.example.net", check_type=CheckType.TCP, port=443, label="https",
                contact=contact)


# --- render_message -------------------------------------------------------------------

def test_render_ping_down():
    st = NodeState(lastcheck=Status.UNPINGABLE, deathtime=FIXED_NOW - 3700)  # ~1h2m ago
    msg = render_message("%t: %h %w is %u %d", ping_node(), st, myname="mon", now_wall=FIXED_NOW)
    assert "rtr.example.net" in msg
    assert "rtr.example.net's" not in msg  # no possessive for a ping
    assert "Unpingable" in msg
    assert "00:01:01" in msg  # 1h1m downtime as DD:HH:MM
    # %w (label) is blank for a ping -> no double content from it
    assert "is Unpingable" in msg


def test_render_service_down_has_label_and_possessive():
    st = NodeState(lastcheck=Status.CONN_REFUSED, deathtime=FIXED_NOW)
    msg = render_message("%h %w is %u", tcp_node(), st, myname="mon", now_wall=FIXED_NOW)
    assert "web.example.net's https is Conn Ref" == msg


def test_render_unknown_token_passthrough():
    st = NodeState()
    assert render_message("%z%m", ping_node(), st, myname="MON", now_wall=FIXED_NOW) == "%zMON"


def test_render_template_edges():
    """Empty template, a trailing bare %, and consecutive tokens all render sanely."""
    st = NodeState()
    n = ping_node()
    assert render_message("", n, st, myname="m", now_wall=FIXED_NOW) == ""
    # A trailing % has no following char to consume, so it passes through verbatim.
    assert render_message("x%", n, st, myname="m", now_wall=FIXED_NOW) == "x%"
    # Adjacent tokens expand independently with no separator inserted.
    assert render_message("%m%m", n, st, myname="ab", now_wall=FIXED_NOW) == "abab"


def test_render_token_in_value_is_not_re_expanded():
    """A % inside an expanded value (label/hostname) is literal — no recursive injection."""
    st = NodeState()
    node = Node(hostname="h", check_type=CheckType.TCP, port=80, label="a%m b")
    # %w expands to the label verbatim; the embedded %m is NOT re-expanded to myname.
    assert render_message("%w", node, st, myname="HOST", now_wall=FIXED_NOW) == "a%m b"


def test_render_deathtime_zero_does_not_crash():
    """deathtime never set (0.0): downtime is a huge bogus span but must not raise.

    Unreachable via the real scheduler (a DOWN page always has deathtime stamped first),
    but render_message is public, so lock in the non-crash behaviour.
    """
    st = NodeState(lastcheck=Status.UNPINGABLE, deathtime=0.0)
    msg = render_message("%d", ping_node(), st, myname="m", now_wall=FIXED_NOW)
    parts = msg.split(":")
    assert len(parts) == 3  # DD:HH:MM shape preserved
    assert int(parts[0]) > 99  # days field widens past two digits rather than truncating


def test_render_downtime_over_99_days():
    """A >99-day outage widens the day field instead of overflowing/truncating."""
    st = NodeState(lastcheck=Status.UNPINGABLE, deathtime=FIXED_NOW - 100 * 86400)
    assert render_message("%d", ping_node(), st, myname="m", now_wall=FIXED_NOW) == "100:00:00"


# --- SmtpNotifier contract ------------------------------------------------------------

class Capture:
    def __init__(self):
        self.messages = []

    async def __call__(self, message):
        self.messages.append(message)


async def test_no_contact_is_handled_without_sending():
    cap = Capture()
    n = SmtpNotifier(settings(), send_fn=cap, now_wall=lambda: FIXED_NOW)
    st = NodeState(lastcheck=Status.UNPINGABLE)
    ok = await n.send(ping_node(contact=""), st, PageIntent.DOWN)
    assert ok is True  # treated as contacted so the state machine dedups
    assert cap.messages == []


async def test_notify_disabled_does_not_send_but_reports_contacted():
    cap = Capture()
    n = SmtpNotifier(settings(notify_enabled=False), send_fn=cap, now_wall=lambda: FIXED_NOW)
    ok = await n.send(ping_node(), NodeState(lastcheck=Status.UNPINGABLE), PageIntent.DOWN)
    assert ok is True
    assert cap.messages == []


async def test_down_page_built_correctly():
    cap = Capture()
    n = SmtpNotifier(settings(), send_fn=cap, now_wall=lambda: FIXED_NOW)
    st = NodeState(lastcheck=Status.UNPINGABLE, deathtime=FIXED_NOW)
    ok = await n.send(ping_node(), st, PageIntent.DOWN)
    assert ok is True
    (msg,) = cap.messages
    assert msg["To"] == "noc@example.net"
    assert msg["From"] == "psysmon@mon.example.net"
    assert msg["Subject"] == "rtr.example.net is Unpingable"
    assert "Unpingable" in msg.get_content()


async def test_recovery_subject():
    cap = Capture()
    n = SmtpNotifier(settings(), send_fn=cap, now_wall=lambda: FIXED_NOW)
    st = NodeState(lastcheck=Status.OK, deathtime=FIXED_NOW)
    await n.send(tcp_node(), st, PageIntent.RECOVERY)
    assert cap.messages[0]["Subject"] == "web.example.net has recovered"


async def test_delivery_failure_returns_false():
    async def boom(message):
        raise OSError("smtp down")

    n = SmtpNotifier(settings(), send_fn=boom, now_wall=lambda: FIXED_NOW)
    ok = await n.send(ping_node(), NodeState(lastcheck=Status.UNPINGABLE), PageIntent.DOWN)
    assert ok is False  # so the scheduler leaves contacted False and retries


async def test_custom_mail_from():
    cap = Capture()
    n = SmtpNotifier(settings(mail_from="alerts@corp.net"), send_fn=cap, now_wall=lambda: FIXED_NOW)
    await n.send(ping_node(), NodeState(lastcheck=Status.UNPINGABLE), PageIntent.DOWN)
    assert cap.messages[0]["From"] == "alerts@corp.net"


async def test_header_injection_contact_returns_false_not_raises():
    """A CR/LF in the contact (header-injection attempt) is rejected by EmailMessage.

    The build happens inside send()'s guard, so this surfaces as a False return (treated like
    a delivery failure) rather than escaping send() and breaking the `-> bool` contract.
    """
    cap = Capture()
    n = SmtpNotifier(settings(), send_fn=cap, now_wall=lambda: FIXED_NOW)
    evil = ping_node(contact="good@x.net\nBcc: attacker@evil.net")
    ok = await n.send(evil, NodeState(lastcheck=Status.UNPINGABLE), PageIntent.DOWN)
    assert ok is False
    assert cap.messages == []  # nothing was handed to delivery


async def test_smtp_timeout_is_passed_to_smtplib(monkeypatch):
    """The real send path bounds the blocking exchange with a finite socket timeout so a hung
    SMTP server can't pin a worker thread (and the node's in_flight check) forever.
    """
    seen = {}

    class FakeSMTP:
        def __init__(self, host, port, *, timeout, source_address=None):
            seen["timeout"] = timeout

        def __enter__(self):
            return self

        def __exit__(self, *exc):
            return False

        def send_message(self, message):
            seen["sent"] = message

    import psysmon.notify.email_smtp as mod

    monkeypatch.setattr(mod.smtplib, "SMTP", FakeSMTP)
    n = SmtpNotifier(settings(), now_wall=lambda: FIXED_NOW, timeout=7.5)  # real path (no send_fn)
    ok = await n.send(ping_node(), NodeState(lastcheck=Status.UNPINGABLE), PageIntent.DOWN)
    assert ok is True
    assert seen["timeout"] == 7.5
    assert "sent" in seen


# --- end-to-end: scheduler drives the notifier ----------------------------------------

async def test_scheduler_pages_and_recovers_via_notifier():
    clock = ManualClock()
    codes = {"rtr.example.net": Status.UNPINGABLE}

    async def runner(node, ctx):
        return codes.get(node.hostname, Status.OK)

    cap = Capture()
    s = settings(interval_s=10, pageinterval_min=1, numfailures=2)
    notifier = SmtpNotifier(s, send_fn=cap, now_wall=lambda: FIXED_NOW)
    node = Node(hostname="rtr.example.net", check_type=CheckType.PING, contact="noc@x", max_down=2)
    sched = Scheduler([node], s, clock=clock, runner=runner, notifier=notifier, stagger=False)

    await _sweep(sched)  # downct 1
    clock.advance(10)
    await _sweep(sched)  # downct 2 -> DOWN page
    assert len(cap.messages) == 1
    assert cap.messages[0]["Subject"] == "rtr.example.net is Unpingable"

    codes["rtr.example.net"] = Status.OK
    clock.advance(10)
    await _sweep(sched)  # recovery page
    assert cap.messages[-1]["Subject"] == "rtr.example.net has recovered"


async def test_scheduler_repage_subject_is_down_status():
    """A re-page (still-down past pageinterval) uses intent DOWN, so its subject is the
    status line, not a recovery — and it stamps lastcontacted without re-flipping contacted.
    """
    clock = ManualClock()

    async def runner(node, ctx):
        return Status.UNPINGABLE  # never recovers

    cap = Capture()
    s = settings(interval_s=10, pageinterval_min=1, numfailures=2)  # re-page after 60s
    notifier = SmtpNotifier(s, send_fn=cap, now_wall=lambda: FIXED_NOW)
    node = Node(hostname="rtr.example.net", check_type=CheckType.PING, contact="noc@x", max_down=2)
    sched = Scheduler([node], s, clock=clock, runner=runner, notifier=notifier, stagger=False)

    await _sweep(sched)  # downct 1
    clock.advance(10)
    await _sweep(sched)  # downct 2 -> initial DOWN page
    assert len(cap.messages) == 1

    # Tick repeatedly until pageinterval (60s) elapses; no extra page should fire before then.
    for _ in range(5):
        clock.advance(10)
        await _sweep(sched)
    assert len(cap.messages) == 1  # still within the 60s window -> no re-page yet

    clock.advance(20)  # now > 60s since lastcontacted
    await _sweep(sched)
    assert len(cap.messages) == 2  # re-paged
    assert cap.messages[-1]["Subject"] == "rtr.example.net is Unpingable"  # DOWN, not recovery


async def _sweep(sched):
    await sched.tick()
    await sched.drain()
