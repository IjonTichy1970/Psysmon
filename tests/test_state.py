"""Tests for the per-node up/down state machine."""

from __future__ import annotations

import pytest

from sysmon.config.model import NodeState
from sysmon.engine.state import PageIntent, apply_result, maybe_repage
from sysmon.status import Status

PING_DOWN = int(Status.UNPINGABLE)  # 6
CONN_REF = int(Status.CONN_REFUSED)  # 1


def st(**kw) -> NodeState:
    s = NodeState()
    for k, v in kw.items():
        setattr(s, k, v)
    return s


# --- core transitions -----------------------------------------------------------------

def test_first_failure_below_threshold_no_page():
    s = st(max_down=3, lastcheck=Status.OK, downct=0)
    t = apply_result(s, PING_DOWN, now_wall=100.0)
    assert (s.lastcheck, s.downct) == (PING_DOWN, 1)
    assert s.deathtime == 100.0
    assert t.intent is PageIntent.NONE
    assert t.state_changed


def test_reaching_threshold_emits_down():
    s = st(max_down=2, lastcheck=PING_DOWN, downct=1, contacted=False)
    t = apply_result(s, PING_DOWN, now_wall=100.0)
    assert s.downct == 2
    assert t.intent is PageIntent.DOWN


def test_down_does_not_set_contacted():
    # The notifier owns `contacted`; the state machine must not set it.
    s = st(max_down=1, lastcheck=Status.OK, downct=0, contacted=False)
    apply_result(s, PING_DOWN, now_wall=1.0)
    assert s.contacted is False


def test_already_contacted_no_repeat_down():
    s = st(max_down=2, lastcheck=PING_DOWN, downct=5, contacted=True)
    t = apply_result(s, PING_DOWN, now_wall=100.0)
    assert s.downct == 6
    assert t.intent is PageIntent.NONE


def test_recovery_after_paged():
    s = st(max_down=2, lastcheck=PING_DOWN, downct=5, contacted=True, deathtime=10.0)
    t = apply_result(s, Status.OK, now_wall=200.0)
    assert s.lastcheck == Status.OK
    assert s.downct == 0
    assert s.contacted is False  # cleared by recovery branch
    assert s.last_up == 200.0
    assert t.intent is PageIntent.RECOVERY


def test_came_up_never_paged_no_recovery():
    s = st(max_down=5, lastcheck=PING_DOWN, downct=1, contacted=False)
    t = apply_result(s, Status.OK, now_wall=200.0)
    assert s.lastcheck == Status.OK
    assert s.downct == 0
    assert t.intent is PageIntent.NONE


def test_still_up_is_noop():
    s = st(lastcheck=Status.OK, downct=0)
    t = apply_result(s, Status.OK, now_wall=200.0)
    assert t.intent is PageIntent.NONE
    assert not t.state_changed


def test_error_change_resets_downct_and_deathtime():
    s = st(max_down=2, lastcheck=PING_DOWN, downct=5, contacted=True, deathtime=10.0)
    t = apply_result(s, CONN_REF, now_wall=300.0)
    assert s.downct == 1
    assert s.lastcheck == CONN_REF
    assert s.deathtime == 300.0
    # Was already contacted (max_down=2 > 1) -> no new page this tick.
    assert t.intent is PageIntent.NONE


def test_error_change_pages_when_max_down_one():
    s = st(max_down=1, lastcheck=Status.OK, downct=0, contacted=False)
    t = apply_result(s, PING_DOWN, now_wall=1.0)
    assert s.downct == 1
    assert t.intent is PageIntent.DOWN


# --- NO_DNS handling ------------------------------------------------------------------

def test_nodns_records_outage_no_page():
    s = st(lastcheck=Status.OK, downct=0)
    t = apply_result(s, Status.NO_DNS, now_wall=50.0)
    assert s.lastcheck == Status.NO_DNS
    assert s.deathtime == 50.0
    assert s.downct == 0  # untouched
    assert t.intent is PageIntent.NONE
    assert t.state_changed


def test_nodns_persisting_is_noop():
    s = st(lastcheck=Status.NO_DNS, deathtime=50.0)
    t = apply_result(s, Status.NO_DNS, now_wall=999.0)
    assert s.deathtime == 50.0  # not reset while persisting
    assert not t.state_changed


# --- re-page timer --------------------------------------------------------------------

@pytest.mark.parametrize(
    ("contacted", "lastcontacted", "now", "interval", "expected"),
    [
        (True, 0.0, 700.0, 600.0, True),    # past the interval
        (True, 0.0, 500.0, 600.0, False),   # not yet
        (False, 0.0, 700.0, 600.0, False),  # not contacted
        (True, 0.0, 700.0, 0.0, False),     # re-paging disabled
    ],
)
def test_maybe_repage(contacted, lastcontacted, now, interval, expected):
    s = st(contacted=contacted, lastcontacted=lastcontacted)
    assert maybe_repage(s, now_mono=now, pageinterval_s=interval) is expected


# --- full outage lifecycle ------------------------------------------------------------

def test_full_lifecycle():
    """up -> down x2 (page) -> still down -> recovery (page)."""
    s = st(max_down=2, lastcheck=Status.OK)
    assert apply_result(s, PING_DOWN, 1.0).intent is PageIntent.NONE  # downct 1
    assert apply_result(s, PING_DOWN, 2.0).intent is PageIntent.DOWN  # downct 2 -> page
    s.contacted = True  # notifier marks it
    assert apply_result(s, PING_DOWN, 3.0).intent is PageIntent.NONE  # still down, no repeat
    assert apply_result(s, Status.OK, 4.0).intent is PageIntent.RECOVERY
    assert s.contacted is False and s.downct == 0
