"""Tests for cross-restart state persistence (savestate, #21).

Covers the three layers: the :class:`StateStore` file (round-trip, atomic write, and every
invalid/stale degrade-to-fresh path), the scheduler's ``export_state``/``import_state`` merge
(by ``(hostname, type, port)``, dropping unknown nodes, rebasing the monotonic re-page timer),
and the headline behavior — a node that was DOWN-and-paged before a restart does not re-page on
the first post-restart sweep.
"""

from __future__ import annotations

import json
import logging

from psysmon.config.model import CheckType, Node
from psysmon.config.settings import Settings
from psysmon.engine.clock import ManualClock
from psysmon.engine.scheduler import Scheduler
from psysmon.engine.state import PageIntent
from psysmon.engine.statestore import SCHEMA_VERSION, StateStore
from psysmon.status import Status

RECORD = {
    "hostname": "p", "type": "ping", "port": 0, "lastcheck": int(Status.UNPINGABLE),
    "downct": 5, "contacted": True, "lastcontacted": 0.0, "deathtime": 50.0, "last_up": 10.0,
    "acked": False, "note": None,  # carried since schema v2 (#68)
}


def _scheduler(roots, **kw):
    return Scheduler(roots, Settings(), stagger=False, **kw)


# --- StateStore: round trip + atomic write --------------------------------------------

def test_save_load_round_trip(tmp_path):
    store = StateStore(str(tmp_path / "state.json"))
    store.save([RECORD], now_wall=1000.0)
    assert store.load(now_wall=1000.0) == [RECORD]


def test_save_leaves_no_temp_file(tmp_path):
    store = StateStore(str(tmp_path / "state.json"))
    store.save([RECORD], now_wall=1.0)
    # the temp file is renamed into place, never left behind
    assert [p.name for p in tmp_path.iterdir()] == ["state.json"]


def test_save_overwrites_existing(tmp_path):
    # A periodic flush rewrites the file in place (exercises os.replace over an existing target,
    # which on Windows must not trip over a read-only bit — the state file is 0o600, writable).
    store = StateStore(str(tmp_path / "state.json"))
    store.save([{"hostname": "a"}], now_wall=1.0)
    store.save([{"hostname": "b"}], now_wall=2.0)
    assert store.load(now_wall=2.0) == [{"hostname": "b"}]


# --- StateStore: every invalid/stale path degrades to a fresh start --------------------

def test_load_missing_file_is_empty(tmp_path):
    assert StateStore(str(tmp_path / "nope.json")).load(now_wall=1.0) == []


def test_load_malformed_json_is_empty(tmp_path, caplog):
    (tmp_path / "state.json").write_text("{not json", encoding="utf-8")
    with caplog.at_level(logging.WARNING, logger="psysmon.statestore"):
        assert StateStore(str(tmp_path / "state.json")).load(now_wall=1.0) == []
    assert "not valid JSON" in caplog.text


def test_load_non_dict_payload_is_empty(tmp_path):
    (tmp_path / "state.json").write_text("[1, 2, 3]", encoding="utf-8")
    assert StateStore(str(tmp_path / "state.json")).load(now_wall=1.0) == []


def test_load_wrong_schema_version_ignored(tmp_path, caplog):
    payload = {"schema_version": SCHEMA_VERSION + 999, "saved_at": 1.0, "nodes": [RECORD]}
    (tmp_path / "state.json").write_text(json.dumps(payload), encoding="utf-8")
    with caplog.at_level(logging.WARNING, logger="psysmon.statestore"):
        assert StateStore(str(tmp_path / "state.json")).load(now_wall=1.0) == []
    assert "schema_version" in caplog.text


def test_load_nodes_not_a_list_is_empty(tmp_path):
    payload = {"schema_version": SCHEMA_VERSION, "saved_at": 1.0, "nodes": "oops"}
    (tmp_path / "state.json").write_text(json.dumps(payload), encoding="utf-8")
    assert StateStore(str(tmp_path / "state.json")).load(now_wall=2.0) == []


def test_load_non_dict_node_entries_rejected(tmp_path, caplog):
    # A schema-valid file whose node list holds non-records (e.g. [1,2,3]) must be rejected at
    # load, not crash the consumer with record.get(...) on an int.
    payload = {"schema_version": SCHEMA_VERSION, "saved_at": 1.0, "nodes": [1, 2, 3]}
    (tmp_path / "state.json").write_text(json.dumps(payload), encoding="utf-8")
    with caplog.at_level(logging.WARNING, logger="psysmon.statestore"):
        assert StateStore(str(tmp_path / "state.json")).load(now_wall=2.0) == []
    assert "malformed node entries" in caplog.text


def test_load_empty_file_is_empty(tmp_path):
    (tmp_path / "state.json").write_text("", encoding="utf-8")  # json.loads("") raises -> fresh
    assert StateStore(str(tmp_path / "state.json")).load(now_wall=1.0) == []


def test_load_oversize_file_rejected(tmp_path, monkeypatch, caplog):
    from psysmon.engine import statestore as ss

    monkeypatch.setattr(ss, "_MAX_FILE_BYTES", 5)  # tiny cap; a normal file blows past it
    store = ss.StateStore(str(tmp_path / "state.json"))
    store.save([RECORD], now_wall=1.0)
    with caplog.at_level(logging.WARNING, logger="psysmon.statestore"):
        assert store.load(now_wall=1.0) == []
    assert "could not read" in caplog.text


def test_load_stale_file_ignored(tmp_path, caplog):
    store = StateStore(str(tmp_path / "state.json"), max_age_s=100)
    store.save([RECORD], now_wall=1000.0)
    with caplog.at_level(logging.WARNING, logger="psysmon.statestore"):
        assert store.load(now_wall=1000.0 + 101) == []  # 101s old > 100s max age
    assert "stale" in caplog.text


def test_load_within_max_age_is_kept(tmp_path):
    store = StateStore(str(tmp_path / "state.json"), max_age_s=100)
    store.save([RECORD], now_wall=1000.0)
    assert store.load(now_wall=1000.0 + 99) == [RECORD]  # 99s old <= 100s max age


def test_load_stale_check_disabled_when_max_age_zero(tmp_path):
    store = StateStore(str(tmp_path / "state.json"), max_age_s=0)
    store.save([RECORD], now_wall=1000.0)
    assert store.load(now_wall=1000.0 + 1_000_000) == [RECORD]  # never considered stale


# --- Scheduler export / import merge ---------------------------------------------------

def test_export_carries_key_and_state():
    sched = _scheduler([Node("p", CheckType.PING)])
    st = next(s for nd, s in sched.node_states() if nd.hostname == "p")
    st.lastcheck = Status.UNPINGABLE
    st.downct = 4
    st.contacted = True
    st.deathtime = 7.0
    st.last_up = 2.0

    [rec] = sched.export_state()
    assert (rec["hostname"], rec["type"], rec["port"]) == ("p", "ping", 0)
    assert rec["lastcheck"] == int(Status.UNPINGABLE) and rec["downct"] == 4
    assert rec["contacted"] is True and rec["deathtime"] == 7.0 and rec["last_up"] == 2.0
    assert "suppressed" not in rec and "max_down" not in rec  # config/transient fields excluded


def test_export_import_round_trip():
    src = _scheduler([Node("p", CheckType.PING), Node("c", CheckType.TCP, port=22)])
    ps = next(s for nd, s in src.node_states() if nd.hostname == "p")
    ps.lastcheck, ps.downct, ps.contacted, ps.deathtime, ps.last_up = (
        Status.UNPINGABLE, 4, True, 7.0, 2.0)

    dst = _scheduler([Node("p", CheckType.PING), Node("c", CheckType.TCP, port=22)])
    assert dst.import_state(src.export_state()) == 2

    d = {nd.hostname: s for nd, s in dst.node_states()}
    assert d["p"].lastcheck == Status.UNPINGABLE and d["p"].downct == 4
    assert d["p"].contacted is True and d["p"].deathtime == 7.0 and d["p"].last_up == 2.0


def test_export_import_carries_ack_and_note():
    # #68: acked/note are carried fields (schema v2) so they survive a restart, like 0.93.
    src = _scheduler([Node("p", CheckType.PING)])
    ps = next(s for nd, s in src.node_states() if nd.hostname == "p")
    ps.lastcheck, ps.downct, ps.contacted, ps.deathtime, ps.last_up = (
        int(Status.UNPINGABLE), 2, True, 1.0, 1.0)
    ps.acked, ps.note = True, "vendor ticket 4711"
    dst = _scheduler([Node("p", CheckType.PING)])
    assert dst.import_state(src.export_state()) == 1
    d = next(s for nd, s in dst.node_states() if nd.hostname == "p")
    assert d.acked is True and d.note == "vendor ticket 4711"


def test_import_rebases_lastcontacted_to_now():
    # lastcontacted is a MONOTONIC timestamp; the persisted value is from a dead process's clock,
    # so import must rebase it to the new clock's "now" (else the re-page timer math is garbage).
    sched = _scheduler([Node("p", CheckType.PING)], clock=ManualClock(monotonic=1000.0))
    assert sched.import_state([RECORD]) == 1
    st = next(s for nd, s in sched.node_states() if nd.hostname == "p")
    assert st.lastcontacted == 1000.0  # rebased to now, not the stale persisted 0.0
    assert st.lastcheck == int(Status.UNPINGABLE) and st.downct == 5  # other fields verbatim


def test_import_drops_unknown_and_keeps_new_fresh():
    sched = _scheduler([Node("keep", CheckType.PING), Node("fresh", CheckType.PING)])
    records = [
        {**RECORD, "hostname": "keep"},
        {**RECORD, "hostname": "gone"},  # not in the current config -> dropped
    ]
    assert sched.import_state(records) == 1  # only 'keep' matched

    states = {nd.hostname: s for nd, s in sched.node_states()}
    assert states["keep"].lastcheck == int(Status.UNPINGABLE) and states["keep"].downct == 5
    assert states["fresh"].lastcheck == Status.OK and states["fresh"].downct == 0  # untouched


def test_import_matches_on_full_key_not_just_hostname():
    # Same hostname, different type/port must NOT cross-pollinate state.
    sched = _scheduler([Node("h", CheckType.TCP, port=80)])
    assert sched.import_state([{**RECORD, "hostname": "h", "type": "tcp", "port": 22}]) == 0
    st = next(s for nd, s in sched.node_states() if nd.hostname == "h")
    assert st.lastcheck == Status.OK  # the port-22 record did not match the port-80 node


# --- import rejects corrupt/hostile field values (degrade to fresh, never wedge) -------

def test_import_skips_record_with_wrong_typed_field():
    # A string downct would crash apply_result's `downct += 1` and wedge the node forever; a
    # malformed record is skipped wholesale, leaving the node fresh rather than half-restored.
    sched = _scheduler([Node("p", CheckType.PING)])
    assert sched.import_state([{**RECORD, "downct": "5"}]) == 0
    st = next(s for nd, s in sched.node_states() if nd.hostname == "p")
    assert st.lastcheck == Status.OK and st.downct == 0


def test_import_rejects_bool_as_int_field():
    # bool is an int subclass; a JSON `true` must not slip through as a status code / counter.
    sched = _scheduler([Node("p", CheckType.PING)])
    assert sched.import_state([{**RECORD, "lastcheck": True}]) == 0


def test_import_skips_record_missing_a_carried_field():
    sched = _scheduler([Node("p", CheckType.PING)])
    incomplete = {k: v for k, v in RECORD.items() if k != "last_up"}
    assert sched.import_state([incomplete]) == 0
    st = next(s for nd, s in sched.node_states() if nd.hostname == "p")
    assert st.lastcheck == Status.OK


def test_import_good_and_bad_records_partial_restore():
    # A bad record is dropped without poisoning the good ones in the same file.
    sched = _scheduler([Node("good", CheckType.PING), Node("bad", CheckType.PING)])
    records = [{**RECORD, "hostname": "good"}, {**RECORD, "hostname": "bad", "contacted": "yes"}]
    assert sched.import_state(records) == 1
    states = {nd.hostname: s for nd, s in sched.node_states()}
    assert states["good"].downct == 5  # restored
    assert states["bad"].lastcheck == Status.OK and states["bad"].downct == 0  # left fresh


# --- the headline guarantee: no duplicate page after a restart -------------------------

class _RecordingNotifier:
    def __init__(self):
        self.sent: list[tuple[str, PageIntent]] = []

    async def send(self, node, state, intent):
        self.sent.append((node.hostname, intent))
        return True


async def test_no_duplicate_page_on_first_sweep_after_restart():
    # A node that was DOWN and already contacted before the restart, restored from disk, must not
    # re-page when the first post-restart check confirms it is still down.
    notifier = _RecordingNotifier()

    async def runner(node, ctx):
        return Status.UNPINGABLE  # still down

    sched = Scheduler(
        [Node("p", CheckType.PING, max_down=2)], Settings(),
        clock=ManualClock(), notifier=notifier, runner=runner, stagger=False,
    )
    sched.import_state([RECORD])  # restore DOWN + contacted

    await sched.tick()
    await sched.drain()

    st = next(s for nd, s in sched.node_states() if nd.hostname == "p")
    assert st.lastcheck == Status.UNPINGABLE and st.downct == 6  # incremented, still down
    assert st.contacted is True
    assert notifier.sent == []  # NO duplicate DOWN page (nor a spurious recovery)


async def test_recovery_after_restart_still_pages():
    # The flip side: if the restored-contacted node comes back up, the recovery page DOES fire —
    # restoring `contacted` suppresses a duplicate DOWN, not a legitimate recovery notice.
    notifier = _RecordingNotifier()

    async def runner(node, ctx):
        return Status.OK  # recovered

    sched = Scheduler(
        [Node("p", CheckType.PING, max_down=2)], Settings(),
        clock=ManualClock(), notifier=notifier, runner=runner, stagger=False,
    )
    sched.import_state([RECORD])

    await sched.tick()
    await sched.drain()

    st = next(s for nd, s in sched.node_states() if nd.hostname == "p")
    assert st.lastcheck == Status.OK and st.contacted is False
    assert notifier.sent == [("p", PageIntent.RECOVERY)]
