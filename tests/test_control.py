"""Tests for the control/query channel (#69) — bind gating, token auth, and the dispatch surface.

The security-critical invariants live here: a non-loopback bind is refused without TLS, mutations
fail closed without a token, status output never leaks credentials, and the dispatch denies by
default. Round-trips run a real server on a loopback ``port 0`` (OS-assigned) over asyncio.
"""

from __future__ import annotations

import asyncio
import json
import os

import pytest

from psysmon.config.model import CheckType, Node
from psysmon.config.settings import Settings
from psysmon.control.auth import TokenError, load_token, token_matches
from psysmon.control.server import ControlError, ControlServer, _all_loopback, _build_tls
from psysmon.engine.scheduler import Scheduler
from psysmon.status import Status

POSIX_ONLY = pytest.mark.skipif(os.name != "posix", reason="POSIX file-mode bits")


def _sched(nodes=None) -> Scheduler:
    nodes = nodes or [Node("h.example.net", CheckType.PING)]
    return Scheduler(nodes, Settings(), stagger=False)


def _settings(**kw) -> Settings:
    s = Settings()
    s.control_enabled = True
    s.control_bind = "127.0.0.1"
    s.control_port = 0  # OS picks a free port
    for k, v in kw.items():
        setattr(s, k, v)
    return s


async def _start(scheduler, settings) -> tuple[ControlServer, asyncio.Event, int]:
    reload_flag = asyncio.Event()
    server = ControlServer(scheduler, reload_flag, settings)
    await server.start()
    port = server._server.sockets[0].getsockname()[1]
    return server, reload_flag, port


async def _send(port: int, payload: dict, *, host: str = "127.0.0.1") -> dict:
    reader, writer = await asyncio.open_connection(host, port)
    writer.write((json.dumps(payload) + "\n").encode("utf-8"))
    await writer.drain()
    line = await asyncio.wait_for(reader.readline(), 5)
    writer.close()
    await writer.wait_closed()
    return json.loads(line)


# --- bind gating -----------------------------------------------------------------------

def test_all_loopback_classifies_addresses():
    assert _all_loopback("127.0.0.1") is True
    assert _all_loopback("::1") is True
    assert _all_loopback("localhost") is True  # resolves to loopback (closes the hostname bypass)
    assert _all_loopback("0.0.0.0") is False
    assert _all_loopback("8.8.8.8") is False


async def test_start_refuses_nonloopback_without_tls():
    server = ControlServer(_sched(), asyncio.Event(), _settings(control_bind="0.0.0.0"))
    with pytest.raises(ControlError):
        await server.start()


def test_build_tls_requires_both_cert_and_key():
    with pytest.raises(ControlError):
        _build_tls(_settings(control_tls_cert="/c.pem"))  # key missing
    with pytest.raises(ControlError):
        _build_tls(_settings(control_tls_cert="/nope.pem", control_tls_key="/nope.key"))  # no file


# --- token auth ------------------------------------------------------------------------

def test_token_matches_constant_time_semantics():
    assert token_matches("s3cret", "s3cret") is True
    assert token_matches("wrong", "s3cret") is False
    assert token_matches(None, "s3cret") is False  # missing -> False, never raises
    assert token_matches(12345, "s3cret") is False  # non-str -> False


def test_load_token_reads_value(tmp_path):
    f = tmp_path / "tok"
    f.write_text("  my-token\n", encoding="utf-8")
    if os.name == "posix":
        os.chmod(f, 0o600)
    assert load_token(str(f)) == "my-token"  # stripped


def test_load_token_missing_and_empty(tmp_path):
    with pytest.raises(TokenError):
        load_token(str(tmp_path / "absent"))
    empty = tmp_path / "empty"
    empty.write_text("", encoding="utf-8")
    if os.name == "posix":
        os.chmod(empty, 0o600)
    with pytest.raises(TokenError):
        load_token(str(empty))


@POSIX_ONLY
def test_load_token_rejects_group_world_readable(tmp_path):
    f = tmp_path / "tok"
    f.write_text("t\n", encoding="utf-8")
    os.chmod(f, 0o644)  # group/world-readable
    with pytest.raises(TokenError):
        load_token(str(f))


# --- query surface (sanitized) ---------------------------------------------------------

async def test_status_is_sanitized_no_credential_leak():
    secret = "s3cr3t-p@ss"
    node = Node("mail.example.net", CheckType.POP3, port=110, username="systest",
                password=secret, label="pop3", contact="noc@example.net")
    sched = _sched([node])
    sched.node_states()[0][1].lastcheck = Status.BAD_AUTH  # down for realism
    server, _, port = await _start(sched, _settings())
    try:
        resp = await _send(port, {"cmd": "status"})
        assert resp["ok"] is True
        blob = json.dumps(resp)
        assert secret not in blob and "systest" not in blob  # no creds over the channel
        assert any(h["hostname"] == "mail.example.net" for h in resp["status"]["hosts"])
    finally:
        await server.stop()


async def test_version_query():
    server, _, port = await _start(_sched(), _settings())
    try:
        resp = await _send(port, {"cmd": "version"})
        assert resp["ok"] is True and isinstance(resp["version"], str)
    finally:
        await server.stop()


# --- mutations + dispatch --------------------------------------------------------------

async def test_mutations_disabled_without_token():
    server, reload_flag, port = await _start(_sched(), _settings())  # no token configured
    try:
        resp = await _send(port, {"cmd": "ack", "object": {"hostname": "h.example.net",
                                                           "type": "ping", "port": 0}})
        assert resp == {"ok": False, "error": "mutations_disabled"}
        assert not reload_flag.is_set()
    finally:
        await server.stop()


async def test_ack_requires_correct_token(tmp_path):
    tok = tmp_path / "tok"
    tok.write_text("sekret\n", encoding="utf-8")
    if os.name == "posix":
        os.chmod(tok, 0o600)
    sched = _sched()
    server, _, port = await _start(sched, _settings(control_token_file=str(tok)))
    try:
        obj = {"hostname": "h.example.net", "type": "ping", "port": 0}
        bad = await _send(port, {"cmd": "ack", "object": obj, "token": "nope"})
        assert bad == {"ok": False, "error": "unauthorized"}
        assert sched.node_states()[0][1].acked is False
        ok = await _send(port, {"cmd": "ack", "object": obj, "token": "sekret"})
        assert ok["ok"] is True and ok["matched"] == 1
        assert sched.node_states()[0][1].acked is True
    finally:
        await server.stop()


async def test_reload_with_token_sets_flag(tmp_path):
    tok = tmp_path / "tok"
    tok.write_text("k\n", encoding="utf-8")
    if os.name == "posix":
        os.chmod(tok, 0o600)
    server, reload_flag, port = await _start(_sched(), _settings(control_token_file=str(tok)))
    try:
        resp = await _send(port, {"cmd": "reload", "token": "k"})
        assert resp["ok"] is True and reload_flag.is_set()
    finally:
        await server.stop()


async def test_unknown_command_and_malformed_request():
    server, _, port = await _start(_sched(), _settings())
    try:
        assert (await _send(port, {"cmd": "killit"}))["error"] == "unknown_command"
        assert (await _send(port, {"cmd": "ack"}))["error"] == "mutations_disabled"  # gated first
        # malformed (non-object / bad JSON)
        reader, writer = await asyncio.open_connection("127.0.0.1", port)
        writer.write(b"not json\n")
        await writer.drain()
        line = await asyncio.wait_for(reader.readline(), 5)
        writer.close()
        await writer.wait_closed()
        assert json.loads(line)["error"] == "bad_request"
    finally:
        await server.stop()


async def test_psysmonctl_client_roundtrip():
    # Exercise the sync psysmonctl client against the real async server (client runs in a thread).
    from psysmon.control import client

    server, _, port = await _start(_sched(), _settings())
    try:
        resp = await asyncio.to_thread(
            client._request, "127.0.0.1", port, {"cmd": "version"}, tls_ca=None, timeout=5.0)
        assert resp["ok"] is True and "version" in resp
    finally:
        await server.stop()


async def test_oversized_request_is_rejected():
    server, _, port = await _start(_sched(), _settings())
    try:
        reader, writer = await asyncio.open_connection("127.0.0.1", port)
        writer.write(b"x" * 70000 + b"\n")  # exceeds the 64 KiB line cap, no usable newline first
        await writer.drain()
        line = await asyncio.wait_for(reader.readline(), 5)
        writer.close()
        await writer.wait_closed()
        assert json.loads(line)["error"] == "bad_request"
    finally:
        await server.stop()


async def test_deep_nested_json_replies_bad_request():
    # A JSON bomb (deep nesting within the line cap) raises RecursionError in json.loads; it must
    # be answered with bad_request, not dropped with a traceback (review MED).
    server, _, port = await _start(_sched(), _settings())
    try:
        reader, writer = await asyncio.open_connection("127.0.0.1", port)
        writer.write(b"[" * 20000 + b"]" * 20000 + b"\n")
        await writer.drain()
        line = await asyncio.wait_for(reader.readline(), 5)
        writer.close()
        await writer.wait_closed()
        assert json.loads(line)["error"] == "bad_request"  # a reply, not a silent drop
    finally:
        await server.stop()


async def test_handler_exception_replies_internal_error():
    # A handler that raises must yield a fixed error code on the wire (no traceback leak, no drop).
    class _Boom:
        def node_states(self):
            raise RuntimeError("boom-INTERNAL-detail")

    server, _, port = await _start(_Boom(), _settings())
    try:
        resp = await _send(port, {"cmd": "status"})
        assert resp == {"ok": False, "error": "internal_error"}  # detail stays in the local log
    finally:
        await server.stop()


async def test_rejects_when_full():
    # reject-when-full: at the connection cap, a new client is answered "busy" rather than queued.
    from psysmon.control import server as srv

    server, _, port = await _start(_sched(), _settings())
    server._active = srv._MAX_CONNS  # simulate a full server deterministically
    try:
        assert (await _send(port, {"cmd": "version"}))["error"] == "busy"
    finally:
        server._active = 0
        await server.stop()


async def test_stop_does_not_hang_on_idle_connection():
    # An idle connected client must not block shutdown (cancel-before-wait_closed); serve() awaits
    # stop() on SIGTERM, so a hang here would wedge the daemon's graceful shutdown.
    server, _, port = await _start(_sched(), _settings())
    reader, writer = await asyncio.open_connection("127.0.0.1", port)  # connect, send nothing
    await asyncio.sleep(0.05)  # let the server register the connection
    try:
        await asyncio.wait_for(server.stop(), 3.0)  # must return, not hang on the idle client
    finally:
        writer.close()
        try:
            await writer.wait_closed()
        except OSError:
            pass


async def test_start_nonloopback_bad_cert_aborts_no_plaintext_fallback():
    # The headline invariant: a non-loopback bind whose TLS cert won't load must ABORT, never fall
    # back to a plaintext channel on a public interface.
    s = _settings(control_bind="0.0.0.0", control_tls_cert="/nope.pem", control_tls_key="/nope.key")
    with pytest.raises(ControlError):
        await ControlServer(_sched(), asyncio.Event(), s).start()


async def test_object_key_validation_rejects_bad_shapes(tmp_path):
    tok = tmp_path / "t"
    tok.write_text("k\n", encoding="utf-8")
    if os.name == "posix":
        os.chmod(tok, 0o600)
    server, _, port = await _start(_sched(), _settings(control_token_file=str(tok)))
    try:
        bad = [
            {"cmd": "ack", "token": "k"},  # no object
            {"cmd": "ack", "token": "k", "object": ["h", "ping", 0]},  # object not a dict
            {"cmd": "ack", "token": "k", "object": {"hostname": 1, "type": "ping", "port": 0}},
            {"cmd": "ack", "token": "k", "object": {"hostname": "h", "type": "ping", "port": True}},
        ]
        for req in bad:
            assert (await _send(port, req))["error"] == "bad_request"
        nt = {"cmd": "note", "token": "k",
              "object": {"hostname": "h.example.net", "type": "ping", "port": 0}, "text": 123}
        assert (await _send(port, nt))["error"] == "bad_request"  # non-string note text
    finally:
        await server.stop()


async def test_note_set_clear_and_not_found(tmp_path):
    tok = tmp_path / "t"
    tok.write_text("k\n", encoding="utf-8")
    if os.name == "posix":
        os.chmod(tok, 0o600)
    sched = _sched()
    server, _, port = await _start(sched, _settings(control_token_file=str(tok)))
    try:
        obj = {"hostname": "h.example.net", "type": "ping", "port": 0}
        r = await _send(port, {"cmd": "note", "token": "k", "object": obj, "text": "flaky"})
        assert r["ok"] and r["matched"] == 1 and sched.node_states()[0][1].note == "flaky"
        r2 = await _send(port, {"cmd": "note", "token": "k", "object": obj, "text": ""})
        assert r2["ok"] and sched.node_states()[0][1].note is None  # empty clears
        miss = {"hostname": "nope.example.net", "type": "ping", "port": 0}
        assert await _send(port, {"cmd": "ack", "token": "k", "object": miss}) == {
            "ok": False, "error": "not_found"}
    finally:
        await server.stop()


@POSIX_ONLY
def test_load_token_refuses_symlink(tmp_path):
    real = tmp_path / "real"
    real.write_text("k\n", encoding="utf-8")
    os.chmod(real, 0o600)
    link = tmp_path / "link"
    os.symlink(real, link)
    with pytest.raises(TokenError):
        load_token(str(link))  # O_NOFOLLOW refuses the symlink
