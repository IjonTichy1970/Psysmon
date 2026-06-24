"""The psysmon control/query channel server (#69).

A minimal **line-framed JSON** request/response over ``asyncio.start_server`` (no HTTP, no new
dependency), with optional TLS. One request per connection: the client sends a single JSON
object terminated by ``\\n`` and reads one JSON object back, then the connection closes.

Security model (every rule fails CLOSED — see #69):
  * **Loopback by default.** The bind address is resolved and every resolved address must be
    loopback; a non-loopback bind is refused unless TLS (cert+key) is configured.
  * **Token-gated mutations.** ``ack``/``note``/``reload`` require a bearer token (a 0600 file);
    with no token configured, mutations are *disabled* (reads still work). Reads (``status``/
    ``version``) need no token. The token is compared in constant time.
  * **Sanitized output only.** ``status`` serves the same :func:`~psysmon.output.jsonout.to_json`
    the status page uses — it never emits stored credentials, and there is no raw-config dump.
  * **Bounded.** Max request size, a total per-connection deadline, and a concurrent-connection
    cap so the channel can't starve the scheduler's event loop.
  * **Deny-by-default dispatch + generic wire errors.** Unknown command -> error; a handler
    exception is logged locally and answered with a fixed error code (never a traceback);
    nothing is mutated on any error path. No remote shutdown/kill command exists.
"""

from __future__ import annotations

import asyncio
import ipaddress
import json
import logging
import socket
import ssl
import time

from psysmon import __version__
from psysmon.control.auth import TokenError, load_token, token_matches
from psysmon.output.jsonout import to_json

log = logging.getLogger("psysmon.control")

_MAX_LINE = 65536       # max request line in bytes (DoS guard)
_READ_TIMEOUT_S = 5.0   # per-connection read deadline — slow-loris guard; NOT behind a shared gate
_WRITE_TIMEOUT_S = 5.0  # deadline to flush the reply (a client that won't read can't linger)
_MAX_CONNS = 32         # concurrent connections; reject-when-full (never queue behind slow ones)
_BACKLOG = 16


class ControlError(Exception):
    """A misconfiguration that must abort startup (bad bind, missing/invalid TLS). Fail closed."""


def _all_loopback(host: str) -> bool:
    """True iff every address ``host`` resolves to is loopback; raises ControlError if it does
    not resolve. Resolving (rather than parsing) closes the ``localhost``/hostname bypass."""
    try:
        infos = socket.getaddrinfo(host, None, type=socket.SOCK_STREAM)
    except OSError as exc:
        raise ControlError(f"control bind {host!r} does not resolve: {exc}") from exc
    addrs = {info[4][0] for info in infos}
    if not addrs:
        raise ControlError(f"control bind {host!r} did not resolve to any address")
    for addr in addrs:
        ip = ipaddress.ip_address(addr.split("%", 1)[0])  # strip any zone id
        ip = ip.ipv4_mapped or ip if isinstance(ip, ipaddress.IPv6Address) else ip
        if not ip.is_loopback:
            return False
    return True


def _build_tls(settings) -> ssl.SSLContext | None:
    cert, key = settings.control_tls_cert, settings.control_tls_key
    if not cert and not key:
        return None
    if not (cert and key):
        raise ControlError("control TLS needs both control_tls_cert and control_tls_key")
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ctx.minimum_version = ssl.TLSVersion.TLSv1_2
    ctx.verify_mode = ssl.CERT_NONE  # the bearer token is the authn; TLS is confidentiality only
    try:
        ctx.load_cert_chain(cert, key)
    except (OSError, ssl.SSLError) as exc:
        raise ControlError(f"control TLS cert/key load failed: {exc}") from exc
    return ctx


class ControlServer:
    """Owns the ``asyncio`` server + per-connection handling. Construct, ``start()``, ``stop()``."""

    def __init__(self, scheduler, reload_flag: asyncio.Event, settings) -> None:
        self._scheduler = scheduler
        self._reload_flag = reload_flag
        self._settings = settings
        self._token: str | None = None
        self._server: asyncio.AbstractServer | None = None
        self._conns: set[asyncio.Task] = set()
        self._active = 0  # concurrent connection count (reject-when-full, never queue)

    async def start(self) -> None:
        """Bind + start listening. Raises :class:`ControlError` (fatal at startup) on a bad
        bind / TLS config / unsafe token file — never silently opens an unprotected channel."""
        s = self._settings
        loopback = _all_loopback(s.control_bind)
        tls = _build_tls(s)
        if not loopback and tls is None:
            raise ControlError(
                f"control bind {s.control_bind!r} is not loopback; TLS (control_tls_cert + "
                "control_tls_key) is required to expose the control channel beyond localhost"
            )
        if s.control_token_file:
            self._token = load_token(s.control_token_file)  # raises TokenError on unsafe/missing
        else:
            log.warning("psysmon: control channel has no token file configured; mutating actions "
                        "(ack/note/reload) are DISABLED — status queries only")
        self._server = await asyncio.start_server(
            self._handle, host=s.control_bind, port=s.control_port,
            ssl=tls, limit=_MAX_LINE, backlog=_BACKLOG,
        )
        log.info("psysmon: control channel listening on %s:%d (%s)",
                 s.control_bind, s.control_port, "tls" if tls else "plaintext")

    async def stop(self) -> None:
        # Cancel live connections FIRST: an idle client never drains, so wait_closed() would
        # otherwise block here (and thus block the daemon's SIGTERM shutdown, which awaits stop()).
        for task in list(self._conns):
            task.cancel()
        if self._server is not None:
            self._server.close()
            await self._server.wait_closed()

    async def _handle(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
        if self._active >= _MAX_CONNS:
            # Reject-when-full: never queue a legitimate client behind a backlog of slow ones.
            await self._write(writer, {"ok": False, "error": "busy"})
            writer.close()
            return
        self._active += 1
        task = asyncio.current_task()
        self._conns.add(task)
        try:
            # The read has its OWN short deadline and is NOT behind a shared gate, so a slow/never-
            # sending client only holds its own slot (freed in <= _READ_TIMEOUT_S), never blocking
            # others — the dispatch itself is synchronous and instant.
            resp = await self._read_request(reader)
            await self._write(writer, resp)
        except (TimeoutError, asyncio.CancelledError):
            pass
        except Exception:
            log.exception("psysmon: control connection error")  # detail to the local log only
        finally:
            self._active -= 1
            self._conns.discard(task)
            writer.close()
            try:
                await writer.wait_closed()
            except (OSError, ssl.SSLError):
                pass

    async def _read_request(self, reader) -> dict:
        try:
            line = await asyncio.wait_for(reader.readuntil(b"\n"), _READ_TIMEOUT_S)
        except (TimeoutError, asyncio.LimitOverrunError, asyncio.IncompleteReadError, OSError):
            return {"ok": False, "error": "bad_request"}
        try:
            req = json.loads(line)
        except Exception:  # ValueError / UnicodeDecodeError, and RecursionError on a JSON bomb
            return {"ok": False, "error": "bad_request"}
        if not isinstance(req, dict):
            return {"ok": False, "error": "bad_request"}
        return self._dispatch(req)

    async def _write(self, writer, resp: dict) -> None:
        writer.write((json.dumps(resp) + "\n").encode("utf-8"))
        try:
            await asyncio.wait_for(writer.drain(), _WRITE_TIMEOUT_S)
        except (TimeoutError, OSError, ssl.SSLError):
            pass  # a client that won't read its reply doesn't get to hold the connection open

    def _dispatch(self, req: dict) -> dict:
        cmd = req.get("cmd")
        entry = _COMMANDS.get(cmd) if isinstance(cmd, str) else None
        if entry is None:
            return {"ok": False, "error": "unknown_command"}
        handler, requires_token = entry
        if requires_token:
            if self._token is None:  # fail closed: no token configured -> no mutations
                return {"ok": False, "error": "mutations_disabled"}
            if not token_matches(req.get("token"), self._token):
                return {"ok": False, "error": "unauthorized"}
        try:
            return handler(self, req)
        except Exception:
            log.exception("psysmon: control handler error")  # never leak detail to the wire
            return {"ok": False, "error": "internal_error"}

    # --- command handlers -------------------------------------------------------------
    def _cmd_status(self, req: dict) -> dict:
        payload = to_json(self._scheduler.node_states(), now_wall=time.time(), indent=None)
        return {"ok": True, "status": json.loads(payload)}  # sanitized: no creds, no raw config

    def _cmd_version(self, req: dict) -> dict:
        return {"ok": True, "version": __version__}

    def _cmd_ack(self, req: dict) -> dict:
        key = _object_key(req)
        if key is None:
            return {"ok": False, "error": "bad_request"}
        matched = self._scheduler.ack(*key)
        return {"ok": True, "matched": matched} if matched else {"ok": False, "error": "not_found"}

    def _cmd_note(self, req: dict) -> dict:
        key = _object_key(req)
        text = req.get("text")
        if key is None or (text is not None and not isinstance(text, str)):
            return {"ok": False, "error": "bad_request"}
        matched = self._scheduler.set_note(*key, text)
        return {"ok": True, "matched": matched} if matched else {"ok": False, "error": "not_found"}

    def _cmd_reload(self, req: dict) -> dict:
        self._reload_flag.set()  # coalesced by the daemon's reload loop; no inline parse here
        return {"ok": True}


def _object_key(req: dict) -> tuple[str, str, int] | None:
    """Extract a validated (hostname, type, port) lookup key from ``req['object']``."""
    obj = req.get("object")
    if not isinstance(obj, dict):
        return None
    host, type_value, port = obj.get("hostname"), obj.get("type"), obj.get("port", 0)
    if not isinstance(host, str) or not isinstance(type_value, str):
        return None
    if isinstance(port, bool) or not isinstance(port, int):  # bool is an int subclass — reject it
        return None
    return (host, type_value, port)


_COMMANDS = {
    "status": (ControlServer._cmd_status, False),
    "version": (ControlServer._cmd_version, False),
    "ack": (ControlServer._cmd_ack, True),
    "note": (ControlServer._cmd_note, True),
    "reload": (ControlServer._cmd_reload, True),
}

# Re-export the loader error so callers can catch a single control-startup failure type.
__all__ = ["ControlServer", "ControlError", "TokenError"]
