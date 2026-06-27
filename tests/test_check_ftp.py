"""Tests for the FTP greeting + optional login check (#102).

Drives the real checker against a loopback server (plaintext; the implicit-TLS wrapping for the
FTPS type is covered in test_check_base). Mirrors the SMTP/POP3 check tests.
"""

from __future__ import annotations

from psysmon.checks import base, ftp
from psysmon.config.model import CheckType, Node
from psysmon.status import Status

from .conftest import FakeResolver


def node(port: int = 0, *, user: str = "", pw: str = "") -> Node:
    return Node(hostname="ftp.example.net", check_type=CheckType.FTP, port=port,
                username=user, password=pw)


async def _greeting_only(text: bytes):
    """An FTP server that sends only a greeting, then waits for the client's QUIT and closes."""
    async def handler(reader, writer):
        writer.write(text)
        await writer.drain()
        await reader.readline()  # the client's QUIT (banner path) or EOF, then tear down
        writer.close()

    return handler


def make_login_handler(user_reply: bytes | None, pass_reply: bytes | None,
                       greeting: bytes = b"220 ProFTPD ready\r\n"):
    """Build a handler emulating an FTP login, recording client commands seen. A ``None`` reply
    means: read the command, then close WITHOUT replying (modelling a mid-login drop)."""
    seen: list[bytes] = []

    async def handler(reader, writer):
        writer.write(greeting)
        await writer.drain()
        if not greeting.startswith(b"220"):
            writer.close()
            return
        seen.append(await reader.readline())  # USER
        if user_reply is None:
            writer.close()
            return
        writer.write(user_reply)
        await writer.drain()
        if not user_reply.startswith(b"331"):  # 230/530/odd end the exchange before PASS
            try:
                await reader.readline()  # drain a possible QUIT (the 230 success path sends one)
            except Exception:  # pragma: no cover - peer may already be gone
                pass
            writer.close()
            return
        seen.append(await reader.readline())  # PASS
        if pass_reply is None:
            writer.close()
            return
        writer.write(pass_reply)
        await writer.drain()
        try:
            await reader.readline()  # the client's QUIT on success
        except Exception:  # pragma: no cover
            pass
        writer.close()

    return handler, seen


async def test_banner_220_ok_without_credentials(check_ctx, tcp_server):
    port = await tcp_server(await _greeting_only(b"220 Welcome\r\n"))
    assert await ftp.check(node(port=port), check_ctx) == Status.OK


async def test_multiline_220_banner_ok(check_ctx, tcp_server):
    # A multi-line greeting (220-... continuation, 220 final) must be consumed and read as up.
    port = await tcp_server(await _greeting_only(
        b"220-First line\r\n220-More info\r\n220 Ready\r\n"))
    assert await ftp.check(node(port=port), check_ctx) == Status.OK


async def test_421_greeting_bad_response(check_ctx, tcp_server):
    port = await tcp_server(await _greeting_only(b"421 Service not available\r\n"))
    assert await ftp.check(node(port=port), check_ctx) == Status.BAD_RESPONSE


async def test_empty_greeting_no_response(check_ctx, tcp_server):
    async def handler(reader, writer):
        writer.close()

    port = await tcp_server(handler)
    assert await ftp.check(node(port=port), check_ctx) == Status.NO_RESPONSE


async def test_login_ok(check_ctx, tcp_server):
    handler, seen = make_login_handler(b"331 need password\r\n", b"230 logged in\r\n")
    port = await tcp_server(handler)
    assert await ftp.check(node(port=port, user="alice", pw="secret"), check_ctx) == Status.OK
    assert seen == [b"USER alice\r\n", b"PASS secret\r\n"]


async def test_login_230_after_user_ok(check_ctx, tcp_server):
    # Some servers (e.g. anonymous) log in straight after USER, with no password needed.
    handler, seen = make_login_handler(b"230 logged in\r\n", None)
    port = await tcp_server(handler)
    assert await ftp.check(node(port=port, user="anonymous", pw="e@x"), check_ctx) == Status.OK
    assert seen == [b"USER anonymous\r\n"]  # PASS was never sent


async def test_user_rejected_bad_auth(check_ctx, tcp_server):
    handler, seen = make_login_handler(b"530 no such user\r\n", None)
    port = await tcp_server(handler)
    assert await ftp.check(node(port=port, user="x", pw="y"), check_ctx) == Status.BAD_AUTH
    assert seen == [b"USER x\r\n"]  # PASS not sent after the rejection


async def test_pass_rejected_bad_auth(check_ctx, tcp_server):
    handler, _ = make_login_handler(b"331 need password\r\n", b"530 login incorrect\r\n")
    port = await tcp_server(handler)
    assert await ftp.check(node(port=port, user="x", pw="y"), check_ctx) == Status.BAD_AUTH


async def test_drop_at_pass_no_response(check_ctx, tcp_server):
    # USER accepted (331), then the server drops at PASS with no reply -> NO_RESPONSE, not BAD_AUTH
    # (a correct password can be dropped on a post-auth fault; reporting auth would misdirect).
    handler, seen = make_login_handler(b"331 need password\r\n", None)
    port = await tcp_server(handler)
    assert await ftp.check(node(port=port, user="x", pw="y"), check_ctx) == Status.NO_RESPONSE
    assert seen == [b"USER x\r\n", b"PASS y\r\n"]


async def test_drop_at_user_no_response(check_ctx, tcp_server):
    handler, _ = make_login_handler(None, None)
    port = await tcp_server(handler)
    assert await ftp.check(node(port=port, user="x", pw="y"), check_ctx) == Status.NO_RESPONSE


async def test_odd_user_reply_bad_response(check_ctx, tcp_server):
    # A USER reply that is neither 331/230/530 is a protocol violation -> BAD_RESPONSE.
    handler, _ = make_login_handler(b"200 weird\r\n", None)
    port = await tcp_server(handler)
    assert await ftp.check(node(port=port, user="x", pw="y"), check_ctx) == Status.BAD_RESPONSE


async def test_default_port_used(check_ctx, monkeypatch):
    # port=0 must fall back to the FTP default (21).
    from psysmon.config.model import DEFAULT_PORT

    captured: dict[str, int] = {}

    async def fake_open_connection(ip, port, ctx, *, tls=False, server_hostname=None):
        captured["port"] = port

        class _Reader:
            async def readline(self):
                return b"220 ready\r\n"

        class _Writer:
            def write(self, _data):
                pass

            async def drain(self):
                pass

            def close(self):
                pass

            async def wait_closed(self):
                pass

        return _Reader(), _Writer()

    monkeypatch.setattr(base, "open_connection", fake_open_connection)
    assert await ftp.check(node(port=0), check_ctx) == Status.OK
    assert captured["port"] == DEFAULT_PORT[CheckType.FTP] == 21


async def test_perform_no_dns():
    ctx = base.CheckContext(resolver=FakeResolver(default=None), timeout_s=2.0)
    assert await base.perform(ftp.check, node(), ctx) == Status.NO_DNS


async def test_perform_connection_failure(check_ctx, free_port):
    result = await base.perform(ftp.check, node(port=free_port), check_ctx)
    assert result in (Status.CONN_REFUSED, Status.TIMED_OUT, Status.HOST_DOWN)
    assert result != Status.OK
