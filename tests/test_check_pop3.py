"""Tests for the POP3 auth check."""

from __future__ import annotations

from psysmon.checks import base
from psysmon.checks.pop3 import check
from psysmon.config.model import CheckType, Node
from psysmon.status import Status

from .conftest import FakeResolver


def node(port: int = 0, username: str = "alice", password: str = "secret") -> Node:
    return Node(
        hostname="mail.example.net",
        check_type=CheckType.POP3,
        port=port,
        username=username,
        password=password,
    )


def make_pop3_handler(
    pass_reply: bytes | None,
    greeting: bytes = b"+OK POP3 ready\r\n",
    *,
    user_reply: bytes | None = b"+OK send PASS\r\n",
):
    """Build a tcp_server handler emulating a POP3 server, recording client lines seen.

    A ``None`` reply (``user_reply`` or ``pass_reply``) means: read the client's command, then
    close the connection WITHOUT sending a reply — modelling a server that drops mid-auth (e.g.
    a post-auth backend fault). An ``-ERR`` ``user_reply`` closes after the rejection.
    """
    seen: list[bytes] = []

    async def handler(reader, writer):
        writer.write(greeting)
        await writer.drain()
        if not greeting.startswith(b"+OK"):
            writer.close()
            return
        # USER
        seen.append(await reader.readline())
        if user_reply is None:  # drop without answering USER
            writer.close()
            return
        writer.write(user_reply)
        await writer.drain()
        if user_reply.startswith(b"-ERR"):  # username rejected, server closes
            writer.close()
            return
        # PASS
        seen.append(await reader.readline())
        if pass_reply is None:  # drop without answering PASS (a post-auth drop)
            writer.close()
            return
        writer.write(pass_reply)
        await writer.drain()
        # Optionally drain QUIT
        try:
            seen.append(await reader.readline())
        except Exception:  # pragma: no cover - connection may close first
            pass
        writer.close()

    return handler, seen


async def test_happy_path_ok(check_ctx, tcp_server):
    handler, seen = make_pop3_handler(b"+OK logged in\r\n")
    port = await tcp_server(handler)
    n = node(port=port, username="alice", password="secret")

    assert await check(n, check_ctx) == Status.OK

    # Give the server a chance to record the QUIT (close happens client-side).
    assert seen[0] == b"USER alice\r\n"
    assert seen[1] == b"PASS secret\r\n"


async def test_bad_auth_on_pass(check_ctx, tcp_server):
    handler, _ = make_pop3_handler(b"-ERR auth failed\r\n")
    port = await tcp_server(handler)

    assert await check(node(port=port), check_ctx) == Status.BAD_AUTH


async def test_bad_auth_on_user(check_ctx, tcp_server):
    # The server rejects the username outright (-ERR on USER). We must classify that as BAD_AUTH
    # and NOT go on to send PASS — previously the USER reply was read and discarded (#54).
    handler, seen = make_pop3_handler(b"+OK logged in\r\n", user_reply=b"-ERR no such user\r\n")
    port = await tcp_server(handler)

    assert await check(node(port=port), check_ctx) == Status.BAD_AUTH
    assert seen == [b"USER alice\r\n"]  # PASS was never sent


async def test_garbage_user_reply_still_sends_pass(check_ctx, tcp_server):
    # A USER reply that is neither +OK nor -ERR nor empty is not a clear rejection, so the check
    # proceeds to PASS (which then decides the verdict) — the deliberate, faithful behavior. Here
    # PASS succeeds, so the overall result is OK despite the odd USER reply.
    handler, seen = make_pop3_handler(b"+OK logged in\r\n", user_reply=b"?? odd\r\n")
    port = await tcp_server(handler)

    assert await check(node(port=port), check_ctx) == Status.OK
    assert seen[0] == b"USER alice\r\n"
    assert seen[1] == b"PASS secret\r\n"  # PASS was still sent


async def test_no_response_when_dropped_at_user(check_ctx, tcp_server):
    # The connection drops after USER with no reply at all -> NO_RESPONSE: there was no response
    # (so not BAD_AUTH) and nothing malformed was received (so not BAD_RESPONSE) (#54).
    handler, _ = make_pop3_handler(b"+OK logged in\r\n", user_reply=None)
    port = await tcp_server(handler)

    assert await check(node(port=port), check_ctx) == Status.NO_RESPONSE


async def test_no_response_when_dropped_at_pass(check_ctx, tcp_server):
    # The real mail.example.net case: USER is accepted (+OK), then the server drops the
    # connection at PASS with no reply line (a post-auth backend fault). That is NO_RESPONSE, NOT
    # BAD_AUTH — a *correct* password can also be dropped post-auth, so reporting an auth failure
    # would misdirect the operator. Previously this fell through to BAD_RESPONSE (#54).
    handler, seen = make_pop3_handler(None)  # read PASS, then close without replying
    port = await tcp_server(handler)

    assert await check(node(port=port), check_ctx) == Status.NO_RESPONSE
    assert seen[0] == b"USER alice\r\n"
    assert seen[1] == b"PASS secret\r\n"  # PASS was sent; the server just never answered


async def test_malformed_greeting_bad_response(check_ctx, tcp_server):
    # A non-+OK greeting (the server responded, but not "ready") is BAD_RESPONSE — parity with
    # the SMTP check and the USER/PASS taxonomy (#55). The empty-greeting case stays NO_RESPONSE.
    handler, _ = make_pop3_handler(b"+OK", greeting=b"-ERR not ready\r\n")
    port = await tcp_server(handler)

    assert await check(node(port=port), check_ctx) == Status.BAD_RESPONSE


async def test_no_greeting_no_response(check_ctx, tcp_server):
    # The server accepts the connection then drops it before sending any greeting (empty/EOF) ->
    # NO_RESPONSE. Distinct from a malformed greeting; pins the empty-greeting branch.
    handler, _ = make_pop3_handler(b"+OK", greeting=b"")
    port = await tcp_server(handler)

    assert await check(node(port=port), check_ctx) == Status.NO_RESPONSE


async def test_unexpected_pass_reply_bad_response(check_ctx, tcp_server):
    handler, _ = make_pop3_handler(b"?? what\r\n")
    port = await tcp_server(handler)

    assert await check(node(port=port), check_ctx) == Status.BAD_RESPONSE


async def test_default_port_used(check_ctx, monkeypatch):
    # port=0 must fall back to the POP3 default (110). Capture the port passed to
    # open_connection so we prove the fallback expression actually selects 110.
    from psysmon.config.model import DEFAULT_PORT

    captured: dict[str, int] = {}

    async def fake_open_connection(ip, port, ctx, *, tls=False, server_hostname=None):
        captured["port"] = port

        class _Reader:
            async def readline(self):
                return b"+OK ready\r\n"

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

    assert await check(node(port=0), check_ctx) == Status.OK
    assert captured["port"] == DEFAULT_PORT[CheckType.POP3] == 110


async def test_perform_no_dns():
    ctx = base.CheckContext(resolver=FakeResolver(default=None), timeout_s=2.0)
    assert await base.perform(check, node(), ctx) == Status.NO_DNS


async def test_perform_connection_failure(check_ctx, free_port):
    # No listener on free_port: the OSError propagates and perform() maps it. Linux returns a
    # prompt CONN_REFUSED; Windows may instead let the connect time out (TIMED_OUT). Either
    # way it must be a failure mapped through the OSError/timeout path, never OK.
    result = await base.perform(check, node(port=free_port), check_ctx)
    assert result in (Status.CONN_REFUSED, Status.TIMED_OUT, Status.HOST_DOWN)
    assert result != Status.OK
