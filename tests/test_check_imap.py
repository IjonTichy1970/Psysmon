"""Tests for the IMAP greeting + optional LOGIN check (#88).

Drives the real checker against a loopback server (plaintext; the implicit-TLS wrapping for the
IMAPS type is covered in test_check_base). Mirrors the SMTP/POP3 check tests.
"""

from __future__ import annotations

from psysmon.checks import base, imap
from psysmon.config.model import CheckType, Node
from psysmon.status import Status

from .conftest import FakeResolver


def node(host="mail.example.net", port=143, *, user="", pw=""):
    return Node(hostname=host, check_type=CheckType.IMAP, port=port, username=user, password=pw)


async def _greeting_only(text: bytes):
    async def handler(reader, writer):
        writer.write(text)
        await writer.drain()
        await reader.readline()  # wait for the client to close (or send LOGOUT), then tear down
        writer.close()
        await writer.wait_closed()

    return handler


async def test_banner_ok(check_ctx, tcp_server):
    port = await tcp_server(await _greeting_only(b"* OK [CAPABILITY IMAP4rev1] ready\r\n"))
    assert await imap.check(node(port=port), check_ctx) == Status.OK


async def test_preauth_is_ok(check_ctx, tcp_server):
    port = await tcp_server(await _greeting_only(b"* PREAUTH ready, already authenticated\r\n"))
    assert await imap.check(node(port=port), check_ctx) == Status.OK


async def test_bye_greeting_is_bad_response(check_ctx, tcp_server):
    port = await tcp_server(await _greeting_only(b"* BYE shutting down\r\n"))
    assert await imap.check(node(port=port), check_ctx) == Status.BAD_RESPONSE


async def test_immediate_close_is_no_response(check_ctx, tcp_server):
    async def handler(reader, writer):
        writer.close()
        await writer.wait_closed()

    port = await tcp_server(handler)
    assert await imap.check(node(port=port), check_ctx) == Status.NO_RESPONSE


async def _login_handler(login_reply: bytes, *, extra_untagged: bytes = b""):
    async def handler(reader, writer):
        writer.write(b"* OK ready\r\n")
        await writer.drain()
        login = await reader.readline()
        assert login.startswith(b'a1 LOGIN "')  # quoted args, so a space in a credential is safe
        writer.write(extra_untagged + login_reply)
        await writer.drain()
        await reader.readline()  # consume the LOGOUT, if any
        writer.close()
        await writer.wait_closed()

    return handler


async def test_login_ok(check_ctx, tcp_server):
    port = await tcp_server(await _login_handler(b"a1 OK LOGIN completed\r\n"))
    assert await imap.check(node(port=port, user="u", pw="p"), check_ctx) == Status.OK


async def test_login_no_is_bad_auth(check_ctx, tcp_server):
    port = await tcp_server(await _login_handler(b"a1 NO [AUTHENTICATIONFAILED] bad creds\r\n"))
    assert await imap.check(node(port=port, user="u", pw="p"), check_ctx) == Status.BAD_AUTH


async def test_login_bad_is_bad_response(check_ctx, tcp_server):
    port = await tcp_server(await _login_handler(b"a1 BAD malformed command\r\n"))
    assert await imap.check(node(port=port, user="u", pw="p"), check_ctx) == Status.BAD_RESPONSE


async def test_login_skips_untagged_lines(check_ctx, tcp_server):
    # An untagged `*` line before the tagged result must be skipped, not mistaken for the result.
    port = await tcp_server(await _login_handler(
        b"a1 OK done\r\n", extra_untagged=b"* CAPABILITY IMAP4rev1\r\n"))
    assert await imap.check(node(port=port, user="u", pw="p"), check_ctx) == Status.OK


async def test_login_dropped_is_no_response(check_ctx, tcp_server):
    async def handler(reader, writer):
        writer.write(b"* OK ready\r\n")
        await writer.drain()
        await reader.readline()  # read LOGIN, then drop before the tagged result
        writer.close()
        await writer.wait_closed()

    port = await tcp_server(handler)
    assert await imap.check(node(port=port, user="u", pw="p"), check_ctx) == Status.NO_RESPONSE


async def test_perform_conn_refused(free_port):
    ctx = base.CheckContext(resolver=FakeResolver(), timeout_s=10.0)
    assert await base.perform(imap.check, node(port=free_port), ctx) == Status.CONN_REFUSED


async def test_perform_no_dns(free_port):
    ctx = base.CheckContext(resolver=FakeResolver(default=None), timeout_s=2.0)
    assert await base.perform(imap.check, node(port=free_port), ctx) == Status.NO_DNS
