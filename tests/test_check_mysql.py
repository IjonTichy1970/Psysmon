"""Tests for the MySQL/MariaDB initial-handshake check (#97)."""

from __future__ import annotations

import asyncio

from psysmon.checks import base, mysql
from psysmon.config.model import CheckType, Node
from psysmon.status import Status

from .conftest import FakeResolver


def node(host="db.example.net", port=3306):
    return Node(hostname=host, check_type=CheckType.MYSQL, port=port)


def _packet(payload: bytes, seq: int = 0) -> bytes:
    """A MySQL wire packet: 3-byte little-endian payload length + 1-byte sequence id + payload."""
    return len(payload).to_bytes(3, "little") + bytes([seq]) + payload


async def _bytes_handler(data: bytes):
    async def handler(reader, writer):
        writer.write(data)
        await writer.drain()
        writer.close()
        await writer.wait_closed()

    return handler


async def test_ok_on_handshake_v10(check_ctx, tcp_server):
    payload = b"\x0a" + b"8.0.36\x00" + b"\x00" * 20  # protocol_version 10 + server-version string
    port = await tcp_server(await _bytes_handler(_packet(payload)))
    assert await mysql.check(node(port=port), check_ctx) == Status.OK


async def test_ok_on_handshake_v9(check_ctx, tcp_server):
    port = await tcp_server(await _bytes_handler(_packet(b"\x09" + b"3.23\x00")))
    assert await mysql.check(node(port=port), check_ctx) == Status.OK


async def test_ok_on_error_packet(check_ctx, tcp_server):
    # An ERR packet (0xff) — the server speaks MySQL but is refusing this connection; still up.
    port = await tcp_server(await _bytes_handler(_packet(b"\xff\x69\x04Host not allowed")))
    assert await mysql.check(node(port=port), check_ctx) == Status.OK


async def test_bad_response_on_non_mysql(check_ctx, tcp_server):
    # A well-formed packet whose payload doesn't start with a known marker.
    port = await tcp_server(await _bytes_handler(_packet(b"\x42garbage")))
    assert await mysql.check(node(port=port), check_ctx) == Status.BAD_RESPONSE


async def test_bad_response_on_zero_length_packet(check_ctx, tcp_server):
    port = await tcp_server(await _bytes_handler(b"\x00\x00\x00\x00"))  # header with length 0
    assert await mysql.check(node(port=port), check_ctx) == Status.BAD_RESPONSE


async def test_no_response_on_short_header(check_ctx, tcp_server):
    port = await tcp_server(await _bytes_handler(b"\x05\x00"))  # fewer than the 4 header bytes
    assert await mysql.check(node(port=port), check_ctx) == Status.NO_RESPONSE


async def test_no_response_on_immediate_close(check_ctx, tcp_server):
    async def handler(reader, writer):
        writer.close()
        await writer.wait_closed()

    port = await tcp_server(handler)
    assert await mysql.check(node(port=port), check_ctx) == Status.NO_RESPONSE


async def test_ok_on_handshake_split_across_writes(check_ctx, tcp_server):
    # The header and protocol-version byte arrive in separate writes; readexactly reassembles them.
    pkt = _packet(b"\x0a8.0.36\x00" + b"\x00" * 20)

    async def handler(reader, writer):
        writer.write(pkt[:2])
        await writer.drain()
        await asyncio.sleep(0)
        writer.write(pkt[2:])
        await writer.drain()
        writer.close()
        await writer.wait_closed()

    port = await tcp_server(handler)
    assert await mysql.check(node(port=port), check_ctx) == Status.OK


async def test_no_response_on_close_after_header(check_ctx, tcp_server):
    # A complete 4-byte header declaring a payload, then a close before the payload byte: the second
    # readexactly raises IncompleteReadError -> NO_RESPONSE.
    port = await tcp_server(await _bytes_handler(b"\x05\x00\x00\x00"))  # length 5, no payload
    assert await mysql.check(node(port=port), check_ctx) == Status.NO_RESPONSE


async def test_perform_conn_refused(free_port):
    ctx = base.CheckContext(resolver=FakeResolver(), timeout_s=10.0)
    assert await base.perform(mysql.check, node(port=free_port), ctx) == Status.CONN_REFUSED
