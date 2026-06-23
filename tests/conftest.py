"""Shared pytest fixtures."""

from __future__ import annotations

import asyncio
import socket
from collections.abc import Awaitable, Callable
from pathlib import Path

import pytest

from psysmon.checks.base import CheckContext

FIXTURES = Path(__file__).parent / "fixtures"


# --- config fixtures ------------------------------------------------------------------

@pytest.fixture
def sample_config_text() -> str:
    """Synthetic legacy config exercising every grammar feature (committed)."""
    return (FIXTURES / "legacy_sample.conf").read_text(encoding="utf-8")


@pytest.fixture
def production_config_text() -> str:
    """The real production ``sysmon.conf`` for scale/smoke checks.

    Kept local-only (gitignored) because it contains live customer data and credentials, so
    it is absent in CI — tests that use it are skipped when the file isn't present.
    """
    path = FIXTURES / "production.conf"
    if not path.exists():
        pytest.skip("production.conf not present (local-only fixture)")
    return path.read_text(encoding="utf-8", errors="replace")


# --- check fixtures (shared by all checks tests) --------------------------------------

class FakeResolver:
    """Resolver that maps hostnames to fixed IPs (defaults everything to loopback)."""

    def __init__(
        self, mapping: dict[str, str | None] | None = None, default: str | None = "127.0.0.1"
    ):
        self._mapping = mapping or {}
        self._default = default

    async def resolve(self, hostname: str) -> str | None:
        return self._mapping.get(hostname, self._default)


@pytest.fixture
def check_ctx() -> CheckContext:
    """A CheckContext whose resolver points every host at loopback, short timeout."""
    return CheckContext(resolver=FakeResolver(), timeout_s=2.0)


ServerHandler = Callable[[asyncio.StreamReader, asyncio.StreamWriter], Awaitable[None]]


@pytest.fixture
async def tcp_server():
    """Start loopback TCP servers on demand; returns ``await start(handler) -> port``.

    Point a node at ``127.0.0.1`` (the default FakeResolver) with ``port`` to probe it.
    """
    servers: list[asyncio.AbstractServer] = []

    async def start(handler: ServerHandler) -> int:
        server = await asyncio.start_server(handler, "127.0.0.1", 0)
        servers.append(server)
        return server.sockets[0].getsockname()[1]

    yield start

    for server in servers:
        server.close()
        await server.wait_closed()


@pytest.fixture
def free_port() -> int:
    """An unused localhost TCP port (for connection-refused style tests)."""
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]
