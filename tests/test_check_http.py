"""Tests for the http/https content check.

Hermetic: no real network or TLS. We inject an ``httpx.MockTransport`` via the module's
``_TRANSPORT`` hook so the check exercises real httpx request/response plumbing against a
canned handler.
"""

from __future__ import annotations

import httpx
import pytest

from psysmon.checks import base, http
from psysmon.config.model import CheckType, Node
from psysmon.status import Status

from .conftest import FakeResolver


def node(check_type=CheckType.HTTP, port=80, url="/", url_text="hello"):
    return Node(
        hostname="web.example",
        check_type=check_type,
        port=port,
        url=url,
        url_text=url_text,
    )


@pytest.fixture
def mock_transport(monkeypatch):
    """Install an httpx.MockTransport built from a handler onto http._TRANSPORT."""

    def install(handler):
        monkeypatch.setattr(http, "_TRANSPORT", httpx.MockTransport(handler))

    return install


async def test_ok_2xx_with_matching_text(check_ctx, mock_transport):
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, text="say hello world")

    mock_transport(handler)
    assert await http.check(node(url_text="hello"), check_ctx) == Status.OK


async def test_bad_response_2xx_missing_text(check_ctx, mock_transport):
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, text="nothing to see")

    mock_transport(handler)
    assert await http.check(node(url_text="hello"), check_ctx) == Status.BAD_RESPONSE


async def test_bad_response_on_500(check_ctx, mock_transport):
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(500, text="hello")

    mock_transport(handler)
    assert await http.check(node(url_text="hello"), check_ctx) == Status.BAD_RESPONSE


async def test_reachability_ok_on_401_without_urltext(check_ctx, mock_transport):
    # No urltext (url_text=None) -> any HTTP status is up, incl. an auth-required 401 (#104).
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(401, text="Unauthorized")

    mock_transport(handler)
    assert await http.check(node(url_text=None), check_ctx) == Status.OK


async def test_reachability_ok_on_500_without_urltext(check_ctx, mock_transport):
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(500, text="kaboom")

    mock_transport(handler)
    assert await http.check(node(url_text=None), check_ctx) == Status.OK


async def test_reachability_still_needs_an_http_response(check_ctx, mock_transport):
    # Reachability mode is not a bare TCP check: a connect failure (no HTTP reply) is still down.
    def handler(request: httpx.Request) -> httpx.Response:
        raise httpx.ConnectError("refused", request=request)

    mock_transport(handler)
    assert await http.check(node(url_text=None), check_ctx) == Status.CONN_REFUSED


async def test_connect_error_maps_conn_refused(check_ctx, mock_transport):
    def handler(request: httpx.Request) -> httpx.Response:
        raise httpx.ConnectError("refused", request=request)

    mock_transport(handler)
    assert await http.check(node(), check_ctx) == Status.CONN_REFUSED


async def test_timeout_maps_timed_out(check_ctx, mock_transport):
    def handler(request: httpx.Request) -> httpx.Response:
        raise httpx.ConnectTimeout("slow", request=request)

    mock_transport(handler)
    assert await http.check(node(), check_ctx) == Status.TIMED_OUT


async def test_other_http_error_maps_bad_response(check_ctx, mock_transport):
    def handler(request: httpx.Request) -> httpx.Response:
        raise httpx.ReadError("boom", request=request)

    mock_transport(handler)
    assert await http.check(node(), check_ctx) == Status.BAD_RESPONSE


async def test_https_uses_https_scheme(check_ctx, mock_transport):
    seen = {}

    def handler(request: httpx.Request) -> httpx.Response:
        seen["url"] = str(request.url)
        return httpx.Response(200, text="hello")

    mock_transport(handler)
    # Non-default port so it survives httpx URL normalization, proving the scheme is https.
    n = node(check_type=CheckType.HTTPS, port=8443, url="/path", url_text="hello")
    assert await http.check(n, check_ctx) == Status.OK
    assert seen["url"] == "https://web.example:8443/path"


async def test_http_url_is_built_from_fields(check_ctx, mock_transport):
    seen = {}

    def handler(request: httpx.Request) -> httpx.Response:
        seen["url"] = str(request.url)
        return httpx.Response(200, text="hello")

    mock_transport(handler)
    n = node(check_type=CheckType.HTTP, port=8080, url="/status", url_text="hello")
    assert await http.check(n, check_ctx) == Status.OK
    assert seen["url"] == "http://web.example:8080/status"


async def test_perform_passthrough_ok(check_ctx, mock_transport):
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, text="hello there")

    mock_transport(handler)
    assert await base.perform(http.check, node(url_text="hello"), check_ctx) == Status.OK


async def test_perform_maps_no_dns(mock_transport):
    # The check itself resolves first (base contract): an unresolvable host must surface as
    # NO_DNS via base.perform, without ever issuing the HTTP request.
    requested = False

    def handler(request: httpx.Request) -> httpx.Response:
        nonlocal requested
        requested = True
        return httpx.Response(200, text="hello")

    mock_transport(handler)
    ctx = base.CheckContext(resolver=FakeResolver(default=None))
    assert await base.perform(http.check, node(), ctx) == Status.NO_DNS
    assert requested is False  # resolution failed before any GET
