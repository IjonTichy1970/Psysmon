"""Tests for status codes and their display strings (ported from lib.c)."""

from __future__ import annotations

import pytest

from sysmon.status import Status, errtostr, is_up


def test_ok_is_zero_and_up():
    assert Status.OK == 0
    assert is_up(Status.OK)
    assert not is_up(Status.UNPINGABLE)


@pytest.mark.parametrize(
    ("code", "text"),
    [
        (Status.OK, "up"),
        (Status.CONN_REFUSED, "Conn Ref"),
        (Status.NET_UNREACH, "Net Unrch"),
        (Status.HOST_DOWN, "Host Down"),
        (Status.TIMED_OUT, "Conn Timed Out"),
        (Status.NO_DNS, "No dns entry"),
        (Status.UNPINGABLE, "Unpingable"),
        (Status.THROTTLED, "Thrttl"),
        (Status.NO_AUTH, "No Auth"),
        (Status.NO_RESPONSE, "No Srvr Resp"),
        (Status.IN_PROGRESS, "Conn in prog"),
        (Status.BAD_AUTH, "Bad Auth"),
        (Status.BAD_RESPONSE, "Bad Resp"),
        (Status.X500_WEDGED, "Wedged"),
    ],
)
def test_errtostr_matches_legacy(code, text):
    assert errtostr(code) == text


def test_errtostr_unknown():
    assert errtostr(999) == "ERROR"


def test_status_values_are_stable():
    # The integer values are a compatibility contract with the original config.h.
    assert [s.value for s in Status] == list(range(14))
