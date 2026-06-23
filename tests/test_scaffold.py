"""Smoke tests: the whole package imports, and the CLI exposes --version."""

from __future__ import annotations

import importlib

import pytest

MODULES = [
    "sysmon",
    "sysmon.__main__",
    "sysmon.status",
    "sysmon.privilege",
    "sysmon.config.model",
    "sysmon.config.legacy",
    "sysmon.config.detect",
    "sysmon.config.settings",
    "sysmon.engine.clock",
    "sysmon.engine.state",
    "sysmon.engine.scheduler",
    "sysmon.engine.dnscache",
    "sysmon.checks.base",
    "sysmon.checks.ping",
    "sysmon.checks.tcp",
    "sysmon.checks.udp",
    "sysmon.checks.smtp",
    "sysmon.checks.pop3",
    "sysmon.checks.dns",
    "sysmon.checks.http",
    "sysmon.notify.base",
    "sysmon.notify.email_smtp",
    "sysmon.output.statuspage",
    "sysmon.output.jsonout",
]


@pytest.mark.parametrize("name", MODULES)
def test_module_imports(name):
    importlib.import_module(name)


def test_version_flag(capsys):
    from sysmon.__main__ import main

    with pytest.raises(SystemExit) as exc:
        main(["--version"])
    assert exc.value.code == 0
    assert "sysmon" in capsys.readouterr().out


def test_manual_clock_advances():
    from sysmon.engine.clock import ManualClock

    c = ManualClock()
    c.advance(5)
    assert c.monotonic() == 5
