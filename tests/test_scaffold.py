"""Smoke tests: the whole package imports, and the CLI exposes --version."""

from __future__ import annotations

import importlib

import pytest

MODULES = [
    "psysmon",
    "psysmon.__main__",
    "psysmon.status",
    "psysmon.privilege",
    "psysmon.config.model",
    "psysmon.config.legacy",
    "psysmon.config.detect",
    "psysmon.config.settings",
    "psysmon.engine.clock",
    "psysmon.engine.state",
    "psysmon.engine.scheduler",
    "psysmon.engine.dnscache",
    "psysmon.checks.base",
    "psysmon.checks.ping",
    "psysmon.checks.tcp",
    "psysmon.checks.udp",
    "psysmon.checks.smtp",
    "psysmon.checks.pop3",
    "psysmon.checks.dns",
    "psysmon.checks.http",
    "psysmon.notify.base",
    "psysmon.notify.email_smtp",
    "psysmon.output.statuspage",
    "psysmon.output.jsonout",
]


@pytest.mark.parametrize("name", MODULES)
def test_module_imports(name):
    importlib.import_module(name)


def test_version_flag(capsys):
    from psysmon.__main__ import main

    with pytest.raises(SystemExit) as exc:
        main(["--version"])
    assert exc.value.code == 0
    assert "psysmon" in capsys.readouterr().out


def test_manual_clock_advances():
    from psysmon.engine.clock import ManualClock

    c = ManualClock()
    c.advance(5)
    assert c.monotonic() == 5
