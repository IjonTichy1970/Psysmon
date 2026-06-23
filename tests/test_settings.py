"""Tests for settings precedence (CLI > config file > defaults) and CLI parsing."""

from __future__ import annotations

import pytest

from psysmon.config.settings import Settings, cli_overrides, load, merge

# --- defaults -------------------------------------------------------------------------

def test_merge_no_overrides_is_defaults():
    assert merge() == Settings()
    assert merge(None, None) == Settings()


def test_defaults_sane():
    s = Settings()
    assert s.interval_s == 30.0
    assert s.numfailures == 2
    assert s.status_html is True
    assert s.notify_enabled is True
    assert s.foreground is False


# --- layering / precedence ------------------------------------------------------------

def test_file_overrides_defaults():
    s = merge(file_overrides={"interval_s": 60.0, "numfailures": 5})
    assert s.interval_s == 60.0
    assert s.numfailures == 5
    assert s.max_concurrency == Settings().max_concurrency  # untouched


def test_cli_overrides_file():
    s = merge(file_overrides={"interval_s": 60.0}, cli_overrides={"interval_s": 5.0})
    assert s.interval_s == 5.0  # CLI wins


def test_unset_cli_falls_through_to_file():
    # CLI did not set interval_s, so the config-file value stands.
    s = merge(file_overrides={"interval_s": 60.0}, cli_overrides={"numfailures": 9})
    assert s.interval_s == 60.0
    assert s.numfailures == 9


def test_unknown_key_rejected():
    with pytest.raises(ValueError, match="bogus"):
        merge(file_overrides={"bogus": 1})
    with pytest.raises(ValueError, match="CLI"):
        merge(cli_overrides={"nope": 1})


# --- CLI parsing: only explicitly-set options appear ----------------------------------

def test_cli_overrides_empty():
    assert cli_overrides([]) == {}


def test_cli_overrides_only_set():
    assert cli_overrides(["--interval", "15"]) == {"interval_s": 15.0}


def test_cli_direct_fields():
    got = cli_overrides(
        ["-f", "/tmp/x.conf", "--source-ip", "10.0.0.1", "--smtp-host", "mail.example.net",
         "--smtp-port", "2525", "--numfailures", "7", "--max-concurrency", "100"]
    )
    assert got == {
        "config_path": "/tmp/x.conf",
        "source_ip": "10.0.0.1",
        "smtp_host": "mail.example.net",
        "smtp_port": 2525,
        "numfailures": 7,
        "max_concurrency": 100,
    }


# --- CLI parsing: translated options --------------------------------------------------

def test_status_format_translation():
    assert cli_overrides(["--status-format", "text"]) == {"status_html": False}
    assert cli_overrides(["--status-format", "html"]) == {"status_html": True}


def test_boolean_flags_translation():
    assert cli_overrides(["--no-notify"]) == {"notify_enabled": False}
    assert cli_overrides(["--no-fork"]) == {"foreground": True}
    assert cli_overrides(["--show-up"]) == {"show_up_also": True}
    assert cli_overrides(["-n", "-d"]) == {"notify_enabled": False, "foreground": True}


def test_invalid_choice_errors():
    with pytest.raises(SystemExit):
        cli_overrides(["--status-format", "xml"])


def test_invalid_int_errors():
    with pytest.raises(SystemExit):
        cli_overrides(["--smtp-port", "notaport"])


# --- load(): end-to-end ---------------------------------------------------------------

def test_load_merges_cli_over_file_over_defaults():
    s = load(
        ["--interval", "5", "--no-notify"],
        file_overrides={"interval_s": 60.0, "numfailures": 5, "status_path": "/var/www/s.html"},
    )
    assert s.interval_s == 5.0  # CLI beats file
    assert s.numfailures == 5  # file beats default
    assert s.status_path == "/var/www/s.html"  # file beats default
    assert s.notify_enabled is False  # CLI flag
    assert s.smtp_host == "localhost"  # default stands


def test_load_version_exits(capsys):
    with pytest.raises(SystemExit) as exc:
        load(["--version"])
    assert exc.value.code == 0
    assert "psysmon" in capsys.readouterr().out
