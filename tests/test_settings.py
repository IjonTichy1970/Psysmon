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


# --- logging verbosity + new knobs (#59) ----------------------------------------------

def test_logging_defaults():
    s = Settings()
    assert (s.log_level, s.heartbeat_s, s.slow_check_s) == ("info", 300, 30.0)


def test_verbose_flags_map_to_log_level():
    assert cli_overrides(["-v"]) == {"log_level": "info"}
    assert cli_overrides(["-vv"]) == {"log_level": "debug"}
    assert cli_overrides(["-vvv"]) == {"log_level": "debug"}  # caps at debug


def test_explicit_log_level_beats_verbose():
    # --log-level is authoritative even if -v is also present.
    assert cli_overrides(["--log-level", "warning", "-vv"]) == {"log_level": "warning"}


def test_log_level_invalid_choice_errors():
    with pytest.raises(SystemExit):
        cli_overrides(["--log-level", "trace"])


def test_new_logging_knobs_parse():
    assert cli_overrides(["--heartbeat", "60"]) == {"heartbeat_s": 60}
    assert cli_overrides(["--slow-check", "5"]) == {"slow_check_s": 5.0}


def test_state_persistence_flags_parse():
    assert cli_overrides(["--state-file", "/tmp/s.json"]) == {"state_path": "/tmp/s.json"}
    assert cli_overrides(["--state-save-interval", "30"]) == {"statesave_s": 30}
    assert cli_overrides(["--state-max-age", "0"]) == {"state_max_age_s": 0}


def test_loss_tolerant_ping_flags_parse():
    assert cli_overrides(["--send-pings", "5"]) == {"send_pings": 5}
    assert cli_overrides(["--min-pings", "3"]) == {"min_pings": 3}
    assert cli_overrides(["--page-on-degraded"]) == {"page_on_degraded": True}
    # absent -> not overridden (default False stands)
    assert "page_on_degraded" not in cli_overrides([])
