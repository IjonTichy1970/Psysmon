"""Runtime settings and the CLI > config-file > defaults precedence chain.

Holds the values that were hardcoded in the original C (source IP, org hostname, mail
transport, status-file path, ports, intervals, thresholds) so they can come from the config
file *or* the command line, with the command line winning.

The ``Settings`` dataclass and its defaults are defined here; ``merge`` (argparse parsing +
layering, Milestone 2) is not yet implemented.
"""

from __future__ import annotations

from dataclasses import dataclass


@dataclass(slots=True)
class Settings:
    """Effective runtime configuration after merging CLI, file, and defaults."""

    # Files / output
    config_path: str = "/etc/sysmon.conf"
    status_path: str | None = None  # set by `config statusfile`
    status_html: bool = True  # html vs flat text
    status_refresh_s: int = 30  # HTML meta-refresh
    show_up_also: bool = False  # default view is down-only ("Bad Hosts")

    # Identity / network (formerly hardcoded)
    source_ip: str | None = None  # outbound bind source (ACL-load-bearing)
    org_hostname: str | None = None  # shown in alerts and the status page title

    # Scheduling
    interval_s: float = 30.0  # default per-host check interval
    max_concurrency: int = 50  # bound on concurrent socket/protocol checks
    numfailures: int = 2  # default threshold before paging
    pageinterval_min: int = 10  # re-page interval while down (minutes)

    # DNS cache
    dnsexpire_s: int = 900
    dnslog_s: int = 600

    # Alerting (SMTP)
    smtp_host: str = "localhost"
    smtp_port: int = 25
    mail_from: str | None = None
    notify_enabled: bool = True  # `-n` / donotify disables paging

    # Logging
    syslog_facility: str | None = "daemon"  # None / "none" disables syslog


def merge(argv: list[str] | None = None) -> Settings:
    """Build effective ``Settings`` from CLI args, the config file, and built-in defaults.

    Precedence: CLI > config file > defaults. Uses argparse with suppressed defaults so an
    *unset* CLI flag is distinguishable from one that matches a default.
    """
    raise NotImplementedError("Milestone 2: settings precedence")
