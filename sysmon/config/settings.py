"""Runtime settings and the CLI > config-file > defaults precedence chain.

Holds the values that were hardcoded in the original C (source IP, org hostname, mail
transport, status-file path, ports, intervals, thresholds) so they can come from the config
file *or* the command line, with the command line winning.

Layering:

* ``Settings()`` carries the built-in defaults.
* The legacy parser (Milestone 3) produces a dict of *config-file* overrides from the
  ``config <directive>`` lines.
* :func:`cli_overrides` parses the command line into a dict of *only the explicitly-set*
  options (argparse with suppressed defaults), so an unset flag is distinguishable from one
  that merely matches a default.
* :func:`merge` applies them in order — defaults < config file < CLI — and :func:`load` is
  the convenience that wires CLI parsing to the merge.
"""

from __future__ import annotations

import argparse
from dataclasses import dataclass, fields

from sysmon import __version__


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

    # Logging / process
    syslog_facility: str | None = "daemon"  # None / "none" disables syslog
    foreground: bool = False  # `-d` / don't fork


_FIELD_NAMES = frozenset(f.name for f in fields(Settings))


def build_parser() -> argparse.ArgumentParser:
    """Build the CLI parser.

    ``argument_default=SUPPRESS`` means unset options are *absent* from the parsed namespace,
    so :func:`cli_overrides` can return only what the user explicitly set. Options whose dest
    matches a :class:`Settings` field are applied directly; the rest (``status_format``,
    ``no_notify``, ``no_fork``, ``show_up``) are translated in :func:`cli_overrides`.
    """
    p = argparse.ArgumentParser(
        prog="sysmon",
        description="Dependency-aware network monitoring daemon.",
        argument_default=argparse.SUPPRESS,
    )
    p.add_argument("--version", action="version", version=f"sysmon {__version__}")

    # Files / output
    p.add_argument("-f", "--config", dest="config_path", metavar="PATH", help="config file path")
    p.add_argument("--status-file", dest="status_path", metavar="PATH", help="status output path")
    p.add_argument(
        "--status-format", dest="status_format", choices=["html", "text"], help="status file format"
    )
    p.add_argument(
        "--status-refresh", dest="status_refresh_s", type=int, metavar="SECONDS",
        help="HTML status auto-refresh interval",
    )
    p.add_argument(
        "--show-up", dest="show_up", action="store_true", help="list up hosts too (not just down)"
    )

    # Identity / network
    p.add_argument("--source-ip", dest="source_ip", metavar="IP", help="outbound bind source IP")
    p.add_argument(
        "--hostname", dest="org_hostname", metavar="NAME", help="hostname shown in alerts/status"
    )

    # Scheduling
    p.add_argument(
        "--interval", dest="interval_s", type=float, metavar="SEC", help="check interval"
    )
    p.add_argument(
        "--max-concurrency", dest="max_concurrency", type=int, metavar="N",
        help="concurrent check cap",
    )
    p.add_argument(
        "--numfailures", dest="numfailures", type=int, metavar="N", help="fails before page"
    )
    p.add_argument(
        "--pageinterval", dest="pageinterval_min", type=int, metavar="MIN", help="re-page interval"
    )

    # DNS cache
    p.add_argument("--dnsexpire", dest="dnsexpire_s", type=int, metavar="SEC", help="DNS cache TTL")
    p.add_argument("--dnslog", dest="dnslog_s", type=int, metavar="SEC", help="DNS stats interval")

    # Alerting
    p.add_argument("--smtp-host", dest="smtp_host", metavar="HOST", help="SMTP server host")
    p.add_argument(
        "--smtp-port", dest="smtp_port", type=int, metavar="PORT", help="SMTP server port"
    )
    p.add_argument("--mail-from", dest="mail_from", metavar="ADDR", help="alert From: address")
    p.add_argument("-n", "--no-notify", dest="no_notify", action="store_true", help="do not notify")

    # Logging / process
    p.add_argument(
        "--syslog-facility", dest="syslog_facility", metavar="FAC", help="syslog facility"
    )
    p.add_argument("-d", "--no-fork", dest="no_fork", action="store_true", help="run in foreground")
    return p


def cli_overrides(argv: list[str] | None = None) -> dict[str, object]:
    """Parse ``argv`` into a dict of only the explicitly-set :class:`Settings` fields.

    ``--version`` / ``--help`` raise ``SystemExit`` via argparse, as usual.
    """
    raw = vars(build_parser().parse_args(argv))
    out: dict[str, object] = {dest: val for dest, val in raw.items() if dest in _FIELD_NAMES}

    # Translate the options whose dest doesn't map 1:1 to a Settings field.
    if "status_format" in raw:
        out["status_html"] = raw["status_format"] == "html"
    if raw.get("no_notify"):
        out["notify_enabled"] = False
    if raw.get("no_fork"):
        out["foreground"] = True
    if raw.get("show_up"):
        out["show_up_also"] = True
    return out


def merge(
    file_overrides: dict[str, object] | None = None,
    cli_overrides: dict[str, object] | None = None,
) -> Settings:
    """Build effective ``Settings`` with precedence **CLI > config file > defaults**.

    Raises ``ValueError`` if a layer carries a key that isn't a ``Settings`` field (guards
    against parser/config bugs).
    """
    settings = Settings()
    for source, layer in (("config file", file_overrides), ("CLI", cli_overrides)):
        if not layer:
            continue
        for key, value in layer.items():
            if key not in _FIELD_NAMES:
                raise ValueError(f"unknown setting {key!r} from {source}")
            setattr(settings, key, value)
    return settings


def load(
    argv: list[str] | None = None, file_overrides: dict[str, object] | None = None
) -> Settings:
    """Top-level: parse the CLI and merge it over the config file and defaults.

    ``file_overrides`` come from the legacy parser (Milestone 3); until that lands callers
    pass them in directly (or ``None``).
    """
    return merge(file_overrides, cli_overrides(argv))
