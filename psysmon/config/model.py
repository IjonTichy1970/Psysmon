"""Core data model: the monitored tree (``Node``) and per-node runtime state (``NodeState``).

Ported from the original C ``struct hostinfo`` (config.h), split into the *static*
configuration (``Node``) and the *mutable* runtime state (``NodeState``) so the state
machine can be tested in isolation from parsing and I/O.

The tree mirrors the original ``child``/``sibling`` linked structure: ``Node.children`` are
the hosts/services reachable only when this node (a ping target) is up — the basis for
dependency suppression.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import StrEnum


class CheckType(StrEnum):
    """Check types in scope for the rewrite.

    Values are the legacy ``sysmon.conf`` keywords. (Dropped legacy types — imap, nntp,
    radius, umichX500, snmp, pop2, bootp — are intentionally absent; the parser warns and
    skips them.)
    """

    PING = "ping"
    TCP = "tcp"
    UDP = "udp"
    SMTP = "smtp"
    POP3 = "pop3"
    DNS = "dns"  # authoritative DNS query (legacy "authdns")
    HTTP = "http"  # legacy "www" content check
    HTTPS = "https"


# Default port per type (None = not applicable or supplied explicitly in config).
DEFAULT_PORT: dict[CheckType, int | None] = {
    CheckType.PING: None,
    CheckType.TCP: None,  # required in config
    CheckType.UDP: None,  # required in config
    CheckType.SMTP: 25,
    CheckType.POP3: 110,
    CheckType.DNS: 53,
    CheckType.HTTP: 80,
    CheckType.HTTPS: 443,
}

# type_to_name() display strings from the original lib.c (used in the status file).
_DISPLAY_NAME: dict[CheckType, str] = {
    CheckType.PING: "ping",
    CheckType.TCP: "tcp",
    CheckType.UDP: "udp",
    CheckType.SMTP: "smtp",
    CheckType.POP3: "pop3",
    CheckType.DNS: "authdns",
    CheckType.HTTP: "www",
    CheckType.HTTPS: "https",
}


def type_to_name(check_type: CheckType) -> str:
    """Display name for a check type, matching the original status-file column."""
    return _DISPLAY_NAME[check_type]


# Which state transitions trigger a page. "both" is psysmon's historical behavior (page on a
# host going down AND on its recovery); "down"/"up" page on only that transition; "none" never
# pages. Used as the per-object `contact_on` attr and the global `config contact_on` default.
CONTACT_ON_CHOICES = ("down", "up", "both", "none")


@dataclass(slots=True)
class Node:
    """A monitored host or service (static configuration).

    One ``Node`` per config stanza. ``children`` are nodes reachable only when this node is
    up (dependency suppression); they correspond to the original ``{ }`` nesting.
    """

    hostname: str
    check_type: CheckType
    port: int = 0
    label: str = ""  # the original "message" field
    contact: str = ""  # notification address ("" = no page, syslog only)
    group: str = ""  # operator grouping label (modern `group "..."` attr; display use is #20)
    contact_on: str = ""  # which transitions page (down|up|both|none); "" = use the global default
    username: str = ""  # pop3 auth
    password: str = ""  # pop3 auth
    url: str = ""  # http/https path
    url_text: str = ""  # substring that must appear in the http/https body
    max_down: int = 2  # numfailures in effect when parsed (position-dependent)
    interval: float | None = None  # per-host check interval; None = use global default
    # Loss-tolerant ping (#22): send this many echoes, require this many replies to count up.
    # None = use the global default (1/1, i.e. today's first-reply-wins behavior). The legacy
    # positional grammar has no slot for these, so they arrive only via CLI/global config today.
    send_pings: int | None = None
    min_pings: int | None = None
    children: list[Node] = field(default_factory=list)


@dataclass(slots=True)
class NodeState:
    """Mutable per-node runtime state (the live fields of ``struct hostinfo``).

    Driven by :mod:`psysmon.engine.state`. ``contacted`` is set by the *notifier* (the act
    of paging is the dedup point), never by the state machine.
    """

    max_down: int = 2
    lastcheck: int = 0  # last Status code (0 == up)
    downct: int = 0  # consecutive failed checks
    contacted: bool = False  # have we paged about the current outage?
    lastcontacted: float = 0.0  # monotonic time of last page (for re-page interval)
    deathtime: float = 0.0  # wall-clock time the current outage began
    last_up: float = 0.0  # wall-clock time it was last seen up
    suppressed: bool = False  # currently gated off by a down ancestor ping
