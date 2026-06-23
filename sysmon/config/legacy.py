"""Parser for the original ``sysmon.conf`` grammar (Milestone 3).

Faithfully reproduces ``loadconfig.c``/``parseline``:

* Lines are whitespace-tokenized (up to 7 tokens, like ``sscanf("%s"*7)``).
* A line whose first token starts with ``;`` or ``#`` is a comment; blank lines are skipped.
* ``}`` closes the current block; a trailing ``{`` opens a recursive **child block**.
* ``config <directive> ...`` sets globals: ``statusfile``, ``pageinterval`` (minutes),
  ``logging``, ``dnslog``, ``dnsexpire``, ``numfailures``, ``sleeptime``.
* **``numfailures`` is position-dependent** — its current value snapshots into each
  subsequently-parsed node's ``max_down`` (thread a running value; do NOT take last-wins).
* Per-type field positions exactly as in C (ping: label[,contact]; tcp/udp: port,label[,
  contact]; smtp falls in the ping-like branch; www/https: url,url_text,label[,contact];
  pop3: user,pass,label[,contact]).
* Dropped legacy types (imap, nntp, radius, umichx500, snmp, pop2, bootp) -> warn and skip;
  never hard-fail a legacy file.

Unlike the C, DNS resolution is **deferred to runtime** — unresolvable hosts still produce a
node (no silent drop).

Not yet implemented.
"""

from __future__ import annotations

from sysmon.config.model import Node
from sysmon.config.settings import Settings


def parse(text: str, settings: Settings) -> list[Node]:
    """Parse legacy config ``text`` into a forest of root ``Node``s.

    Mutates ``settings`` in place for the global ``config`` directives encountered.
    """
    raise NotImplementedError("Milestone 3: legacy config parser")
