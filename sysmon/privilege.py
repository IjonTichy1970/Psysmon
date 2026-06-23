"""Privilege handling (Milestone 7).

The daemon is started setuid root so it can open a raw ICMP socket; this module opens that
socket and then **drops** to an unprivileged uid/gid, keeping the socket FD open across the
drop. (Narrowing to ``CAP_NET_RAW`` instead of full root is tracked in security issue #2.)

Not yet implemented.
"""

from __future__ import annotations


def drop_privileges(user: str = "nobody", group: str = "nogroup") -> None:
    """Drop setuid/setgid to an unprivileged account, keeping already-open FDs."""
    raise NotImplementedError("Milestone 7: privilege drop")
