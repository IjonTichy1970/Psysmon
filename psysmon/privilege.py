"""Privilege handling (Milestone 7).

The daemon is started setuid root so it can open a raw ICMP socket; this module opens that
socket and then **drops** to an unprivileged uid/gid, keeping the socket FD open across the
drop. (Narrowing to ``CAP_NET_RAW`` instead of full root is tracked in security issue #2.)

The ``grp``/``pwd``/``os.setuid`` machinery is POSIX-only, so the imports and calls are guarded
to keep this module importable on Windows (where it is a no-op that raises a clear error if a
drop is actually attempted).
"""

from __future__ import annotations

import os

try:  # POSIX-only: absent on Windows.
    import grp
    import pwd

    _HAVE_POSIX_IDS = True
except ImportError:  # pragma: no cover - exercised only on non-POSIX hosts.
    _HAVE_POSIX_IDS = False


class PrivilegeError(RuntimeError):
    """Raised when privileges cannot be dropped (wrong platform, not root, etc.)."""


def drop_privileges(user: str = "nobody", group: str = "nogroup") -> None:
    """Drop setgid/setuid to an unprivileged account, keeping already-open FDs.

    Must be called as root on a POSIX host. Raises :class:`PrivilegeError` if the platform
    lacks ``setuid``/``pwd``/``grp`` (e.g. Windows) or if the process is not running as root.
    """
    if not _HAVE_POSIX_IDS or not hasattr(os, "setuid"):
        raise PrivilegeError("privilege drop is only supported on POSIX systems")

    if os.geteuid() != 0:
        raise PrivilegeError("must be root to drop privileges")

    gid = grp.getgrnam(group).gr_gid
    uid = pwd.getpwnam(user).pw_uid

    # Order matters: drop supplementary groups and gid before uid, or setgid would fail once
    # we are no longer root.
    os.setgroups([])
    os.setgid(gid)
    os.setuid(uid)
