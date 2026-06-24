"""Bearer-token loading + constant-time comparison for the control channel (#69).

The token gates *mutating* actions (ack/note/reload). It is read from a file (not a CLI flag,
to keep it out of ``ps``/``/proc``), and the file is checked for unsafe permissions on the open
descriptor (no TOCTOU/symlink window). Comparison is constant-time and fails closed.
"""

from __future__ import annotations

import hmac
import logging
import os

log = logging.getLogger("psysmon.control")

_MAX_TOKEN_LEN = 4096  # bound both the token we read and a token we're handed (DoS / abuse guard)


class TokenError(Exception):
    """The configured token file could not be loaded safely (refuse to start the channel)."""


def load_token(path: str) -> str:
    """Read the bearer token from ``path``, refusing an unsafe file.

    Opens with ``O_NOFOLLOW`` (POSIX) so a symlink is refused, and checks permissions via
    ``fstat`` on the *open* descriptor — the file we actually read, not a name that could be
    swapped. A group/world-accessible file is rejected on POSIX; on platforms without meaningful
    mode bits (Windows) the check is skipped with a loud warning rather than a silent "trust".
    """
    flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0)
    try:
        fd = os.open(path, flags)
    except OSError as exc:
        raise TokenError(f"cannot open control token file {path!r}: {exc}") from exc
    try:
        st = os.fstat(fd)
        if os.name == "posix":
            if st.st_mode & 0o077:
                raise TokenError(
                    f"control token file {path!r} is group/world-accessible "
                    f"(mode {st.st_mode & 0o777:o}); restrict it to 0600"
                )
        else:
            log.warning(
                "psysmon: cannot verify control-token file permissions on this platform; "
                "ensure %r is readable only by the daemon user", path
            )
        data = os.read(fd, _MAX_TOKEN_LEN + 1)
    finally:
        os.close(fd)
    if len(data) > _MAX_TOKEN_LEN:
        raise TokenError(f"control token file {path!r} is too large")
    try:
        token = data.decode("utf-8").strip()
    except UnicodeDecodeError as exc:
        raise TokenError(f"control token file {path!r} is not valid UTF-8") from exc
    if not token:
        raise TokenError(f"control token file {path!r} is empty")
    return token


def token_matches(provided: object, expected: str) -> bool:
    """Constant-time check that ``provided`` equals ``expected``.

    Returns ``False`` (never raises) for a missing, oversized, or non-string token, so a
    malformed request fails closed rather than erroring.
    """
    if not isinstance(provided, str) or len(provided) > _MAX_TOKEN_LEN:
        return False
    return hmac.compare_digest(provided, expected)
