"""``psysmon-token`` — generate (or rotate) the control-channel bearer token (#69).

The daemon never auto-creates a token (a pip wheel has no install hook, and fail-closed is the
point): run this once at setup to write a ``0600`` token file, then point ``--control-token-file``
at it. Re-run with ``--force`` to rotate. With no path it just prints a fresh token to stdout.
"""

from __future__ import annotations

import argparse
import os
import secrets
import sys

_TOKEN_BYTES = 32  # secrets.token_urlsafe(32) -> ~43 url-safe chars (256 bits of entropy)


def generate(path: str, *, force: bool = False) -> str:
    """Write a fresh random token to ``path`` with ``0600`` perms; return the token.

    Created with ``O_CREAT | O_EXCL`` (refuses to clobber unless ``force``) and ``O_NOFOLLOW`` so a
    pre-placed symlink is never written through. Raises ``FileExistsError`` if the file exists and
    ``force`` is not set.
    """
    token = secrets.token_urlsafe(_TOKEN_BYTES)
    flags = os.O_WRONLY | os.O_CREAT | (os.O_TRUNC if force else os.O_EXCL)
    flags |= getattr(os, "O_NOFOLLOW", 0)
    fd = os.open(path, flags, 0o600)
    try:
        if hasattr(os, "fchmod"):
            os.fchmod(fd, 0o600)  # ensure 0600 even when rotating an existing (looser) file
        os.write(fd, (token + "\n").encode("utf-8"))
    finally:
        os.close(fd)
    return token


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(
        prog="psysmon-token",
        description="Generate (or rotate) the psysmon control-channel bearer token.",
    )
    ap.add_argument("path", nargs="?",
                    help="write the token here (0600); omit to print one to stdout")
    ap.add_argument("--force", action="store_true", help="overwrite an existing file (rotate)")
    args = ap.parse_args(argv)

    if args.path is None:
        print(secrets.token_urlsafe(_TOKEN_BYTES))
        return 0
    try:
        generate(args.path, force=args.force)
    except FileExistsError:
        print(f"psysmon-token: {args.path} already exists; use --force to rotate the token",
              file=sys.stderr)
        return 1
    except OSError as exc:
        print(f"psysmon-token: {exc}", file=sys.stderr)
        return 1
    print(f"psysmon-token: wrote a new 0600 control token to {args.path}", file=sys.stderr)
    return 0


if __name__ == "__main__":  # python -m psysmon.control.token
    sys.exit(main())
