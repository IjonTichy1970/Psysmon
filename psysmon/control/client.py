"""``psysmonctl`` — a small command-line client for the psysmon control channel (#69).

Connects to a running daemon's control channel and issues one request:

    psysmonctl status
    psysmonctl version
    psysmonctl ack  <hostname> <type> [port]   --token-file PATH
    psysmonctl note <hostname> <type> <port> <text>   --token-file PATH
    psysmonctl note <hostname> <type> <port> ""        # empty text clears the note
    psysmonctl reload   --token-file PATH

Defaults to ``127.0.0.1:2026`` (the daemon's defaults). Mutating actions need ``--token-file``
(the same file the daemon reads). Use ``--tls-ca`` to talk to a TLS-enabled channel.
"""

from __future__ import annotations

import argparse
import json
import socket
import ssl
import sys
from pathlib import Path

_MAX_RESPONSE = 8 * 1024 * 1024  # bound the reply we'll buffer


def _request(host: str, port: int, payload: dict, *, tls_ca: str | None, timeout: float) -> dict:
    raw = (json.dumps(payload) + "\n").encode("utf-8")
    with socket.create_connection((host, port), timeout=timeout) as sock:
        if tls_ca:
            ctx = ssl.create_default_context(cafile=tls_ca)
            sock = ctx.wrap_socket(sock, server_hostname=host)
        sock.sendall(raw)
        buf = bytearray()
        while not buf.endswith(b"\n") and len(buf) < _MAX_RESPONSE:
            chunk = sock.recv(65536)
            if not chunk:
                break
            buf += chunk
    return json.loads(bytes(buf))


def _payload(args: argparse.Namespace) -> dict:
    req: dict = {"cmd": args.cmd}
    if args.cmd in ("ack", "note"):
        req["object"] = {"hostname": args.hostname, "type": args.type, "port": args.port}
    if args.cmd == "note":
        req["object"]["port"] = args.port
        req["text"] = args.text
    if args.cmd in ("ack", "note", "reload"):
        if not args.token_file:
            raise SystemExit("psysmonctl: this action needs --token-file")
        req["token"] = Path(args.token_file).read_text(encoding="utf-8").strip()
    return req


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(prog="psysmonctl", description="psysmon control-channel client")
    ap.add_argument("--host", default="127.0.0.1", help="control channel host (default 127.0.0.1)")
    ap.add_argument("--port", type=int, default=2026, help="control channel port (default 2026)")
    ap.add_argument("--token-file", metavar="PATH", help="file holding the bearer token")
    ap.add_argument("--tls-ca", metavar="PATH", help="CA bundle to verify a TLS channel")
    ap.add_argument("--timeout", type=float, default=10.0)
    sub = ap.add_subparsers(dest="cmd", required=True)
    sub.add_parser("status")
    sub.add_parser("version")
    sub.add_parser("reload")
    for name in ("ack", "note"):
        p = sub.add_parser(name)
        p.add_argument("hostname")
        p.add_argument("type")
        p.add_argument("port", nargs="?", type=int, default=0)
        if name == "note":
            p.add_argument("text")
    args = ap.parse_args(argv)

    try:
        resp = _request(args.host, args.port, _payload(args),
                        tls_ca=args.tls_ca, timeout=args.timeout)
    except (OSError, ssl.SSLError, ValueError) as exc:
        print(f"psysmonctl: {exc}", file=sys.stderr)
        return 1
    print(json.dumps(resp, indent=2))
    return 0 if resp.get("ok") else 1


if __name__ == "__main__":  # python -m psysmon.control.client
    sys.exit(main())
