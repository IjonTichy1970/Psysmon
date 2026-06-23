"""Command-line entry point.

Wires settings (CLI > file > defaults) to the monitoring engine and runs the daemon. For now
only ``--version`` is wired up; the run path lands with the scheduler (Milestone 8) and
daemonization (Milestone 11).
"""

from __future__ import annotations

import argparse
import sys

from sysmon import __version__


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="sysmon", description="Network monitoring daemon")
    parser.add_argument("--version", action="version", version=f"sysmon {__version__}")
    parser.add_argument("-f", "--config", help="path to config file")
    parser.add_argument(
        "-n", "--no-notify", action="store_true", help="do not send notifications"
    )
    parser.add_argument("-d", "--no-fork", action="store_true", help="run in the foreground")
    return parser


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    parser.parse_args(argv)
    print("sysmon is not runnable yet — under active development.", file=sys.stderr)
    return 1


if __name__ == "__main__":
    raise SystemExit(main())
