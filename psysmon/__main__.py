"""Command-line entry point.

Parses the command line (``settings.build_parser``), merges it over the config file and
defaults (CLI wins), and will hand the resulting :class:`~psysmon.config.settings.Settings` to
the monitoring engine. The run path lands with the scheduler (Milestone 8) and daemonization
(Milestone 11); for now this validates arguments and reports that the engine isn't wired yet.
"""

from __future__ import annotations

import sys

from psysmon.config.settings import load


def main(argv: list[str] | None = None) -> int:
    # Parses argv (handling --version/--help) and merges over defaults. The config-file layer
    # is wired once the legacy parser lands (Milestone 3).
    load(argv)
    print("psysmon: configuration parsed; engine not runnable yet.", file=sys.stderr)
    return 1


if __name__ == "__main__":
    raise SystemExit(main())
