"""Command-line entry point.

Delegates to :func:`psysmon.daemon.main`, which parses the CLI, loads and merges the config
(CLI > file > defaults), builds the monitoring engine, and runs it with status publishing and
signal handling. Exposed as the ``psysmon`` console script.
"""

from __future__ import annotations

from psysmon.daemon import main

__all__ = ["main"]


if __name__ == "__main__":
    raise SystemExit(main())
