"""PSYSMON — dependency-aware network monitoring daemon.

A Python 3.11+ rewrite of the original 1998 C ``sysmon`` (v0.78.3.2 by Jared Mauch),
preserving its observable monitoring/alerting semantics while modernizing the engine.
"""

# __version__ derives from the installed package metadata (pyproject.toml) — single source of
# truth, no second copy to sync (#57). Caveat: an editable install snapshots the version at
# `pip install -e` time, so re-run the install after a version bump for `--version` to refresh.
# (Release builds read pyproject.toml directly, so release artifacts are always correct.)
from importlib.metadata import PackageNotFoundError, version

try:
    __version__ = version("psysmon")
except PackageNotFoundError:  # running from a source tree with no installed dist
    __version__ = "0.0.0+unknown"
