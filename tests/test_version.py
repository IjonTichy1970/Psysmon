"""The package version derives from installed metadata — single source of truth (#57)."""

from __future__ import annotations

from importlib.metadata import version

import psysmon


def test_version_matches_package_metadata():
    # __version__ is read from importlib.metadata, so it always equals the installed package
    # version (from pyproject.toml) with no hand-maintained second copy that could drift.
    assert psysmon.__version__ == version("psysmon")
    assert psysmon.__version__ != "0.0.0+unknown"  # the package is installed in dev/CI
