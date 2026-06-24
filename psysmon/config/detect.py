"""Config-format auto-detection.

Sniffs a config file to choose between the legacy positional ``sysmon.conf`` parser and the
modern ``object{}`` grammar (sysmon 0.93, issue #3). Both formats share ``config <directive>;``
lines verbatim, so a ``config`` line is **not** a discriminator — the modern-only signals are an
``object NAME { … }`` block, a ``root = …`` assignment, or a ``set NAME = …`` assignment (the
``=`` / ``object{}`` syntax the legacy positional format never had). We scan past leading
comment / blank / ``config`` lines to the first meaningful line and decide from it; anything
ambiguous (e.g. a file of only ``config`` lines, which parses identically either way) defaults
to LEGACY — the safe choice that never mis-routes an existing legacy file.
"""

from __future__ import annotations

from enum import Enum, auto


class ConfigFormat(Enum):
    LEGACY = auto()  # the original positional sysmon.conf grammar (default)
    MODERN = auto()  # the sysmon 0.93 object{} grammar (#3)


def detect(text: str) -> ConfigFormat:
    """Return the detected config format for ``text`` (defaults to LEGACY)."""
    for raw in text.splitlines():
        stripped = raw.strip()
        if not stripped or stripped[0] in ";#":
            continue  # blank or comment line
        first = stripped.split(None, 1)[0]
        if first == "config":
            continue  # shared by both formats — keep looking for a discriminating line
        if _is_modern_line(stripped, first):
            return ConfigFormat.MODERN
        # A meaningful, non-``config`` line that isn't a modern signal is a legacy positional
        # host line, so the file is legacy.
        return ConfigFormat.LEGACY
    return ConfigFormat.LEGACY  # only comments / blanks / config lines -> ambiguous -> legacy


def _is_modern_line(stripped: str, first: str) -> bool:
    """True if ``stripped`` is an ``object NAME {`` / ``root = …`` / ``set NAME = …`` line.

    Matches the modern *shape* on whitespace-split tokens, not a loose substring, so a legacy
    positional line can't misroute: ``object`` requires the brace immediately after the name
    (``object NAME {``), and ``root``/``set`` require a *standalone* ``=`` token — a legacy ``www``
    line whose URL field contains ``a=b`` carries no standalone ``=`` and stays legacy.
    """
    tokens = stripped.split()
    if first == "object" and len(tokens) >= 3 and tokens[2] == "{":
        return True  # object NAME {
    if first in ("root", "set") and "=" in tokens:
        return True  # root = "..."   /   set NAME = "..."
    return False
