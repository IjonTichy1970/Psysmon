"""Config-format auto-detection.

Sniffs a config file's first meaningful (non-blank, non-comment) line to choose a loader.
Today only the legacy ``sysmon.conf`` format is supported; a modern (e.g. YAML) format +
converter is a deferred enhancement (GitHub #3), at which point a YAML document marker or a
top-level ``key:`` mapping selects the new loader.
"""

from __future__ import annotations

from enum import Enum, auto


class ConfigFormat(Enum):
    LEGACY = auto()
    MODERN = auto()  # reserved for the future YAML/TOML format (#3)


def detect(text: str) -> ConfigFormat:
    """Return the detected config format for ``text`` (defaults to LEGACY)."""
    for raw in text.splitlines():
        stripped = raw.strip()
        if not stripped or stripped[0] in ";#":
            continue
        # YAML document marker, or a top-level "key:" mapping (no second bare token).
        if stripped == "---" or stripped.startswith("%YAML"):
            return ConfigFormat.MODERN
        first = stripped.split(None, 1)[0]
        if first.endswith(":"):
            return ConfigFormat.MODERN
        return ConfigFormat.LEGACY
    return ConfigFormat.LEGACY
