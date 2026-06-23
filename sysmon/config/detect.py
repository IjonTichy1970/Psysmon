"""Config-format auto-detection.

Sniffs a config file's first meaningful line to choose a loader. Today only the legacy
``sysmon.conf`` format is supported; a modern (e.g. YAML) format + converter is a deferred
enhancement (GitHub #3), at which point a YAML mapping at the top selects the new loader.

Not yet implemented.
"""

from __future__ import annotations

from enum import Enum, auto


class ConfigFormat(Enum):
    LEGACY = auto()
    MODERN = auto()  # reserved for the future YAML/TOML format (#3)


def detect(text: str) -> ConfigFormat:
    """Return the detected config format for ``text``."""
    raise NotImplementedError("Milestone 2/3: format detection")
