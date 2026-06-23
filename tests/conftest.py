"""Shared pytest fixtures."""

from __future__ import annotations

from pathlib import Path

import pytest

FIXTURES = Path(__file__).parent / "fixtures"


@pytest.fixture
def sample_config_text() -> str:
    """Synthetic legacy config exercising every grammar feature (committed)."""
    return (FIXTURES / "legacy_sample.conf").read_text(encoding="utf-8")


@pytest.fixture
def production_config_text() -> str:
    """The real production ``sysmon.conf`` for scale/smoke checks.

    Kept local-only (gitignored) because it contains live customer data and credentials, so
    it is absent in CI — tests that use it are skipped when the file isn't present.
    """
    path = FIXTURES / "production.conf"
    if not path.exists():
        pytest.skip("production.conf not present (local-only fixture)")
    return path.read_text(encoding="utf-8", errors="replace")
