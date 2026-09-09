"""Shared pytest configuration.

Puts ``backend/`` on the import path and pins the database to a temp file so
tests never touch the developer's real data.
"""

from __future__ import annotations

import os
import sys
import tempfile
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
BACKEND = ROOT / "backend"
FIXTURES = ROOT / "fixtures"

if str(BACKEND) not in sys.path:
    sys.path.insert(0, str(BACKEND))

# Must be set before `app.core.config.get_settings` is first called.
os.environ.setdefault(
    "AUDITOR_DATABASE_URL",
    f"sqlite:///{Path(tempfile.gettempdir()) / 'auditor-tests.db'}",
)
# Keep optional external analysers out of unit tests entirely.
os.environ.setdefault("AUDITOR_ENABLE_SLITHER", "false")
os.environ.setdefault("AUDITOR_ENABLE_MYTHRIL", "false")


@pytest.fixture(scope="session")
def fixtures_dir() -> Path:
    return FIXTURES


@pytest.fixture(scope="session")
def source_of():
    """Load a fixture's Solidity source by path relative to ``fixtures/``."""

    def _load(relative: str) -> str:
        return (FIXTURES / relative).read_text(encoding="utf-8")

    return _load


@pytest.fixture(scope="session")
def solc_binary():
    from app.services.solc import discover_solc

    binary = discover_solc()
    if not binary:
        pytest.skip("no solc binary available (try `npm install solc`)")
    return binary


@pytest.fixture(scope="session")
def audit_cache():
    """Audit each fixture once per session; solc runs are not free."""
    from app.services.engine import audit_sources

    cache: dict[tuple[str, bool], object] = {}

    def _audit(relative: str, *, include_optimizations: bool = True):
        key = (relative, include_optimizations)
        if key not in cache:
            sources = {(FIXTURES / relative).name: (FIXTURES / relative).read_text(encoding="utf-8")}
            cache[key] = audit_sources(
                sources,
                include_optimizations=include_optimizations,
                run_external_tools=False,
            )
        return cache[key]

    return _audit


@pytest.fixture(scope="session")
def audit_dir_cache():
    """Audit a whole directory once per session."""
    from app.services.engine import audit_directory

    cache: dict[str, object] = {}

    def _audit(relative: str):
        if relative not in cache:
            cache[relative] = audit_directory(
                FIXTURES / relative, run_external_tools=False
            )
        return cache[relative]

    return _audit
