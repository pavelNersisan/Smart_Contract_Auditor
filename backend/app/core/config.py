"""Central configuration.

Every knob is environment-overridable so the same image runs locally, in CI and
in a container without code changes.
"""

from __future__ import annotations

import os
from dataclasses import dataclass, field
from functools import lru_cache
from pathlib import Path


def _env_bool(name: str, default: bool) -> bool:
    raw = os.environ.get(name)
    if raw is None:
        return default
    return raw.strip().lower() in {"1", "true", "yes", "on"}


def _env_int(name: str, default: int) -> int:
    raw = os.environ.get(name)
    if raw is None:
        return default
    try:
        return int(raw)
    except ValueError:
        return default


REPO_ROOT = Path(__file__).resolve().parents[3]


@dataclass(frozen=True)
class Settings:
    """Runtime settings for the auditor."""

    # --- API -------------------------------------------------------------
    host: str = "0.0.0.0"
    port: int = 8000
    max_upload_bytes: int = 1_000_000  # 1 MB of Solidity is a very large contract
    max_files_per_request: int = 64

    # --- Analysis --------------------------------------------------------
    # Absolute path to a solc-compatible binary. When empty the engine
    # auto-discovers `solc` on PATH or the WASM `solcjs` shipped via npm.
    solc_bin: str = ""
    solc_timeout: int = 120
    # Run Slither / Mythril when they are installed. Both are optional
    # accelerators; the built-in detectors never depend on them.
    enable_slither: bool = True
    enable_mythril: bool = True

    # --- Security --------------------------------------------------------
    api_keys: tuple[str, ...] = ()
    token_secret: str = "change-me-in-production"
    token_ttl_seconds: int = 3600
    # Token-bucket rate limiting, per client IP.
    rate_limit_capacity: int = _env_int("AUDITOR_RATE_CAPACITY", 60)
    rate_limit_refill_per_sec: float = float(
        os.environ.get("AUDITOR_RATE_REFILL", "2")
    )

    # --- Storage ---------------------------------------------------------
    database_url: str = field(
        default_factory=lambda: os.environ.get(
            "AUDITOR_DATABASE_URL",
            f"sqlite:///{REPO_ROOT / '.data' / 'audits.db'}",
        )
    )

    # --- Reports ---------------------------------------------------------
    report_dir: Path = field(
        default_factory=lambda: Path(
            os.environ.get("AUDITOR_REPORT_DIR", str(REPO_ROOT / ".data" / "reports"))
        )
    )

    # --- Optional toolchain paths ----------------------------------------
    slither_bin: str = "slither"
    mythril_bin: str = "myth"

    @property
    def auth_enabled(self) -> bool:
        return bool(self.api_keys)


@lru_cache(maxsize=1)
def get_settings() -> Settings:
    """Build settings from the environment (cached for the process lifetime)."""
    keys = tuple(
        k.strip()
        for k in os.environ.get("AUDITOR_API_KEYS", "").split(",")
        if k.strip()
    )
    defaults = Settings()
    return Settings(
        host=os.environ.get("AUDITOR_HOST", defaults.host),
        port=_env_int("AUDITOR_PORT", defaults.port),
        max_upload_bytes=_env_int("AUDITOR_MAX_UPLOAD_BYTES", defaults.max_upload_bytes),
        solc_bin=os.environ.get("AUDITOR_SOLC", defaults.solc_bin),
        solc_timeout=_env_int("AUDITOR_SOLC_TIMEOUT", defaults.solc_timeout),
        enable_slither=_env_bool("AUDITOR_ENABLE_SLITHER", defaults.enable_slither),
        enable_mythril=_env_bool("AUDITOR_ENABLE_MYTHRIL", defaults.enable_mythril),
        api_keys=keys,
        token_secret=os.environ.get("AUDITOR_TOKEN_SECRET", defaults.token_secret),
        rate_limit_capacity=_env_int(
            "AUDITOR_RATE_CAPACITY", defaults.rate_limit_capacity
        ),
        rate_limit_refill_per_sec=float(
            os.environ.get("AUDITOR_RATE_REFILL", defaults.rate_limit_refill_per_sec)
        ),
        slither_bin=os.environ.get("AUDITOR_SLITHER_BIN", defaults.slither_bin),
        mythril_bin=os.environ.get("AUDITOR_MYTHRIL_BIN", defaults.mythril_bin),
    )
