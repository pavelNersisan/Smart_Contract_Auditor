"""FastAPI application factory."""

from __future__ import annotations

import logging
from contextlib import asynccontextmanager

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from app.core.config import REPO_ROOT, get_settings
from app.core.security import TokenBucketRateLimiter
from app.routers import audits
from app.services.engine import AuditEngine
from app.services.solc import discover_solc, solc_version
from app.services.store import AuditStore

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s %(levelname)-7s %(name)s: %(message)s",
)
logger = logging.getLogger("auditor")


@asynccontextmanager
async def lifespan(app: FastAPI):
    settings = get_settings()
    binary = discover_solc(settings.solc_bin)
    app.state.auditor = {
        "engine": AuditEngine(settings),
        "store": AuditStore(settings.database_url),
        "limiter": TokenBucketRateLimiter(
            settings.rate_limit_capacity, settings.rate_limit_refill_per_sec
        ),
        "solc_version": solc_version(binary) if binary else "unavailable",
    }
    logger.info(
        "auditor ready (solc=%s, version=%s, auth=%s)",
        binary or "none",
        app.state.auditor["solc_version"],
        settings.auth_enabled,
    )
    yield


def create_app() -> FastAPI:
    """Build the API. Importable as ``app.main:create_app`` or ``app.main:app``."""
    app = FastAPI(
        title="Smart Contract Auditor",
        description=(
            "Static analysis for Solidity: reentrancy, access control, arithmetic, "
            "external-call and hygiene checks with a 1-100 risk score."
        ),
        version="1.0.0",
        lifespan=lifespan,
    )

    settings = get_settings()
    app.add_middleware(
        CORSMiddleware,
        allow_origins=["*"],
        allow_methods=["*"],
        allow_headers=["*"],
    )
    app.include_router(audits.router, tags=["audits"])

    # Serve the built frontend when it exists, so one process serves both.
    dist = REPO_ROOT / "frontend" / "dist"
    if dist.exists():
        from fastapi.staticfiles import StaticFiles

        app.mount("/", StaticFiles(directory=str(dist), html=True), name="frontend")
        logger.info("serving built frontend from %s", dist)

    return app


app = create_app()
