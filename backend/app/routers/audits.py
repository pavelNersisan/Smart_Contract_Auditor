"""REST API for audits.

Endpoints mirror the README's ``POST /audit`` contract (multipart upload) and
add JSON input, stored-run retrieval and report downloads.
"""

from __future__ import annotations

import logging
from typing import Any

from fastapi import APIRouter, Depends, HTTPException, Request
from starlette.datastructures import UploadFile

# Note: the isinstance check below must use Starlette's UploadFile. FastAPI
# re-exports a *subclass*, and Starlette's form parser instantiates the parent
# class, so testing against the FastAPI one silently matches nothing.
from fastapi.responses import HTMLResponse, JSONResponse, PlainTextResponse

from app.core.config import Settings, get_settings
from app.core.security import SecurityError, check_api_key, client_key, verify_token
from app.models.audit import AuditRequest, AuditResult
from app.services.detectors import build_default_registry
from app.services.engine import AuditEngine
from app.services.report_generator import to_html, to_json, to_markdown

logger = logging.getLogger("auditor.api")

router = APIRouter()

#: Shared across requests; created lazily so tests can override settings.
_state: dict[str, Any] = {}


def get_state(request: Request) -> dict[str, Any]:
    """Per-application state (engine, store, limiter)."""
    app_state = request.app.state.auditor
    return app_state


async def require_auth(request: Request, settings: Settings = Depends(get_settings)) -> None:
    """Enforce API key / bearer token when keys are configured."""
    if not settings.auth_enabled:
        return
    headers = {k.lower(): v for k, v in request.headers.items()}
    supplied = headers.get("x-api-key")
    if supplied and check_api_key(settings.api_keys, supplied):
        return
    auth = headers.get("authorization", "")
    if auth.lower().startswith("bearer "):
        try:
            verify_token(settings.token_secret, auth[7:].strip())
            return
        except SecurityError as exc:
            raise HTTPException(status_code=401, detail=str(exc)) from exc
    raise HTTPException(status_code=401, detail="missing or invalid credentials")


def _enforce_rate_limit(request: Request, settings: Settings) -> None:
    state = request.app.state.auditor
    limiter = state["limiter"]
    headers = {k.lower(): v for k, v in request.headers.items()}
    key = client_key(headers, request.client.host if request.client else None)
    if not limiter.allow(key):
        raise HTTPException(
            status_code=429,
            detail="rate limit exceeded; retry shortly or supply an API key",
        )


async def _read_uploads(files: list[UploadFile], settings: Settings) -> dict[str, str]:
    sources: dict[str, str] = {}
    total = 0
    for upload in files:
        raw = await upload.read()
        total += len(raw)
        if total > settings.max_upload_bytes:
            raise HTTPException(
                status_code=413,
                detail=f"upload exceeds {settings.max_upload_bytes} byte limit",
            )
        name = upload.filename or f"Contract{len(sources)}.sol"
        if not name.endswith(".sol"):
            name += ".sol"
        try:
            sources[name] = raw.decode("utf-8")
        except UnicodeDecodeError as exc:
            raise HTTPException(
                status_code=400, detail=f"{name} is not valid UTF-8 text"
            ) from exc
    if len(sources) > settings.max_files_per_request:
        raise HTTPException(
            status_code=400,
            detail=f"too many files (max {settings.max_files_per_request})",
        )
    return sources


@router.post("/audit", response_model=AuditResult)
async def create_audit(
    request: Request,
    settings: Settings = Depends(get_settings),
    _: None = Depends(require_auth),
) -> AuditResult:
    """Audit Solidity supplied as a multipart upload or a JSON body.

    Both input styles are handled off the raw request: declaring a ``File``
    parameter in the signature would make FastAPI treat *every* request as
    multipart and silently drop JSON bodies.
    """
    _enforce_rate_limit(request, settings)
    state = get_state(request)

    sources: dict[str, str] = {}
    include_optimizations = True
    run_tools = True
    content_type = request.headers.get("content-type", "")

    if content_type.startswith("multipart/form-data"):
        form = await request.form()
        uploads = [value for value in form.values() if isinstance(value, UploadFile)]
        if not uploads:
            raise HTTPException(
                status_code=400, detail="multipart request contained no file part"
            )
        sources = await _read_uploads(uploads, settings)
    else:
        try:
            body = await request.json()
        except Exception as exc:
            raise HTTPException(
                status_code=400,
                detail="expected a JSON body or a multipart/form-data upload",
            ) from exc
        try:
            payload = AuditRequest.model_validate(body if isinstance(body, dict) else {})
        except Exception as exc:
            raise HTTPException(status_code=400, detail=f"invalid payload: {exc}") from exc
        if payload.sources:
            sources = dict(payload.sources)
        elif payload.source:
            name = payload.filename or "Contract.sol"
            sources = {name if name.endswith(".sol") else name + ".sol": payload.source}
        include_optimizations = payload.include_optimizations
        run_tools = payload.run_external_tools

    if not sources:
        raise HTTPException(
            status_code=400,
            detail="no contract supplied; upload a .sol file or post {\"source\": ...}",
        )

    result = state["engine"].audit(
        sources,
        include_optimizations=include_optimizations,
        run_external_tools=run_tools,
    )
    state["store"].save(result)
    return result


@router.get("/audits", response_model=list[dict])
async def list_audits(
    request: Request,
    limit: int = 50,
    offset: int = 0,
    _: None = Depends(require_auth),
) -> list[dict]:
    state = get_state(request)
    return state["store"].list(limit=min(limit, 200), offset=max(offset, 0))


@router.get("/audits/{audit_id}", response_model=AuditResult)
async def get_audit(
    audit_id: str,
    request: Request,
    _: None = Depends(require_auth),
) -> AuditResult:
    result = get_state(request)["store"].get(audit_id)
    if result is None:
        raise HTTPException(status_code=404, detail="audit not found")
    return result


@router.get("/audits/{audit_id}/report.{fmt}")
async def get_report(
    audit_id: str,
    fmt: str,
    request: Request,
    _: None = Depends(require_auth),
):
    """Download a stored audit as JSON, Markdown or HTML."""
    result = get_state(request)["store"].get(audit_id)
    if result is None:
        raise HTTPException(status_code=404, detail="audit not found")
    if fmt == "json":
        return PlainTextResponse(to_json(result), media_type="application/json")
    if fmt in ("md", "markdown"):
        return PlainTextResponse(to_markdown(result), media_type="text/markdown")
    if fmt == "html":
        return HTMLResponse(to_html(result))
    raise HTTPException(status_code=400, detail="format must be json, md or html")


@router.get("/detectors")
async def list_detectors(
    include_optimizations: bool = True, _: None = Depends(require_auth)
) -> dict:
    """Every check the engine can run, with its metadata."""
    registry = build_default_registry(include_optimizations=include_optimizations)
    return {
        "count": len(registry.all()),
        "detectors": [
            {
                "check_id": d.check_id,
                "title": d.title,
                "description": d.blurb,
                "swc": d.swc,
                "cwe": d.cwe,
                "requires_compilation": d.requires_ast,
            }
            for d in registry.all()
        ],
    }


@router.get("/health")
async def health(request: Request) -> JSONResponse:
    """Liveness plus what the engine can actually do in this environment."""
    state = get_state(request)
    engine: AuditEngine = state["engine"]
    return JSONResponse(
        {
            "status": "ok",
            "solc": engine.solc_binary,
            "solc_version": (
                state["solc_version"] if "solc_version" in state else "unknown"
            ),
            "detectors": len(build_default_registry().all()),
            "auth_enabled": get_settings().auth_enabled,
        }
    )
