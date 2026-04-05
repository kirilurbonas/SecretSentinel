from __future__ import annotations

import logging
import os
import uuid
from datetime import datetime, timezone
from typing import Any, Callable

from fastapi import FastAPI, Request, Response
from prometheus_fastapi_instrumentator import Instrumentator
from pythonjsonlogger import jsonlogger
from slowapi import Limiter, _rate_limit_exceeded_handler
from slowapi.errors import RateLimitExceeded
from slowapi.util import get_remote_address
from starlette.middleware.base import BaseHTTPMiddleware

from . import service, validators
from .models import (
    BatchScanFileResult,
    BatchScanRequest,
    BatchScanResponse,
    ScanRequest,
    ScanResponse,
    ValidateRequest,
    ValidateResponse,
)

# ── Structured JSON logging ────────────────────────────────────────────────────
_handler = logging.StreamHandler()
_handler.setFormatter(
    jsonlogger.JsonFormatter("%(asctime)s %(name)s %(levelname)s %(message)s")
)
logging.basicConfig(handlers=[_handler], level=logging.INFO, force=True)
logger = logging.getLogger("secretsentinel.detection")

VALIDATION_ENABLED = os.getenv("SENTINEL_ENABLE_VALIDATION", "").lower() in ("1", "true", "yes")

# ── Rate limiter ───────────────────────────────────────────────────────────────
limiter = Limiter(key_func=get_remote_address)

app = FastAPI(title="SecretSentinel Detection Service")
app.state.limiter = limiter
app.add_exception_handler(RateLimitExceeded, _rate_limit_exceeded_handler)  # type: ignore[arg-type]

Instrumentator().instrument(app).expose(app)


# ── Request ID middleware ──────────────────────────────────────────────────────
class RequestIDMiddleware(BaseHTTPMiddleware):
    async def dispatch(self, request: Request, call_next: Callable[..., Any]) -> Response:
        request_id = request.headers.get("X-Request-ID") or str(uuid.uuid4())
        response: Response = await call_next(request)
        response.headers["X-Request-ID"] = request_id
        return response


app.add_middleware(RequestIDMiddleware)


@app.get("/health")
def health() -> dict[str, object]:
    return {
        "status": "ok",
        "min_confidence": service.MIN_CONFIDENCE,
        "validation_enabled": VALIDATION_ENABLED,
        "active_rules": len(service.active_rules()),
    }


@app.get("/ready")
def ready() -> dict[str, str]:
    return {"status": "ready"}


@app.post("/scan", response_model=ScanResponse)
@limiter.limit("100/minute")
def scan(request: Request, req: ScanRequest) -> ScanResponse:
    findings = service.scan_content(req)
    return ScanResponse(findings=findings)


@app.post("/validate", response_model=ValidateResponse)
@limiter.limit("20/minute")
def validate_secret(request: Request, req: ValidateRequest) -> ValidateResponse:
    checked_at = datetime.now(tz=timezone.utc).isoformat()
    if not VALIDATION_ENABLED:
        return ValidateResponse(live=None, checked_at=checked_at, error="validation disabled")
    live, error = validators.validate(req.type, req.value)
    return ValidateResponse(live=live, checked_at=checked_at, error=error)


@app.post("/scan/batch", response_model=BatchScanResponse)
@limiter.limit("50/minute")
def scan_batch(request: Request, req: BatchScanRequest) -> BatchScanResponse:
    results: list[BatchScanFileResult] = []
    for file_req in req.files:
        findings = service.scan_content(file_req)
        results.append(
            BatchScanFileResult(
                filename=file_req.filename,
                findings=findings,
            )
        )
    return BatchScanResponse(files=results)
