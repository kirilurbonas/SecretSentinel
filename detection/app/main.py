from __future__ import annotations

import os
from datetime import datetime, timezone

from fastapi import FastAPI
from prometheus_fastapi_instrumentator import Instrumentator

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

VALIDATION_ENABLED = os.getenv("SENTINEL_ENABLE_VALIDATION", "").lower() in ("1", "true", "yes")

app = FastAPI(title="SecretSentinel Detection Service")

Instrumentator().instrument(app).expose(app)


@app.get("/health")
def health() -> dict[str, object]:
    return {
        "status": "ok",
        "min_confidence": service.MIN_CONFIDENCE,
        "validation_enabled": VALIDATION_ENABLED,
    }


@app.post("/scan", response_model=ScanResponse)
def scan(req: ScanRequest) -> ScanResponse:
    findings = service.scan_content(req)
    return ScanResponse(findings=findings)


@app.post("/validate", response_model=ValidateResponse)
def validate_secret(req: ValidateRequest) -> ValidateResponse:
    checked_at = datetime.now(tz=timezone.utc).isoformat()
    if not VALIDATION_ENABLED:
        return ValidateResponse(live=None, checked_at=checked_at, error="validation disabled")
    live, error = validators.validate(req.type, req.value)
    return ValidateResponse(live=live, checked_at=checked_at, error=error)


@app.post("/scan/batch", response_model=BatchScanResponse)
def scan_batch(req: BatchScanRequest) -> BatchScanResponse:
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
