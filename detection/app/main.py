from __future__ import annotations

from fastapi import FastAPI

from . import service
from .models import (
    BatchScanRequest,
    BatchScanResponse,
    BatchScanFileResult,
    ScanRequest,
    ScanResponse,
)

app = FastAPI(title="SecretSentinel Detection Service")


@app.get("/health")
def health() -> dict[str, str]:
    return {"status": "ok"}


@app.post("/scan", response_model=ScanResponse)
def scan(req: ScanRequest) -> ScanResponse:
    findings = service.scan_content(req)
    return ScanResponse(findings=findings)


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

