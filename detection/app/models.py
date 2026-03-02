from __future__ import annotations

from typing import List

from pydantic import BaseModel, Field


class ScanRequest(BaseModel):
    content: str = Field(..., description="File content to scan")
    filename: str = Field(..., description="Logical filename (for context)")


class ScanResultItem(BaseModel):
    line: int
    type: str
    value: str
    confidence: float


class ScanResponse(BaseModel):
    findings: List[ScanResultItem]


class BatchScanFileResult(BaseModel):
    filename: str
    findings: List[ScanResultItem]


class BatchScanRequest(BaseModel):
    files: List[ScanRequest]


class BatchScanResponse(BaseModel):
    files: List[BatchScanFileResult]

