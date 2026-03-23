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


class ValidateRequest(BaseModel):
    type: str = Field(..., description="Rule ID or type string (e.g. 'aws_access_key', 'github_pat')")
    value: str = Field(..., description="The secret value to validate")


class ValidateResponse(BaseModel):
    live: bool | None = Field(
        None,
        description="True if secret is confirmed live, False if revoked, None if unknown",
    )
    checked_at: str = Field(..., description="ISO-8601 UTC timestamp of the check")
    error: str | None = Field(None, description="Error message if the check could not be completed")

