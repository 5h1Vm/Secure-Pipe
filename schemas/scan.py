"""Pydantic v2 models for scan requests and results."""

from __future__ import annotations

from datetime import datetime
from enum import Enum
from typing import Any

from pydantic import BaseModel, Field

from schemas.finding import ScanFinding


class InputType(str, Enum):
    """Supported input types for a scan target."""

    GITHUB_URL = "GITHUB_URL"
    LIVE_URL = "LIVE_URL"
    MCP_ENDPOINT = "MCP_ENDPOINT"
    ZIP_UPLOAD = "ZIP_UPLOAD"
    PACKAGE_NAME = "PACKAGE_NAME"
    AI_CODE = "AI_CODE"


class ScanRequest(BaseModel):
    """Request body for initiating a new scan."""

    input_str: str
    options: dict[str, Any] = Field(default_factory=dict)


class ScanResult(BaseModel):
    """Full result returned for a completed or in-progress scan."""

    scan_id: str
    status: str
    input_type: str | None = None
    findings: list[ScanFinding] = Field(default_factory=list)
    risk_score: int | None = None
    created_at: datetime
    completed_at: datetime | None = None
