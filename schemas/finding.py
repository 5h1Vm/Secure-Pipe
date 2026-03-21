"""Pydantic v2 models for scan findings."""

from __future__ import annotations

import uuid
from enum import Enum
from typing import Any

from pydantic import BaseModel, Field


class SeverityLevel(str, Enum):
    """Severity levels for a scan finding."""

    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    INFO = "INFO"


class ScanFinding(BaseModel):
    """A single normalised finding produced by any scanner."""

    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    tool: str
    severity: SeverityLevel
    cwe: str | None = None
    title: str
    description: str
    file_path: str | None = None
    line_number: int | None = None
    evidence: str | None = None
    fp_score: float = Field(default=0.5, ge=0.0, le=1.0)
    remediation: str | None = None
    scanner_raw: dict[str, Any] = Field(default_factory=dict)
