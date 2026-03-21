"""Report generation endpoint."""

from __future__ import annotations

import logging
from datetime import datetime
from typing import Any

from fastapi import APIRouter, HTTPException

from db.database import get_scan
from schemas.finding import ScanFinding, SeverityLevel

router = APIRouter()
logger = logging.getLogger(__name__)

_SEVERITY_ORDER: dict[str, int] = {
    "CRITICAL": 0,
    "HIGH": 1,
    "MEDIUM": 2,
    "LOW": 3,
    "INFO": 4,
}


@router.get("/report/{scan_id}")
async def get_report(scan_id: str) -> dict[str, Any]:
    """Return a full structured report for a completed scan.

    The findings are sorted from most-severe to least-severe.

    Args:
        scan_id: UUID of the scan to report on.

    Raises:
        HTTPException: 404 if the scan does not exist.

    Returns:
        A dict with scan metadata, sorted findings, and the risk score.
    """
    record = await get_scan(scan_id)
    if record is None:
        raise HTTPException(status_code=404, detail="Scan not found")

    findings = [
        ScanFinding(
            id=f["id"],
            tool=f["tool"],
            severity=SeverityLevel(f["severity"]),
            cwe=f.get("cwe"),
            title=f["title"],
            description=f.get("description", ""),
            file_path=f.get("file_path"),
            line_number=f.get("line_number"),
            evidence=f.get("evidence"),
            fp_score=f.get("fp_score", 0.5),
            remediation=f.get("remediation"),
        )
        for f in record.get("findings", [])
    ]

    findings.sort(key=lambda f: _SEVERITY_ORDER.get(f.severity.value, 99))

    return {
        "scan_id": record["id"],
        "input_str": record.get("input_str"),
        "input_type": record.get("input_type"),
        "status": record["status"],
        "risk_score": record.get("risk_score"),
        "created_at": record.get("created_at"),
        "completed_at": record.get("completed_at"),
        "finding_count": len(findings),
        "findings": [f.model_dump() for f in findings],
    }
