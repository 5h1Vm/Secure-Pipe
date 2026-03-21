"""Scan initiation and status endpoints."""

from __future__ import annotations

import asyncio
import logging
import uuid
from typing import Any

from datetime import datetime

from fastapi import APIRouter, HTTPException

from db.database import create_scan, get_scan, save_findings, update_scan_status
from schemas.finding import ScanFinding, SeverityLevel
from schemas.scan import InputType, ScanRequest, ScanResult
from services.input_router import detect_input_type
from services.scanners.bandit_scanner import BanditScanner
from services.scanners.gitleaks_scanner import GitleaksScanner
from services.scanners.semgrep_scanner import SemgrepScanner

router = APIRouter()
logger = logging.getLogger(__name__)

_SEVERITY_WEIGHT: dict[SeverityLevel, int] = {
    SeverityLevel.CRITICAL: 40,
    SeverityLevel.HIGH: 20,
    SeverityLevel.MEDIUM: 10,
    SeverityLevel.LOW: 5,
    SeverityLevel.INFO: 1,
}


def _compute_risk_score(findings: list[ScanFinding]) -> int:
    """Compute a 0-100 risk score from *findings*.

    Each finding contributes its severity weight, capped at 100.
    """
    score = sum(_SEVERITY_WEIGHT.get(f.severity, 0) for f in findings)
    return min(score, 100)


async def _run_scan(scan_id: str, target: str, input_type: InputType) -> None:
    """Background task: run all applicable scanners and persist results."""
    await update_scan_status(scan_id, "running")
    findings: list[ScanFinding] = []

    scanners = [BanditScanner(), GitleaksScanner(), SemgrepScanner()]
    for scanner in scanners:
        try:
            results = await scanner.run(target)
            findings.extend(results)
        except Exception:
            logger.exception("Scanner %s raised an exception", scanner.scanner_name)

    risk_score = _compute_risk_score(findings)
    await save_findings(scan_id, findings)
    await update_scan_status(scan_id, "complete", risk_score=risk_score)


@router.post("/scan")
async def start_scan(request: ScanRequest) -> dict[str, Any]:
    """Accept a scan request, persist it, and launch a background scan task.

    Args:
        request: The scan request body containing the target and options.

    Returns:
        A dict with ``scan_id``, ``status``, and ``input_type``.
    """
    scan_id = str(uuid.uuid4())
    input_type = detect_input_type(request.input_str)
    await create_scan(scan_id, request.input_str, input_type.value)

    asyncio.create_task(
        _run_scan(scan_id, request.input_str, input_type),
        name=f"scan-{scan_id}",
    )

    return {"scan_id": scan_id, "status": "queued", "input_type": input_type.value}


@router.get("/scan/{scan_id}", response_model=ScanResult)
async def get_scan_result(scan_id: str) -> ScanResult:
    """Return the current status and findings for *scan_id*.

    Args:
        scan_id: UUID of the scan to retrieve.

    Raises:
        HTTPException: 404 if no scan with that ID exists.
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

    return ScanResult(
        scan_id=record["id"],
        status=record["status"],
        input_type=record.get("input_type"),
        findings=findings,
        risk_score=record.get("risk_score"),
        created_at=datetime.fromisoformat(record["created_at"]),
        completed_at=(
            datetime.fromisoformat(record["completed_at"])
            if record.get("completed_at")
            else None
        ),
    )
