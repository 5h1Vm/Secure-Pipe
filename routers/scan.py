"""Scan initiation and status endpoints."""

from __future__ import annotations

import asyncio
import logging
import os
import shutil
import uuid
from datetime import datetime
from typing import Any, Optional

from fastapi import APIRouter, HTTPException, Query
from pydantic import BaseModel

from db.database import create_scan, get_scan, get_scan_history, save_findings, update_scan_status
from schemas.finding import ScanFinding, SeverityLevel
from schemas.scan import InputType, ScanRequest, ScanResult
from services.diff_scanner import DiffScanResult, scan_diff
from services.input_router import detect_input_type
from services.risk_score import compute_risk_score
from services.mcp_scanner import MCPScanner
from services.scanners.bandit_scanner import BanditScanner
from services.scanners.gitleaks_scanner import GitleaksScanner
from services.scanners.semgrep_scanner import SemgrepScanner
from services.supply_chain import check_dependencies, check_slopsquat

router = APIRouter()
logger = logging.getLogger(__name__)


async def _run_scan(scan_id: str, target: str, input_type: InputType) -> None:
    """Background task: run all applicable scanners and persist results."""
    await update_scan_status(scan_id, "running")
    findings: list[ScanFinding] = []
    clone_path: str | None = None

    try:
        if input_type == InputType.GITHUB_URL:
            import git

            clone_path = f"/tmp/{scan_id}"
            logger.info("Cloning %s to %s", target, clone_path)
            git.Repo.clone_from(target, clone_path)

            scanners = [
                SemgrepScanner(),
                BanditScanner(),
                GitleaksScanner(),
            ]
            for scanner in scanners:
                try:
                    results = await scanner.run(clone_path)
                    findings.extend(results)
                except Exception:
                    logger.exception(
                        "Scanner %s raised an exception", scanner.scanner_name
                    )

            # Supply chain: check for abandoned and slopsquatted packages.
            try:
                sc_findings = await check_dependencies(clone_path)
                findings.extend(sc_findings)
            except Exception:
                logger.exception("supply_chain check_dependencies raised an exception")

            req_file = os.path.join(clone_path, "requirements.txt")
            if os.path.exists(req_file):
                try:
                    from services.supply_chain import _parse_requirements_txt

                    pkgs = _parse_requirements_txt(req_file)
                    findings.extend(check_slopsquat(pkgs))
                except Exception:
                    logger.exception(
                        "supply_chain check_slopsquat raised an exception"
                    )

        elif input_type == InputType.MCP_ENDPOINT:
            logger.info("MCP_ENDPOINT target %s: running MCP scanner", target)
            try:
                results = await MCPScanner().run(target)
                findings.extend(results)
            except Exception:
                logger.exception("MCPScanner raised an exception for %s", target)

        elif input_type == InputType.LIVE_URL:
            # DAST via ZAP comes in phase 3 — return empty findings with a note
            logger.info(
                "LIVE_URL target %s: skipping static scanners (ZAP in phase 3)",
                target,
            )

        elif input_type == InputType.PACKAGE_NAME:
            # Supply-chain scanning comes in phase 5
            logger.info(
                "PACKAGE_NAME target %s: skipping (supply chain in phase 5)", target
            )

        else:
            # ZIP_UPLOAD, AI_CODE — handled in later phases
            logger.info(
                "Input type %s for %s: no scanner implemented yet", input_type, target
            )

        # AI triage: enrich CRITICAL/HIGH findings before scoring
        from services.ai_consensus import triage_all

        if findings:
            findings = await triage_all(findings)
        risk_score = compute_risk_score(findings)
        await save_findings(scan_id, findings)
        await update_scan_status(scan_id, "complete", risk_score=risk_score)

    except Exception:
        logger.exception("Scan %s failed", scan_id)
        await update_scan_status(scan_id, "failed")

    finally:
        if clone_path:
            try:
                shutil.rmtree(clone_path, ignore_errors=True)
            except Exception:
                logger.warning("Failed to clean up clone path %s", clone_path)


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


@router.get("/scan/history")
async def scan_history(
    input_str: Optional[str] = Query(default=None),
) -> list[dict[str, Any]]:
    """Return the last 20 scans, optionally filtered by *input_str*.

    Args:
        input_str: When provided, only scans for this target are returned.

    Returns:
        List of dicts with scan_id, input_str, status, risk_score,
        finding_count, and created_at.
    """
    return await get_scan_history(input_str=input_str, limit=20)


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


# ---------------------------------------------------------------------------
# Diff scan endpoint
# ---------------------------------------------------------------------------


class DiffScanRequest(BaseModel):
    """Request body for the diff scan endpoint."""

    repo_url: str
    base_sha: str
    head_sha: str


@router.post("/scan/diff")
async def start_diff_scan(request: DiffScanRequest) -> dict[str, Any]:
    """Clone *repo_url*, check out *head_sha*, and run a diff-aware scan.

    Args:
        request: Body containing ``repo_url``, ``base_sha``, and ``head_sha``.

    Returns:
        A dict with classified findings (new, fixed, worsened, existing_count).

    Raises:
        HTTPException: 500 if the scan fails.
    """
    import git as _git

    import tempfile as _tempfile

    scan_id = str(uuid.uuid4())
    clone_path = os.path.join(_tempfile.gettempdir(), f"diff_clone_{scan_id}")
    try:
        logger.info("Cloning %s for diff scan", request.repo_url)
        _git.Repo.clone_from(request.repo_url, clone_path)

        result: DiffScanResult = await scan_diff(
            clone_path, request.base_sha, request.head_sha
        )

        return {
            "new_findings": [f.model_dump() for f in result.new_findings],
            "fixed_findings": [f.model_dump() for f in result.fixed_findings],
            "worsened_findings": [f.model_dump() for f in result.worsened_findings],
            "existing_count": result.existing_count,
        }
    except Exception as exc:
        logger.exception("Diff scan %s failed", scan_id)
        raise HTTPException(status_code=500, detail=str(exc)) from exc
    finally:
        shutil.rmtree(clone_path, ignore_errors=True)
