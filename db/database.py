"""Async SQLite persistence layer using aiosqlite."""

from __future__ import annotations

import os
from typing import Any

import aiosqlite

from schemas.finding import ScanFinding

DB_PATH: str = os.getenv("DB_PATH", "securepipe.db")

_CREATE_SCANS = """
CREATE TABLE IF NOT EXISTS scans (
    id          TEXT PRIMARY KEY,
    input_str   TEXT,
    input_type  TEXT,
    status      TEXT,
    risk_score  INTEGER,
    risk_label  TEXT DEFAULT 'UNKNOWN',
    created_at  TEXT,
    completed_at TEXT
)
"""

_MIGRATE_RISK_LABEL = (
    "ALTER TABLE scans ADD COLUMN risk_label TEXT DEFAULT 'UNKNOWN'"
)

_CREATE_FINDINGS = """
CREATE TABLE IF NOT EXISTS findings (
    id          TEXT PRIMARY KEY,
    scan_id     TEXT REFERENCES scans(id),
    tool        TEXT,
    severity    TEXT,
    cwe         TEXT,
    title       TEXT,
    description TEXT,
    file_path   TEXT,
    line_number INTEGER,
    evidence    TEXT,
    fp_score    REAL,
    remediation TEXT
)
"""


async def init_db() -> None:
    """Create database tables if they do not already exist."""
    async with aiosqlite.connect(DB_PATH) as db:
        await db.execute(_CREATE_SCANS)
        await db.execute(_CREATE_FINDINGS)
        # Migrate: add risk_label column if it doesn't exist yet.
        try:
            await db.execute(_MIGRATE_RISK_LABEL)
        except Exception:
            pass  # Column already exists — ignore.
        # Backfill any rows where risk_label is still NULL or 'UNKNOWN'.
        try:
            await db.execute(
                "UPDATE scans SET risk_label = CASE "
                "WHEN risk_score IS NULL THEN 'UNKNOWN' "
                "WHEN risk_score < 40 THEN 'CRITICAL' "
                "WHEN risk_score < 60 THEN 'HIGH' "
                "WHEN risk_score < 80 THEN 'MEDIUM' "
                "ELSE 'LOW' END "
                "WHERE risk_label = 'UNKNOWN' OR risk_label IS NULL"
            )
        except Exception:
            pass
        await db.commit()


async def create_scan(scan_id: str, input_str: str, input_type: str) -> None:
    """Insert a new scan record with status ``queued``.

    Args:
        scan_id: Unique identifier for the scan.
        input_str: The raw target string supplied by the user.
        input_type: The detected :class:`~schemas.scan.InputType` value.
    """
    from datetime import datetime, timezone

    now = datetime.now(timezone.utc).isoformat()
    async with aiosqlite.connect(DB_PATH) as db:
        await db.execute(
            "INSERT INTO scans (id, input_str, input_type, status, created_at) "
            "VALUES (?, ?, ?, ?, ?)",
            (scan_id, input_str, input_type, "queued", now),
        )
        await db.commit()


async def update_scan_status(
    scan_id: str, status: str, risk_score: int | None = None,
    risk_label: str | None = None,
) -> None:
    """Update the status (and optionally the risk score) of a scan.

    Args:
        scan_id: Identifier of the scan to update.
        status: New status string (e.g. ``"running"``, ``"complete"``).
        risk_score: Optional 0-100 risk score to record.
        risk_label: Optional human-readable risk label (e.g. ``"HIGH"``).
    """
    from datetime import datetime, timezone

    now = datetime.now(timezone.utc).isoformat()
    async with aiosqlite.connect(DB_PATH) as db:
        await db.execute(
            "UPDATE scans SET status=?, risk_score=?, risk_label=?, completed_at=? WHERE id=?",
            (
                status,
                risk_score,
                risk_label,
                now if status in ("complete", "failed") else None,
                scan_id,
            ),
        )
        await db.commit()


async def save_findings(scan_id: str, findings: list[ScanFinding]) -> None:
    """Persist a list of findings linked to *scan_id*.

    Args:
        scan_id: The parent scan identifier.
        findings: Normalised findings to store.
    """
    rows = [
        (
            f.id,
            scan_id,
            f.tool,
            f.severity.value,
            f.cwe,
            f.title,
            f.description,
            f.file_path,
            f.line_number,
            f.evidence,
            f.fp_score,
            f.remediation,
        )
        for f in findings
    ]
    async with aiosqlite.connect(DB_PATH) as db:
        await db.executemany(
            "INSERT OR IGNORE INTO findings "
            "(id, scan_id, tool, severity, cwe, title, description, file_path, "
            "line_number, evidence, fp_score, remediation) "
            "VALUES (?,?,?,?,?,?,?,?,?,?,?,?)",
            rows,
        )
        await db.commit()


async def get_scan(scan_id: str) -> dict[str, Any] | None:
    """Retrieve scan metadata and its findings.

    Args:
        scan_id: Identifier of the scan to look up.

    Returns:
        A dict containing scan metadata and a ``findings`` list, or ``None``
        if no scan with that ID exists.
    """
    async with aiosqlite.connect(DB_PATH) as db:
        db.row_factory = aiosqlite.Row
        async with db.execute(
            "SELECT * FROM scans WHERE id=?", (scan_id,)
        ) as cursor:
            row = await cursor.fetchone()
        if row is None:
            return None
        scan = dict(row)

        async with db.execute(
            "SELECT * FROM findings WHERE scan_id=?", (scan_id,)
        ) as cursor:
            finding_rows = await cursor.fetchall()
        scan["findings"] = [dict(r) for r in finding_rows]
        return scan


async def get_scan_history(
    input_str: str | None = None, limit: int = 20
) -> list[dict[str, Any]]:
    """Return the most recent scans, optionally filtered by *input_str*.

    Each returned dict includes a ``finding_count`` key with the number of
    findings associated with that scan.

    Args:
        input_str: When provided, only scans with this target string are
            returned.  When ``None``, all scans are considered.
        limit: Maximum number of records to return.

    Returns:
        List of scan metadata dicts ordered newest-first.
    """
    _select = (
        "SELECT s.id, s.input_str, s.status, s.risk_score, s.risk_label, s.created_at, "
        "COUNT(f.id) AS finding_count "
        "FROM scans s LEFT JOIN findings f ON f.scan_id = s.id "
    )
    async with aiosqlite.connect(DB_PATH) as db:
        db.row_factory = aiosqlite.Row
        if input_str is not None:
            query = _select + "WHERE s.input_str=? GROUP BY s.id ORDER BY s.created_at DESC LIMIT ?"
            params: tuple[Any, ...] = (input_str, limit)
        else:
            query = _select + "GROUP BY s.id ORDER BY s.created_at DESC LIMIT ?"
            params = (limit,)
        async with db.execute(query, params) as cursor:
            rows = await cursor.fetchall()
    return [dict(r) for r in rows]
