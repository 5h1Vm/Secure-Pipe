"""File scanning via VirusTotal and MalwareBazaar."""

from __future__ import annotations

import asyncio
import hashlib
import os
from typing import List

import httpx

from schemas.finding import ScanFinding, SeverityLevel

VT_KEY: str = os.getenv("VIRUSTOTAL_API_KEY", "")
VT_BASE: str = "https://www.virustotal.com/api/v3"
MB_BASE: str = "https://mb-api.abuse.ch/api/v1/"


async def compute_sha256(file_path: str) -> str:
    """Compute the SHA-256 hash of a file using chunked reading.

    Args:
        file_path: Absolute path to the file.

    Returns:
        Lowercase hexadecimal SHA-256 digest string.
    """
    h = hashlib.sha256()
    with open(file_path, "rb") as f:
        for chunk in iter(lambda: f.read(8192), b""):
            h.update(chunk)
    return h.hexdigest()


async def check_malwarebazaar(sha256: str) -> List[ScanFinding]:
    """Instant hash lookup against MalwareBazaar — free, no rate limit.

    Args:
        sha256: SHA-256 hash string to query.

    Returns:
        A list containing a CRITICAL :class:`~schemas.finding.ScanFinding`
        when the hash is found in MalwareBazaar, otherwise an empty list.
    """
    async with httpx.AsyncClient(timeout=10) as client:
        r = await client.post(MB_BASE, data={"query": "get_info", "hash": sha256})
        data = r.json()
    if data.get("query_status") == "hash_not_found":
        return []
    if data.get("query_status") == "ok":
        info = data["data"][0]
        return [ScanFinding(
            tool="malwarebazaar",
            severity=SeverityLevel.CRITICAL,
            cwe="MALWARE:KNOWN",
            title=f"Known malware: {info.get('signature', 'Unknown')}",
            description=(
                f"Hash {sha256} found in MalwareBazaar. "
                f"Type: {info.get('file_type')} "
                f"Tags: {', '.join(info.get('tags') or [])}"
            ),
            evidence=sha256,
            file_path=f"file://{sha256}",
        )]
    return []


async def check_virustotal_hash(sha256: str) -> List[ScanFinding]:
    """Check a hash against VirusTotal — uses 1 of 4/min free quota.

    Args:
        sha256: SHA-256 hash string to query.

    Returns:
        A list with a finding when detections are reported, empty otherwise.
        Returns an empty list immediately when ``VIRUSTOTAL_API_KEY`` is not set.
    """
    vt_key = os.getenv("VIRUSTOTAL_API_KEY", "")
    if not vt_key:
        return []
    async with httpx.AsyncClient(timeout=15) as client:
        r = await client.get(
            f"{VT_BASE}/files/{sha256}",
            headers={"x-apikey": vt_key},
        )
    if r.status_code == 404:
        return []  # Unknown to VT — not necessarily clean
    if r.status_code != 200:
        return []
    data = r.json()["data"]["attributes"]
    stats = data.get("last_analysis_stats", {})
    malicious = stats.get("malicious", 0)
    suspicious = stats.get("suspicious", 0)
    total = sum(stats.values()) or 1
    if malicious == 0 and suspicious == 0:
        return []
    severity = SeverityLevel.CRITICAL if malicious > 3 else SeverityLevel.HIGH
    return [ScanFinding(
        tool="virustotal",
        severity=severity,
        cwe="MALWARE:VT",
        title=f"VirusTotal: {malicious}/{total} engines flagged as malicious",
        description=(
            f"Malicious: {malicious}, Suspicious: {suspicious}, "
            f"Clean: {stats.get('harmless', 0)}"
        ),
        evidence=sha256,
        file_path=f"file://{sha256}",
    )]


async def submit_file_virustotal(file_path: str) -> List[ScanFinding]:
    """Submit an unknown file to VirusTotal for a fresh scan.

    Polls for results up to 60 seconds (12 × 5 s intervals).

    Args:
        file_path: Path to the file to submit.

    Returns:
        A list with a CRITICAL finding when malicious engines are found,
        empty otherwise. Returns immediately when ``VIRUSTOTAL_API_KEY``
        is not set.
    """
    vt_key = os.getenv("VIRUSTOTAL_API_KEY", "")
    if not vt_key:
        return []
    async with httpx.AsyncClient(timeout=30) as client:
        with open(file_path, "rb") as f:
            r = await client.post(
                f"{VT_BASE}/files",
                headers={"x-apikey": vt_key},
                files={"file": f},
            )
    if r.status_code not in (200, 201):
        return []
    analysis_id = r.json()["data"]["id"]
    # Poll for results (max 60 s)
    for _ in range(12):
        await asyncio.sleep(5)
        async with httpx.AsyncClient(timeout=10) as client:
            r2 = await client.get(
                f"{VT_BASE}/analyses/{analysis_id}",
                headers={"x-apikey": vt_key},
            )
        result = r2.json()["data"]
        if result["attributes"]["status"] == "completed":
            stats = result["attributes"]["stats"]
            malicious = stats.get("malicious", 0)
            if malicious > 0:
                return [ScanFinding(
                    tool="virustotal",
                    severity=SeverityLevel.CRITICAL,
                    cwe="MALWARE:VT_SUBMITTED",
                    title=f"VirusTotal scan: {malicious} engines flagged",
                    description=str(stats),
                    evidence=analysis_id,
                    file_path=file_path,
                )]
            return []
    return []


async def scan_file(file_path: str) -> List[ScanFinding]:
    """Full file scan pipeline.

    Steps:
    1. Compute SHA-256.
    2. Check MalwareBazaar (instant, free).
    3. If known malware → return immediately (save VT quota).
    4. If unknown → check VT hash lookup.
    5. If not in VT → submit file to VT for a fresh scan.

    Args:
        file_path: Absolute path to the file to scan.

    Returns:
        Combined list of :class:`~schemas.finding.ScanFinding`.
    """
    sha256 = await compute_sha256(file_path)

    mb_findings = await check_malwarebazaar(sha256)
    if mb_findings:
        return mb_findings  # Known malware — no need to use VT quota

    vt_findings = await check_virustotal_hash(sha256)
    if vt_findings:
        return vt_findings

    # Unknown to both — submit to VT for fresh analysis
    return await submit_file_virustotal(file_path)
