"""MCP server exposure for SecurePipe using fastmcp."""

from __future__ import annotations

import asyncio
import json

import httpx
from mcp.server.fastmcp import FastMCP

mcp = FastMCP("SecurePipe")

_BASE = "http://localhost:8000"


@mcp.tool()
async def scan_repo(github_url: str) -> str:
    """Scan a GitHub repository for security vulnerabilities.

    Returns a JSON string with scan_id, risk_score, and finding count.

    Args:
        github_url: The GitHub repository URL to scan.
    """
    async with httpx.AsyncClient() as client:
        r = await client.post(f"{_BASE}/scan", json={"input_str": github_url})
        scan_id: str = r.json()["scan_id"]
        for _ in range(60):
            await asyncio.sleep(3)
            s = await client.get(f"{_BASE}/scan/{scan_id}")
            if s.json()["status"] not in ("queued", "running"):
                break
        report = await client.get(f"{_BASE}/report/{scan_id}")
        d = report.json()
        return json.dumps(
            {
                "scan_id": scan_id,
                "risk_score": d.get("risk_score"),
                "finding_count": d.get("finding_count"),
                "status": d.get("status"),
            }
        )


@mcp.tool()
async def scan_mcp_server(mcp_url: str) -> str:
    """Scan an MCP server endpoint for OWASP MCP Top 10 vulnerabilities.

    Args:
        mcp_url: The MCP server endpoint URL to scan.
    """
    async with httpx.AsyncClient() as client:
        r = await client.post(f"{_BASE}/scan", json={"input_str": mcp_url})
        scan_id: str = r.json()["scan_id"]
        for _ in range(30):
            await asyncio.sleep(2)
            s = await client.get(f"{_BASE}/scan/{scan_id}")
            if s.json()["status"] not in ("queued", "running"):
                break
        report = await client.get(f"{_BASE}/report/{scan_id}")
        d = report.json()
        return json.dumps(
            {
                "scan_id": scan_id,
                "risk_score": d.get("risk_score"),
                "finding_count": d.get("finding_count"),
                "critical_count": sum(
                    1
                    for f in d.get("findings", [])
                    if f.get("severity") == "CRITICAL"
                ),
            }
        )


@mcp.tool()
async def get_report(scan_id: str) -> str:
    """Get the full security report for a completed scan.

    Args:
        scan_id: The UUID of the completed scan.
    """
    async with httpx.AsyncClient() as client:
        r = await client.get(f"{_BASE}/report/{scan_id}")
        return json.dumps(r.json())


@mcp.tool()
def get_scan_history() -> str:
    """Get the last 20 scans with their risk scores."""
    r = httpx.get(f"{_BASE}/scan/history")
    return json.dumps(r.json())
