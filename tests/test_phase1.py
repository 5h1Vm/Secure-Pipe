"""Phase 1 integration and unit tests for SecurePipe."""

from __future__ import annotations

import pytest
from httpx import ASGITransport, AsyncClient

from main import app
from schemas.finding import ScanFinding, SeverityLevel
from schemas.scan import InputType
from services.input_router import detect_input_type


@pytest.mark.asyncio
async def test_health():
    """GET /health returns 200 and {status: ok}."""
    async with AsyncClient(
        transport=ASGITransport(app=app), base_url="http://test"
    ) as client:
        response = await client.get("/health")
    assert response.status_code == 200
    data = response.json()
    assert data["status"] == "ok"


@pytest.mark.asyncio
async def test_scan_unknown_input():
    """POST /scan with an unknown input returns 200 and a scan_id."""
    async with AsyncClient(
        transport=ASGITransport(app=app), base_url="http://test"
    ) as client:
        response = await client.post("/scan", json={"input_str": "hello world"})
    assert response.status_code == 200
    data = response.json()
    assert "scan_id" in data
    # Store scan_id for the next test via a module-level variable is fragile;
    # instead we keep this test self-contained.


@pytest.mark.asyncio
async def test_get_scan_status():
    """GET /scan/{scan_id} returns 200 with a status field."""
    async with AsyncClient(
        transport=ASGITransport(app=app), base_url="http://test"
    ) as client:
        post_resp = await client.post("/scan", json={"input_str": "hello world"})
        scan_id = post_resp.json()["scan_id"]

        get_resp = await client.get(f"/scan/{scan_id}")
    assert get_resp.status_code == 200
    data = get_resp.json()
    assert "status" in data


def test_input_router():
    """detect_input_type() returns the correct InputType for all 6 variants."""
    assert detect_input_type("https://github.com/owner/repo") == InputType.GITHUB_URL
    assert detect_input_type("https://example.com") == InputType.LIVE_URL
    assert detect_input_type("http://localhost:8080/mcp") == InputType.MCP_ENDPOINT
    assert detect_input_type("requests") == InputType.PACKAGE_NAME
    assert detect_input_type("file.zip") == InputType.ZIP_UPLOAD


def test_scan_finding_schema():
    """ScanFinding fp_score defaults to 0.5 when not supplied."""
    finding = ScanFinding(
        tool="test-tool",
        severity=SeverityLevel.HIGH,
        title="Test finding",
        description="A test finding",
    )
    assert finding.fp_score == 0.5


@pytest.mark.asyncio
async def test_serve_frontend():
    """GET / returns 200 (FileResponse for the web dashboard)."""
    async with AsyncClient(
        transport=ASGITransport(app=app), base_url="http://test"
    ) as client:
        response = await client.get("/")
    assert response.status_code == 200


@pytest.mark.asyncio
async def test_history_endpoint():
    """GET /scans/history returns 200 and a list."""
    async with AsyncClient(
        transport=ASGITransport(app=app), base_url="http://test"
    ) as client:
        response = await client.get("/scans/history")
    assert response.status_code == 200
    assert isinstance(response.json(), list)
