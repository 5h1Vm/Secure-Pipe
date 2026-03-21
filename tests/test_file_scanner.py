"""Tests for the file scanner (services/file_scanner.py)."""

from __future__ import annotations

import hashlib
import os
import tempfile

import pytest


@pytest.mark.asyncio
async def test_compute_sha256() -> None:
    """compute_sha256 returns the correct hex digest for a known file."""
    from services.file_scanner import compute_sha256

    content = b"hello securepipe"
    expected = hashlib.sha256(content).hexdigest()

    with tempfile.NamedTemporaryFile(delete=False) as tmp:
        tmp.write(content)
        tmp_path = tmp.name

    try:
        result = await compute_sha256(tmp_path)
        assert result == expected
    finally:
        os.unlink(tmp_path)


@pytest.mark.asyncio
async def test_malwarebazaar_clean(httpx_mock) -> None:
    """check_malwarebazaar returns empty list when hash is not found."""
    from services.file_scanner import check_malwarebazaar

    httpx_mock.add_response(
        method="POST",
        json={"query_status": "hash_not_found"},
    )

    findings = await check_malwarebazaar("abc123deadbeef")
    assert findings == []


@pytest.mark.asyncio
async def test_malwarebazaar_hit(httpx_mock) -> None:
    """check_malwarebazaar returns a CRITICAL finding when hash is matched."""
    from schemas.finding import SeverityLevel
    from services.file_scanner import check_malwarebazaar

    sha = "cafebabe" * 8
    httpx_mock.add_response(
        method="POST",
        json={
            "query_status": "ok",
            "data": [
                {
                    "signature": "Trojan.Test",
                    "file_type": "exe",
                    "tags": ["trojan", "test"],
                }
            ],
        },
    )

    findings = await check_malwarebazaar(sha)
    assert len(findings) == 1
    assert findings[0].severity == SeverityLevel.CRITICAL
    assert "Trojan.Test" in findings[0].title


@pytest.mark.asyncio
async def test_virustotal_skips_without_key(monkeypatch) -> None:
    """check_virustotal_hash returns empty list when VT key is not set."""
    monkeypatch.delenv("VIRUSTOTAL_API_KEY", raising=False)
    from services.file_scanner import check_virustotal_hash

    result = await check_virustotal_hash("abc123")
    assert result == []
