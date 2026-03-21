"""Tests for the supply-chain scanner (Phase 5)."""

from __future__ import annotations

import pytest

from schemas.finding import SeverityLevel
from services.supply_chain import _levenshtein, check_slopsquat


def test_levenshtein_exact_match() -> None:
    """_levenshtein returns 0 for identical strings."""
    assert _levenshtein("abc", "abc") == 0


def test_levenshtein_one_edit() -> None:
    """_levenshtein returns 1 for a single insertion."""
    assert _levenshtein("flask", "flaask") == 1


def test_slopsquat_known_hallucinated() -> None:
    """check_slopsquat flags 'huggingface' as CRITICAL with cwe SC02:2025."""
    findings = check_slopsquat(["huggingface"])
    assert any(f.cwe == "SC02:2025" for f in findings)
    assert any(f.severity == SeverityLevel.CRITICAL for f in findings)


def test_slopsquat_clean_package() -> None:
    """check_slopsquat returns no findings for a legitimate popular package."""
    findings = check_slopsquat(["requests"])
    assert findings == []


def test_slopsquat_typosquat() -> None:
    """check_slopsquat flags 'requets' (edit distance 1 from 'requests') as HIGH."""
    findings = check_slopsquat(["requets"])
    assert any(f.severity == SeverityLevel.HIGH for f in findings)


@pytest.mark.asyncio
async def test_osv_clean_package(httpx_mock) -> None:
    """check_osv returns empty list when OSV API reports no vulnerabilities."""
    from services.supply_chain import check_osv

    httpx_mock.add_response(
        method="POST",
        json={"vulns": []},
    )

    findings = await check_osv("requests", None, "PyPI")
    assert findings == []


@pytest.mark.asyncio
async def test_osv_known_vuln(httpx_mock) -> None:
    """check_osv returns a HIGH finding when OSV reports a known CVE."""
    from services.supply_chain import check_osv

    httpx_mock.add_response(
        method="POST",
        json={
            "vulns": [
                {
                    "id": "GHSA-xxxx-yyyy-zzzz",
                    "aliases": ["CVE-2023-12345"],
                    "summary": "Remote code execution in fakelib",
                    "severity": [],
                }
            ]
        },
    )

    findings = await check_osv("fakelib", None, "PyPI")
    assert len(findings) == 1
    assert findings[0].severity == SeverityLevel.HIGH
    assert "CVE-2023-12345" in findings[0].cwe
