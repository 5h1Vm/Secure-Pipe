"""Tests for the AI consensus engine (Phase 6)."""

from __future__ import annotations

import pytest

from schemas.finding import ScanFinding, SeverityLevel
from services.ai_consensus import get_finding_category, triage_all, triage_finding


def _make_finding(**kwargs) -> ScanFinding:
    """Return a minimal :class:`ScanFinding` with sensible defaults."""
    defaults: dict = {
        "tool": "test_tool",
        "severity": SeverityLevel.HIGH,
        "title": "test",
        "description": "test",
    }
    defaults.update(kwargs)
    return ScanFinding(**defaults)


def test_get_finding_category_injection():
    """A finding whose CWE contains 'INJ' is categorised as injection."""
    f = _make_finding(cwe="INJ01:2025", tool="injection_detector")
    assert get_finding_category(f) == "injection"


def test_get_finding_category_secret():
    """A finding from the gitleaks tool is categorised as secret_exposure."""
    f = _make_finding(tool="gitleaks")
    assert get_finding_category(f) == "secret_exposure"


@pytest.mark.asyncio
async def test_triage_no_api_key(monkeypatch):
    """triage_finding returns a LOW-confidence 'none' result when GROQ_API_KEY is absent."""
    monkeypatch.delenv("GROQ_API_KEY", raising=False)
    finding = _make_finding()
    result = await triage_finding(finding)
    assert result.model_used == "none"
    assert result.confidence == "LOW"


@pytest.mark.asyncio
async def test_triage_all_skips_low():
    """triage_all does not modify LOW-severity findings."""
    findings = [
        _make_finding(severity=SeverityLevel.LOW, fp_score=0.5, tool="bandit")
    ]
    result = await triage_all(findings)
    assert result[0].fp_score == 0.5
