"""Tests for the risk score computation (services/risk_score.py)."""

from __future__ import annotations

import pytest

from schemas.finding import ScanFinding, SeverityLevel
from services.risk_score import RiskResult, compute_risk_score


def _make_finding(severity: SeverityLevel, fp_score: float = 0.5) -> ScanFinding:
    """Create a minimal ScanFinding for testing."""
    return ScanFinding(
        tool="test",
        severity=severity,
        title="test",
        description="test",
        fp_score=fp_score,
    )


def test_low_findings_capped() -> None:
    """100 LOW findings must not drive the score to zero (cap = 20 pts)."""
    findings = [_make_finding(SeverityLevel.LOW) for _ in range(100)]
    result = compute_risk_score(findings)
    assert isinstance(result, RiskResult)
    # cap for LOW is 20, so score = 100 - 20 = 80
    assert result.score > 70


def test_critical_dominates() -> None:
    """4 CRITICAL findings (4 × 25 = 100 pts, capped at 100) → score == 0."""
    findings = [_make_finding(SeverityLevel.CRITICAL) for _ in range(4)]
    result = compute_risk_score(findings)
    assert result.score == 0


def test_fp_reduces_deduction() -> None:
    """A CRITICAL finding with fp_score=0.9 should have only 30% deduction."""
    findings = [_make_finding(SeverityLevel.CRITICAL, fp_score=0.9)]
    result = compute_risk_score(findings)
    # 0.30 × 25 = 7.5, score ≈ 92
    assert result.score > 75


def test_risk_label() -> None:
    """Risk labels are assigned correctly by score range."""
    # score < 40 → CRITICAL
    critical_findings = [_make_finding(SeverityLevel.CRITICAL) for _ in range(3)]
    result = compute_risk_score(critical_findings)
    assert result.label == "CRITICAL"

    # score > 80 → LOW
    empty_result = compute_risk_score([])
    assert empty_result.score == 100
    assert empty_result.label == "LOW"
