"""Risk score computation from a list of scan findings."""

from __future__ import annotations

from dataclasses import dataclass
from typing import List

from schemas.finding import ScanFinding, SeverityLevel

_DEDUCTIONS: dict[SeverityLevel, int] = {
    SeverityLevel.CRITICAL: 25,
    SeverityLevel.HIGH: 10,
    SeverityLevel.MEDIUM: 4,
    SeverityLevel.LOW: 1,
    SeverityLevel.INFO: 0,
}

_CAPS: dict[SeverityLevel, int] = {
    SeverityLevel.CRITICAL: 100,
    SeverityLevel.HIGH: 80,
    SeverityLevel.MEDIUM: 40,
    SeverityLevel.LOW: 20,
    SeverityLevel.INFO: 0,
}


@dataclass
class RiskResult:
    """Result of a risk score computation."""

    score: int
    label: str  # "CRITICAL" <40, "HIGH" 40-60, "MEDIUM" 60-80, "LOW" >80


def _risk_label(score: int) -> str:
    """Derive a human-readable risk label from a numeric score.

    Args:
        score: Integer risk score in ``[0, 100]``.

    Returns:
        ``"CRITICAL"`` for score < 40, ``"HIGH"`` for 40–59,
        ``"MEDIUM"`` for 60–79, ``"LOW"`` for ≥ 80.
    """
    if score < 40:
        return "CRITICAL"
    if score < 60:
        return "HIGH"
    if score < 80:
        return "MEDIUM"
    return "LOW"


def compute_risk_score(findings: List[ScanFinding]) -> RiskResult:
    """Compute a 0-100 risk score from *findings*.

    Starts at 100 and deducts points per finding based on severity.
    Per-tier deductions are capped so that a large number of low-severity
    findings cannot drive the score to zero on their own.
    Findings with ``fp_score > 0.8`` (likely false positives) have their
    deduction reduced by 70% (i.e., only 30% of the normal deduction applies).

    Args:
        findings: Normalised findings produced by any scanner.

    Returns:
        A :class:`RiskResult` with an integer ``score`` clamped to
        ``[0, 100]`` and a human-readable ``label``.
    """
    score = 100
    tier_totals: dict[SeverityLevel, float] = {s: 0.0 for s in SeverityLevel}
    for f in findings:
        deduction: float = _DEDUCTIONS[f.severity]
        if f.fp_score > 0.8:
            deduction *= 0.30
        tier_totals[f.severity] += deduction
    for severity, total in tier_totals.items():
        capped = min(total, _CAPS[severity])
        score -= capped
    final = max(0, min(100, int(score)))
    return RiskResult(score=final, label=_risk_label(final))
