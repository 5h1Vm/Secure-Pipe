"""Risk score computation from a list of scan findings."""

from __future__ import annotations

from typing import List

from schemas.finding import ScanFinding, SeverityLevel

_DEDUCTIONS: dict[SeverityLevel, int] = {
    SeverityLevel.CRITICAL: 25,
    SeverityLevel.HIGH: 10,
    SeverityLevel.MEDIUM: 4,
    SeverityLevel.LOW: 1,
    SeverityLevel.INFO: 0,
}


def compute_risk_score(findings: List[ScanFinding]) -> int:
    """Compute a 0-100 risk score from *findings*.

    Starts at 100 and deducts points per finding based on severity.
    Findings with ``fp_score > 0.8`` (likely false positives) have their
    deduction reduced by 70% (i.e., only 30% of the normal deduction applies).

    Args:
        findings: Normalised findings produced by any scanner.

    Returns:
        An integer risk score clamped to ``[0, 100]``.
    """
    score = 100
    for finding in findings:
        deduction = _DEDUCTIONS.get(finding.severity, 0)
        if finding.fp_score > 0.8:
            deduction = round(deduction * 0.3)
        score -= deduction
    return max(0, min(100, score))
