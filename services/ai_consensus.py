"""AI consensus engine for triage of security findings."""

from __future__ import annotations

import asyncio
import json
import logging
import os
from dataclasses import dataclass
from typing import List

from schemas.finding import ScanFinding, SeverityLevel

logger = logging.getLogger(__name__)

MODEL_ROUTING: dict[str, tuple[str, str]] = {
    "code_vulnerability": ("groq", "deepseek-r1-distill-llama-70b"),
    "secret_exposure": ("groq", "llama-3.3-70b-versatile"),
    "injection": ("groq", "deepseek-r1-distill-llama-70b"),
    "default": ("groq", "llama-3.3-70b-versatile"),
}

MODEL_WEIGHTS: dict[str, float] = {
    "deepseek-r1-distill-llama-70b": 1.0,
    "llama-3.3-70b-versatile": 1.0,
}


def get_finding_category(finding: ScanFinding) -> str:
    """Determine the routing category for a finding.

    Args:
        finding: The scan finding to categorise.

    Returns:
        One of ``"injection"``, ``"secret_exposure"``,
        ``"code_vulnerability"``, or ``"default"``.
    """
    cwe = finding.cwe or ""
    if "INJ" in cwe or "MCP03" in cwe:
        return "injection"
    if "MCP01" in cwe or finding.tool == "gitleaks":
        return "secret_exposure"
    if finding.tool in ("semgrep", "bandit"):
        return "code_vulnerability"
    return "default"


@dataclass
class TriageResult:
    """AI triage result for a single finding."""

    severity_score: float
    fp_probability: float
    remediation: str
    confidence: str
    model_used: str


async def triage_finding(finding: ScanFinding) -> TriageResult:
    """Triage a single finding using the Groq AI API.

    Falls back to a default result when ``GROQ_API_KEY`` is not set or the
    API call / JSON parsing fails.

    Args:
        finding: The scan finding to triage.

    Returns:
        A :class:`TriageResult` populated from the AI response.
    """
    api_key = os.getenv("GROQ_API_KEY")
    if not api_key:
        return TriageResult(
            severity_score=5.0,
            fp_probability=0.5,
            remediation="Set GROQ_API_KEY for AI triage",
            confidence="LOW",
            model_used="none",
        )

    system_prompt = (
        "You are a security expert. Analyze this vulnerability and return ONLY valid JSON "
        "with exactly these keys: severity_score (float 0-10), fp_probability (float 0-1, "
        "probability this is a false positive), remediation (one sentence fix). "
        "No markdown, no extra text."
    )
    user_message = (
        f"Tool: {finding.tool}\nCWE: {finding.cwe}\n"
        f"Title: {finding.title}\nDescription: {finding.description}\n"
        f"File: {finding.file_path}\nLine: {finding.line_number}"
    )

    model_name = "unknown"
    try:
        category = get_finding_category(finding)
        _, model_name = MODEL_ROUTING[category]
        from groq import AsyncGroq

        client = AsyncGroq(api_key=api_key)
        response = await client.chat.completions.create(
            model=model_name,
            messages=[
                {"role": "system", "content": system_prompt},
                {"role": "user", "content": user_message},
            ],
        )
        content = response.choices[0].message.content or ""
        data = json.loads(content)
        return TriageResult(
            severity_score=float(data.get("severity_score", 5.0)),
            fp_probability=float(data.get("fp_probability", 0.5)),
            remediation=str(data.get("remediation", "No remediation available")),
            confidence="HIGH",
            model_used=model_name,
        )
    except Exception:
        logger.exception("Failed to triage finding %s", finding.id)
        return TriageResult(
            severity_score=5.0,
            fp_probability=0.5,
            remediation="AI triage failed",
            confidence="LOW",
            model_used=model_name,
        )


async def triage_all(findings: List[ScanFinding]) -> List[ScanFinding]:
    """Triage all CRITICAL and HIGH findings using AI.

    Uses an :class:`asyncio.Semaphore` to limit concurrent Groq calls to 5.
    LOW / INFO findings are returned unchanged.

    Args:
        findings: Full list of findings from all scanners.

    Returns:
        The same list with ``fp_score`` and ``remediation`` updated for
        CRITICAL / HIGH findings.
    """
    semaphore = asyncio.Semaphore(5)

    async def _triage_one(finding: ScanFinding) -> None:
        async with semaphore:
            result = await triage_finding(finding)
            finding.fp_score = result.fp_probability
            finding.remediation = result.remediation

    tasks = [
        _triage_one(f)
        for f in findings
        if f.severity in (SeverityLevel.CRITICAL, SeverityLevel.HIGH)
    ]
    if tasks:
        await asyncio.gather(*tasks)

    return findings
