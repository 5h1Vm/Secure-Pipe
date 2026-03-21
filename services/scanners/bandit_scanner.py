"""Bandit SAST scanner for Python code."""

from __future__ import annotations

import json
import logging

from schemas.finding import ScanFinding, SeverityLevel
from services.base_scanner import BaseScanner

logger = logging.getLogger(__name__)

_SEVERITY_MAP: dict[str, SeverityLevel] = {
    "HIGH": SeverityLevel.HIGH,
    "MEDIUM": SeverityLevel.MEDIUM,
    "LOW": SeverityLevel.LOW,
}


class BanditScanner(BaseScanner):
    """Run Bandit against a Python source tree."""

    scanner_name = "bandit"

    async def run(self, target: str) -> list[ScanFinding]:
        """Recursively scan *target* with Bandit and return normalised findings.

        Args:
            target: Filesystem path to the Python source tree.

        Returns:
            Normalised :class:`~schemas.finding.ScanFinding` list.
        """
        cmd = ["bandit", "-r", target, "-f", "json"]
        result = await self._run_subprocess(cmd)

        findings: list[ScanFinding] = []
        if result["returncode"] not in (0, 1):
            logger.warning(
                "bandit exited with code %d: %s",
                result["returncode"],
                result["stderr"][:200],
            )
            return findings

        try:
            data = json.loads(result["stdout"])
        except json.JSONDecodeError as exc:
            logger.error("Failed to parse bandit JSON output: %s", exc)
            return findings

        for item in data.get("results", []):
            raw_severity = item.get("issue_severity", "LOW").upper()
            severity = _SEVERITY_MAP.get(raw_severity, SeverityLevel.LOW)

            findings.append(
                ScanFinding(
                    tool=self.scanner_name,
                    severity=severity,
                    cwe=item.get("test_id"),
                    title=item.get("test_name", item.get("test_id", "unknown")),
                    description=item.get("issue_text", ""),
                    file_path=item.get("filename"),
                    line_number=item.get("line_number"),
                    scanner_raw=item,
                )
            )

        return findings
