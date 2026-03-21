"""Semgrep SAST scanner."""

from __future__ import annotations

import json
import logging

from schemas.finding import ScanFinding, SeverityLevel
from services.base_scanner import BaseScanner

logger = logging.getLogger(__name__)

_SEVERITY_MAP: dict[str, SeverityLevel] = {
    "ERROR": SeverityLevel.HIGH,
    "WARNING": SeverityLevel.MEDIUM,
    "INFO": SeverityLevel.INFO,
}


class SemgrepScanner(BaseScanner):
    """Run Semgrep SAST rules against a local path."""

    scanner_name = "semgrep"

    async def run(self, target: str) -> list[ScanFinding]:
        """Run semgrep with the python and security-audit rule packs.

        Args:
            target: Filesystem path to the source tree to scan.

        Returns:
            Normalised :class:`~schemas.finding.ScanFinding` list.
        """
        cmd = [
            "semgrep",
            "--config=p/python",
            "--config=p/security-audit",
            "--json",
            target,
        ]
        result = await self._run_subprocess(cmd)

        findings: list[ScanFinding] = []
        if result["returncode"] not in (0, 1):
            logger.warning(
                "semgrep exited with code %d: %s",
                result["returncode"],
                result["stderr"][:200],
            )
            return findings

        try:
            data = json.loads(result["stdout"])
        except json.JSONDecodeError as exc:
            logger.error("Failed to parse semgrep JSON output: %s", exc)
            return findings

        for item in data.get("results", []):
            extra = item.get("extra", {})
            raw_severity = extra.get("severity", "INFO").upper()
            severity = _SEVERITY_MAP.get(raw_severity, SeverityLevel.INFO)

            metadata = extra.get("metadata", {})
            cwe_raw = metadata.get("cwe")
            if isinstance(cwe_raw, list):
                cwe = cwe_raw[0] if cwe_raw else None
            else:
                cwe = cwe_raw

            findings.append(
                ScanFinding(
                    tool=self.scanner_name,
                    severity=severity,
                    cwe=cwe,
                    title=item.get("check_id", "unknown"),
                    description=extra.get("message", ""),
                    file_path=item.get("path"),
                    line_number=item.get("start", {}).get("line"),
                    scanner_raw=item,
                )
            )

        return findings
