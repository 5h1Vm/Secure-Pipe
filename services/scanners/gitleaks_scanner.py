"""Gitleaks secrets scanner."""

from __future__ import annotations

import json
import logging

from schemas.finding import ScanFinding, SeverityLevel
from services.base_scanner import BaseScanner

logger = logging.getLogger(__name__)


class GitleaksScanner(BaseScanner):
    """Detect secrets and credentials in a source tree with Gitleaks."""

    scanner_name = "gitleaks"

    async def run(self, target: str) -> list[ScanFinding]:
        """Scan *target* for hard-coded secrets using gitleaks.

        Args:
            target: Filesystem path to the source tree to scan.

        Returns:
            Normalised :class:`~schemas.finding.ScanFinding` list, with
            secret values truncated to 20 characters followed by ``***``.
        """
        cmd = [
            "gitleaks",
            "detect",
            "--source",
            target,
            "--report-format",
            "json",
            "--no-git",
        ]
        result = await self._run_subprocess(cmd)

        findings: list[ScanFinding] = []
        # gitleaks exits 1 when leaks are found, 0 when clean
        if result["returncode"] not in (0, 1):
            logger.warning(
                "gitleaks exited with code %d: %s",
                result["returncode"],
                result["stderr"][:200],
            )
            return findings

        stdout = result["stdout"].strip()
        if not stdout:
            return findings

        try:
            data = json.loads(stdout)
        except json.JSONDecodeError as exc:
            logger.error("Failed to parse gitleaks JSON output: %s", exc)
            return findings

        if not isinstance(data, list):
            logger.warning("Unexpected gitleaks output format")
            return findings

        for item in data:
            raw_secret: str = item.get("Secret", "") or ""
            truncated = raw_secret[:20] + "***" if raw_secret else None
            description: str = item.get("Description", "")

            findings.append(
                ScanFinding(
                    tool=self.scanner_name,
                    severity=self._map_severity(description),
                    title=description or "Secret detected",
                    description=description,
                    file_path=item.get("File"),
                    line_number=item.get("StartLine"),
                    evidence=truncated,
                    scanner_raw=item,
                )
            )

        return findings

    @staticmethod
    def _map_severity(description: str) -> SeverityLevel:
        """Map a secret description to a :class:`SeverityLevel`.

        Args:
            description: The human-readable description from gitleaks output.

        Returns:
            ``CRITICAL`` if the description contains a high-risk keyword
            (``aws``, ``private key``, ``password``, ``secret``, ``token``,
            or ``credential``); ``HIGH`` otherwise.
        """
        desc_lower = description.lower()
        critical_keywords = (
            "aws",
            "private key",
            "password",
            "secret",
            "token",
            "credential",
        )
        if any(kw in desc_lower for kw in critical_keywords):
            return SeverityLevel.CRITICAL
        return SeverityLevel.HIGH
