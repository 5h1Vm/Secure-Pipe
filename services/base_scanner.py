"""Abstract base class for all SecurePipe scanners."""

from __future__ import annotations

import asyncio
import logging
from abc import ABC, abstractmethod
from typing import Any

from schemas.finding import ScanFinding


class BaseScanner(ABC):
    """Abstract scanner that every concrete scanner must subclass."""

    logger: logging.Logger = logging.getLogger(__name__)

    @property
    @abstractmethod
    def scanner_name(self) -> str:
        """Return the short identifier for this scanner (e.g. ``"semgrep"``)."""

    @abstractmethod
    async def run(self, target: str) -> list[ScanFinding]:
        """Execute the scanner against *target* and return normalised findings.

        Args:
            target: A filesystem path, URL, or other target string appropriate
                for the concrete scanner.

        Returns:
            A (possibly empty) list of :class:`~schemas.finding.ScanFinding`.
        """

    async def _run_subprocess(
        self, cmd: list[str], timeout: int = 300
    ) -> dict[str, Any]:
        """Run *cmd* in a subprocess and capture its output.

        Args:
            cmd: The command and arguments to execute.
            timeout: Maximum number of seconds to wait before terminating.

        Returns:
            A dict with keys ``stdout`` (str), ``stderr`` (str), and
            ``returncode`` (int).
        """
        proc = await asyncio.create_subprocess_exec(
            *cmd,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
        try:
            stdout_bytes, stderr_bytes = await asyncio.wait_for(
                proc.communicate(), timeout=timeout
            )
        except asyncio.TimeoutError:
            proc.kill()
            await proc.communicate()
            self.logger.warning(
                "Scanner %s timed out after %ds: %s",
                self.scanner_name,
                timeout,
                " ".join(cmd),
            )
            return {"stdout": "", "stderr": "timeout", "returncode": -1}

        return {
            "stdout": stdout_bytes.decode("utf-8", errors="replace"),
            "stderr": stderr_bytes.decode("utf-8", errors="replace"),
            "returncode": proc.returncode,
        }
