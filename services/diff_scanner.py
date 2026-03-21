"""Diff scanner: classify findings introduced or fixed between two commits."""

from __future__ import annotations

import asyncio
import logging
import os
import shutil
import tempfile
import uuid
from dataclasses import dataclass, field

import git

from schemas.finding import ScanFinding, SeverityLevel
from services.scanners.semgrep_scanner import SemgrepScanner

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Result model
# ---------------------------------------------------------------------------


@dataclass
class DiffScanResult:
    """Result of a diff-aware scan between two commits.

    Attributes:
        new_findings: Findings present in head but not in base.
        fixed_findings: Findings present in base but not in head.
        worsened_findings: Findings at the same location but higher severity
            in head than in base.
        existing_count: Number of findings present in both base and head.
    """

    new_findings: list[ScanFinding] = field(default_factory=list)
    fixed_findings: list[ScanFinding] = field(default_factory=list)
    worsened_findings: list[ScanFinding] = field(default_factory=list)
    existing_count: int = 0


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

_SEVERITY_ORDER: dict[SeverityLevel, int] = {
    SeverityLevel.INFO: 0,
    SeverityLevel.LOW: 1,
    SeverityLevel.MEDIUM: 2,
    SeverityLevel.HIGH: 3,
    SeverityLevel.CRITICAL: 4,
}


def _finding_key(f: ScanFinding) -> tuple[str, str | None, int | None]:
    """Return a stable identity key for *f* based on title, path, and line.

    Args:
        f: The finding to key.

    Returns:
        A tuple ``(title, file_path, line_number)`` suitable for use in a set.
    """
    return (f.title, f.file_path, f.line_number)


async def _scan_at_revision(
    repo: git.Repo,
    revision: str,
    changed_py_files: list[str],
    tmp_root: str,
) -> list[ScanFinding]:
    """Check out *revision* and run Semgrep on *changed_py_files*.

    Args:
        repo: A :class:`git.Repo` instance for the target repository.
        revision: The commit SHA to check out.
        changed_py_files: Repo-relative paths of Python files to scan.
        tmp_root: Temporary directory for writing file snapshots.

    Returns:
        List of :class:`~schemas.finding.ScanFinding` from the scan.
    """
    if not changed_py_files:
        return []

    scan_dir = os.path.join(tmp_root, revision[:12])
    os.makedirs(scan_dir, exist_ok=True)

    # Write each file at the requested revision into scan_dir.
    for rel_path in changed_py_files:
        try:
            blob_data: str = repo.git.show(f"{revision}:{rel_path}")
        except git.GitCommandError:
            # File may not exist at this revision (newly added / already deleted).
            continue
        dest = os.path.join(scan_dir, os.path.basename(rel_path))
        with open(dest, "w", encoding="utf-8") as fh:
            fh.write(blob_data)

    if not os.listdir(scan_dir):
        return []

    scanner = SemgrepScanner()
    return await scanner.run(scan_dir)


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------


async def scan_diff(
    repo_path: str,
    base_sha: str,
    head_sha: str,
) -> DiffScanResult:
    """Run a diff-aware scan between *base_sha* and *head_sha*.

    Only ``.py`` files that changed between the two commits are scanned.
    Findings are classified as NEW, FIXED, WORSENED, or EXISTING by
    comparing the two sets.

    Args:
        repo_path: Filesystem path to a git repository.
        base_sha: The base commit SHA.
        head_sha: The head (newer) commit SHA.

    Returns:
        A :class:`DiffScanResult` with findings classified by change type.
    """
    repo = git.Repo(repo_path)

    # Step A — find changed Python files.
    raw_diff: str = repo.git.diff(
        base_sha, head_sha, "--unified=0", "--name-only"
    )
    changed_files = [line for line in raw_diff.split("\n") if line.strip()]
    changed_py_files = [f for f in changed_files if f.endswith(".py")]

    scan_id = str(uuid.uuid4())
    tmp_root = os.path.join(tempfile.gettempdir(), f"diff_{scan_id}")
    try:
        os.makedirs(tmp_root, exist_ok=True)

        # Step B — scan each revision.
        base_findings, head_findings = await _gather_findings(
            repo, base_sha, head_sha, changed_py_files, tmp_root
        )

        # Step C — classify.
        return _classify(base_findings, head_findings)

    finally:
        shutil.rmtree(tmp_root, ignore_errors=True)


async def _gather_findings(
    repo: git.Repo,
    base_sha: str,
    head_sha: str,
    changed_py_files: list[str],
    tmp_root: str,
) -> tuple[list[ScanFinding], list[ScanFinding]]:
    """Run scans at both revisions concurrently.

    Args:
        repo: Git repository handle.
        base_sha: Base commit SHA.
        head_sha: Head commit SHA.
        changed_py_files: Python files to scan.
        tmp_root: Temporary directory root.

    Returns:
        Tuple of ``(base_findings, head_findings)``.
    """
    base_task = _scan_at_revision(repo, base_sha, changed_py_files, tmp_root)
    head_task = _scan_at_revision(repo, head_sha, changed_py_files, tmp_root)
    base_findings, head_findings = await asyncio.gather(base_task, head_task)
    return base_findings, head_findings


def _classify(
    base_findings: list[ScanFinding],
    head_findings: list[ScanFinding],
) -> DiffScanResult:
    """Classify findings into NEW, FIXED, WORSENED, and EXISTING.

    Args:
        base_findings: Findings at the base revision.
        head_findings: Findings at the head revision.

    Returns:
        A populated :class:`DiffScanResult`.
    """
    base_by_key: dict[tuple, ScanFinding] = {
        _finding_key(f): f for f in base_findings
    }
    head_by_key: dict[tuple, ScanFinding] = {
        _finding_key(f): f for f in head_findings
    }

    base_keys = set(base_by_key)
    head_keys = set(head_by_key)

    new_findings: list[ScanFinding] = [
        head_by_key[k] for k in head_keys - base_keys
    ]
    fixed_findings: list[ScanFinding] = [
        base_by_key[k] for k in base_keys - head_keys
    ]
    worsened_findings: list[ScanFinding] = []
    existing_count = 0

    for key in base_keys & head_keys:
        base_f = base_by_key[key]
        head_f = head_by_key[key]
        if _SEVERITY_ORDER[head_f.severity] > _SEVERITY_ORDER[base_f.severity]:
            worsened_findings.append(head_f)
        else:
            existing_count += 1

    return DiffScanResult(
        new_findings=new_findings,
        fixed_findings=fixed_findings,
        worsened_findings=worsened_findings,
        existing_count=existing_count,
    )
