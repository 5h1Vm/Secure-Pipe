"""Supply-chain scanner: abandoned-package detection and slopsquat analysis."""

from __future__ import annotations

import asyncio
import logging
import os
from datetime import datetime, timezone
from typing import List

import httpx

from schemas.finding import ScanFinding, SeverityLevel

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

KNOWN_HALLUCINATED: set[str] = {
    "huggingface",
    "pytorch-lightning-bolts",
    "langchain-openai-tools",
    "openai-tools",
    "transformers-utils",
    "llm-tools",
    "ai-utils",
    "gpt-utils",
    "chatgpt",
    "langchain-utils",
    "openai-helper",
    "anthropic-sdk",
    "claude-api",
    "gpt4-api",
    "llama-index-tools",
    "fastapi-ai",
    "pydantic-ai-tools",
    "semantic-kernel-tools",
}

TOP_PACKAGES: list[str] = [
    "requests",
    "numpy",
    "pandas",
    "flask",
    "django",
    "fastapi",
    "sqlalchemy",
    "pytest",
    "boto3",
    "urllib3",
    "certifi",
    "setuptools",
    "pip",
    "wheel",
    "six",
    "python-dateutil",
    "pytz",
    "pyyaml",
    "click",
    "rich",
    "httpx",
    "pydantic",
    "uvicorn",
    "starlette",
    "aiohttp",
    "cryptography",
    "paramiko",
    "pillow",
    "matplotlib",
    "scipy",
]


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _levenshtein(a: str, b: str) -> int:
    """Compute the Levenshtein edit distance between *a* and *b*.

    Args:
        a: First string.
        b: Second string.

    Returns:
        Minimum number of single-character edits (insert, delete, replace)
        required to transform *a* into *b*.
    """
    m, n = len(a), len(b)
    # Allocate a (m+1) x (n+1) DP table.
    dp: list[list[int]] = [[0] * (n + 1) for _ in range(m + 1)]

    for i in range(m + 1):
        dp[i][0] = i
    for j in range(n + 1):
        dp[0][j] = j

    for i in range(1, m + 1):
        for j in range(1, n + 1):
            if a[i - 1] == b[j - 1]:
                dp[i][j] = dp[i - 1][j - 1]
            else:
                dp[i][j] = 1 + min(dp[i - 1][j], dp[i][j - 1], dp[i - 1][j - 1])

    return dp[m][n]


def _parse_requirements_txt(path: str) -> list[str]:
    """Parse package names from *requirements.txt*.

    Args:
        path: Filesystem path to requirements.txt.

    Returns:
        List of bare package names (version specifiers stripped).
    """
    packages: list[str] = []
    with open(path, encoding="utf-8") as fh:
        for raw in fh:
            line = raw.strip()
            if not line or line.startswith("#"):
                continue
            # Strip extras, version specifiers, and environment markers.
            for sep in ("==", ">=", "<=", "!=", "~=", ">", "<", "[", ";", " "):
                line = line.split(sep)[0]
            name = line.strip()
            if name:
                packages.append(name)
    return packages


def _parse_package_json(path: str) -> list[str]:
    """Parse package names from *package.json*.

    Args:
        path: Filesystem path to package.json.

    Returns:
        List of bare package names from dependencies and devDependencies.
    """
    import json

    with open(path, encoding="utf-8") as fh:
        data = json.load(fh)

    packages: list[str] = []
    for key in ("dependencies", "devDependencies"):
        packages.extend(data.get(key, {}).keys())
    return packages


async def _check_single_package(package_name: str) -> ScanFinding | None:
    """Query PyPI for *package_name* and return a finding if it is abandoned.

    Args:
        package_name: The PyPI package name to check.

    Returns:
        A :class:`~schemas.finding.ScanFinding` when the package is abandoned
        (last release > 12 months ago), otherwise ``None``.
    """
    url = f"https://pypi.org/pypi/{package_name}/json"
    try:
        async with httpx.AsyncClient(timeout=5.0) as client:
            response = await client.get(url)
            if response.status_code != 200:
                return None
            data = response.json()
    except Exception:
        logger.debug("PyPI lookup failed for %s", package_name)
        return None

    releases: dict = data.get("releases", {})
    if not releases:
        return None

    latest_date: datetime | None = None
    for version_files in releases.values():
        for file_info in version_files:
            upload_time_str = file_info.get("upload_time_iso_8601") or file_info.get(
                "upload_time"
            )
            if not upload_time_str:
                continue
            try:
                # Normalise to aware datetime.
                upload_time = datetime.fromisoformat(
                    upload_time_str.replace("Z", "+00:00")
                )
                if upload_time.tzinfo is None:
                    upload_time = upload_time.replace(tzinfo=timezone.utc)
                if latest_date is None or upload_time > latest_date:
                    latest_date = upload_time
            except ValueError:
                continue

    if latest_date is None:
        return None

    now = datetime.now(tz=timezone.utc)
    age_days = (now - latest_date).days
    if age_days > 365:
        return ScanFinding(
            tool="supply_chain",
            severity=SeverityLevel.MEDIUM,
            cwe="SC01:2025",
            title=f"Abandoned package: {package_name}",
            description="Last release was over 12 months ago",
            file_path=f"supply_chain://{package_name}",
        )

    return None


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------


async def check_dependencies(project_path: str) -> List[ScanFinding]:
    """Detect abandoned dependencies in *project_path*.

    Looks for ``requirements.txt``, ``setup.py``, ``pyproject.toml``
    (Python) or ``package.json`` (Node).  For each discovered package, the
    PyPI JSON API is queried concurrently.  Packages whose most-recent release
    is older than 12 months are returned as MEDIUM findings.

    Args:
        project_path: Filesystem path to the root of the project.

    Returns:
        A (possibly empty) list of :class:`~schemas.finding.ScanFinding`.
    """
    package_names: list[str] = []

    req_txt = os.path.join(project_path, "requirements.txt")
    pkg_json = os.path.join(project_path, "package.json")

    if os.path.exists(req_txt):
        package_names.extend(_parse_requirements_txt(req_txt))
    elif os.path.exists(pkg_json):
        package_names.extend(_parse_package_json(pkg_json))
    elif os.path.exists(os.path.join(project_path, "setup.py")):
        # setup.py is present but we rely on requirements.txt for simplicity.
        logger.debug("setup.py found but no requirements.txt — skipping PyPI check")
        return []
    elif os.path.exists(os.path.join(project_path, "pyproject.toml")):
        logger.debug(
            "pyproject.toml found but no requirements.txt — skipping PyPI check"
        )
        return []
    else:
        return []

    if not package_names:
        return []

    results = await asyncio.gather(
        *[_check_single_package(name) for name in package_names],
        return_exceptions=False,
    )

    return [finding for finding in results if finding is not None]


def check_slopsquat(package_names: List[str]) -> List[ScanFinding]:
    """Detect slopsquatting and typosquatting among *package_names*.

    Slopsquatting refers to AI coding-assistant hallucinations of package
    names that attackers register with malicious code.  Typosquatting checks
    Levenshtein distance == 1 against ``TOP_PACKAGES``.

    Args:
        package_names: List of package names to analyse.

    Returns:
        A (possibly empty) list of :class:`~schemas.finding.ScanFinding`.
    """
    findings: list[ScanFinding] = []

    for name in package_names:
        lower = name.lower()

        # Step C — exact match in KNOWN_HALLUCINATED → CRITICAL
        if lower in KNOWN_HALLUCINATED:
            findings.append(
                ScanFinding(
                    tool="supply_chain",
                    severity=SeverityLevel.CRITICAL,
                    cwe="SC02:2025",
                    title=f"Slopsquat: known hallucinated package '{name}'",
                    description=(
                        "This package name appears in the known list of packages "
                        "hallucinated by AI coding assistants and may be malicious."
                    ),
                    file_path=f"supply_chain://{name}",
                )
            )
            continue

        # Step B — distance == 1 to any TOP_PACKAGES entry → HIGH typosquat
        for top in TOP_PACKAGES:
            if _levenshtein(lower, top) == 1:
                findings.append(
                    ScanFinding(
                        tool="supply_chain",
                        severity=SeverityLevel.HIGH,
                        cwe="SC02:2025",
                        title=f"Typosquat: '{name}' is 1 edit from '{top}'",
                        description=(
                            f"Package '{name}' has Levenshtein distance 1 from the "
                            f"popular package '{top}' and may be a typosquat."
                        ),
                        file_path=f"supply_chain://{name}",
                    )
                )
                break  # one finding per package is enough

    return findings
