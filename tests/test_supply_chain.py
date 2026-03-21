"""Tests for the supply-chain scanner (Phase 5)."""

from __future__ import annotations

import pytest

from schemas.finding import SeverityLevel
from services.supply_chain import _levenshtein, check_slopsquat


def test_levenshtein_exact_match() -> None:
    """_levenshtein returns 0 for identical strings."""
    assert _levenshtein("abc", "abc") == 0


def test_levenshtein_one_edit() -> None:
    """_levenshtein returns 1 for a single insertion."""
    assert _levenshtein("flask", "flaask") == 1


def test_slopsquat_known_hallucinated() -> None:
    """check_slopsquat flags 'huggingface' as CRITICAL with cwe SC02:2025."""
    findings = check_slopsquat(["huggingface"])
    assert any(f.cwe == "SC02:2025" for f in findings)
    assert any(f.severity == SeverityLevel.CRITICAL for f in findings)


def test_slopsquat_clean_package() -> None:
    """check_slopsquat returns no findings for a legitimate popular package."""
    findings = check_slopsquat(["requests"])
    assert findings == []


def test_slopsquat_typosquat() -> None:
    """check_slopsquat flags 'requets' (edit distance 1 from 'requests') as HIGH."""
    findings = check_slopsquat(["requets"])
    assert any(f.severity == SeverityLevel.HIGH for f in findings)
