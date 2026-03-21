"""Pytest configuration for SecurePipe tests."""

from __future__ import annotations

import os
import tempfile

import pytest

# Point aiosqlite at a temporary file for the duration of the test session.
_tmp_dir = tempfile.mkdtemp(prefix="securepipe_test_")
os.environ["DB_PATH"] = os.path.join(_tmp_dir, "test.db")


@pytest.fixture(scope="session", autouse=True)
async def init_database():
    """Initialise the SQLite database before any tests run."""
    from db.database import init_db

    await init_db()
