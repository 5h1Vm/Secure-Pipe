"""SecurePipe FastAPI application entry point."""

from __future__ import annotations

import os
from contextlib import asynccontextmanager
from typing import AsyncIterator

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse
from fastapi.staticfiles import StaticFiles

from db.database import init_db
from routers import report, scan


@asynccontextmanager
async def lifespan(app: FastAPI) -> AsyncIterator[None]:
    """Application lifespan handler — initialises the database on startup."""
    await init_db()
    yield


app = FastAPI(
    title="SecurePipe",
    description=(
        "Open-source AI-augmented security testing platform. "
        "Accepts GitHub repos, live URLs, MCP server endpoints, ZIPs, and "
        "package names. Runs SAST+DAST+VAPT+SCA+Secrets+MCP scanning. "
        "Returns a unified risk score 0-100."
    ),
    version="0.1.0",
    lifespan=lifespan,
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

app.include_router(scan.router)
app.include_router(report.router)


@app.get("/health")
async def health() -> dict[str, str]:
    """Return service health status."""
    return {"status": "ok", "version": "0.1.0"}


# ── Frontend (optional — only when frontend/index.html is present) ──────────

_FRONTEND_DIR = os.path.join(os.path.dirname(__file__), "frontend")
_FRONTEND_INDEX = os.path.join(_FRONTEND_DIR, "index.html")

if os.path.isfile(_FRONTEND_INDEX):
    app.mount("/static", StaticFiles(directory=_FRONTEND_DIR), name="static")

    @app.get("/")
    async def serve_frontend() -> FileResponse:
        """Serve the single-page web dashboard."""
        return FileResponse(_FRONTEND_INDEX)


# ── MCP server exposure (optional — requires fastmcp) ───────────────────────

try:
    from routers.mcp_tools import mcp

    app.mount("/mcp", mcp.sse_app())
except Exception:  # noqa: BLE001
    pass
