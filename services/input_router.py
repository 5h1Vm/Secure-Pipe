"""Detect the type of a scan target from its string representation."""

from __future__ import annotations

import re
from urllib.parse import urlparse

from schemas.scan import InputType

_GITHUB_HOST = "github.com"


def detect_input_type(input_str: str) -> InputType:
    """Infer the :class:`InputType` from *input_str*.

    Detection order (first match wins):

    1. GitHub URL — hostname is exactly ``github.com``
    2. MCP endpoint — contains ``/mcp`` in the path, ``mcp`` in the query
       string, or an explicit port in {443, 80, 8000-8099}
    3. Live URL — starts with ``http://`` or ``https://`` (non-GitHub)
    4. ZIP — ends with ``.zip``
    5. Package name — only alphanumeric characters and hyphens (no slashes)
    6. Default — :attr:`InputType.AI_CODE`
    """
    s = input_str.strip()

    # Parse the URL to check the hostname precisely, avoiding substring attacks.
    if s.startswith("http://") or s.startswith("https://"):
        parsed = urlparse(s)
        if parsed.hostname == _GITHUB_HOST:
            return InputType.GITHUB_URL
        port = parsed.port
        has_mcp_path = "/mcp" in parsed.path
        has_mcp_query = "mcp" in (parsed.query or "")
        is_mcp_port = port in (443, 80) or (port is not None and 8000 <= port <= 8099)
        if has_mcp_path or has_mcp_query or is_mcp_port:
            return InputType.MCP_ENDPOINT
        return InputType.LIVE_URL

    if s.endswith(".zip"):
        return InputType.ZIP_UPLOAD

    if re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9\-]*", s):
        return InputType.PACKAGE_NAME

    return InputType.AI_CODE
