"""MCP Security Scanner — OWASP MCP Top 10 automated checks."""

from __future__ import annotations

import asyncio
import json
import logging
import re
from typing import Any

import httpx

from schemas.finding import ScanFinding, SeverityLevel
from services.base_scanner import BaseScanner

logger = logging.getLogger(__name__)

_MCP_CONNECTION_TIMEOUT = 10  # seconds to wait for MCP server handshake
_HTTP_PROBE_TIMEOUT = 5  # seconds for auth-probe HTTP requests

# MCP01 — Token mismanagement: credentials / secrets in tool definitions
_TOKEN_RE = re.compile(
    r"(Bearer\s+\S+|sk-[A-Za-z0-9]+|api_key\s*=|password\s*=|token\s*=|secret\s*=)",
    re.IGNORECASE,
)

# MCP03 — Tool poisoning: prompt-injection phrases
_INJECTION_PHRASES: list[str] = [
    "ignore previous",
    "disregard",
    "new instructions",
    "instead do",
    "system:",
    "forget",
    "override",
    "<|im_start|>",
    "[INST]",
    "you are now",
    "act as",
    "jailbreak",
]

# MCP04 — Command injection: dangerous execution patterns
_CMD_RE = re.compile(
    r"\b(os\.system|subprocess|exec|eval|shell\s*=\s*True|cmd|command|execute)\b",
    re.IGNORECASE,
)

# MCP02 — Excessive permissions: broad-capability keywords
_PERM_RE = re.compile(
    r"\b(file|database|network|admin|delete|write|execute)\b",
    re.IGNORECASE,
)


class MCPScanner(BaseScanner):
    """Scanner that checks MCP server endpoints for OWASP MCP Top 10 issues."""

    scanner_name = "mcp_scanner"

    async def connect_and_enumerate(self, server_url: str) -> dict[str, Any]:
        """Connect to an MCP server and enumerate its tools.

        Args:
            server_url: The URL of the MCP server endpoint.

        Returns:
            A dict with ``server_name``, ``server_version``, and ``tools`` list.
            On connection failure returns ``{error: str, tools: []}``.
        """
        try:
            from mcp import ClientSession  # type: ignore[import]
            from mcp.client.sse import sse_client  # type: ignore[import]

            async with asyncio.timeout(_MCP_CONNECTION_TIMEOUT):
                async with sse_client(url=server_url) as (read, write):
                    async with ClientSession(read, write) as session:
                        init_result = await session.initialize()
                        tools_result = await session.list_tools()

            server_info = getattr(init_result, "serverInfo", None)
            tools = [
                {
                    "name": t.name,
                    "description": t.description or "",
                    "inputSchema": (
                        t.inputSchema if hasattr(t, "inputSchema") else {}
                    ),
                }
                for t in tools_result.tools
            ]
            return {
                "server_name": server_info.name if server_info else "",
                "server_version": server_info.version if server_info else "",
                "tools": tools,
            }

        except Exception as exc:
            logger.warning("MCP connection failed for %s: %s", server_url, exc)
            return {"error": str(exc), "tools": []}

    def check_static(
        self, tool: dict[str, Any], server_url: str = ""
    ) -> list[ScanFinding]:
        """Run static OWASP MCP Top 10 checks on a single tool definition.

        Args:
            tool: Tool dict with ``name``, ``description``, and ``inputSchema``.
            server_url: Optional server URL used to build ``file_path``.

        Returns:
            List of :class:`~schemas.finding.ScanFinding` for any issues found.
        """
        findings: list[ScanFinding] = []
        name: str = tool.get("name", "")
        description: str = tool.get("description", "")
        input_schema: Any = tool.get("inputSchema", {})

        schema_str = (
            json.dumps(input_schema)
            if isinstance(input_schema, dict)
            else str(input_schema)
        )
        searchable = f"{name} {description} {schema_str}"

        base = f"mcp://{server_url}/tools/{name}" if server_url else f"mcp://tool/{name}"

        # MCP01 — Token mismanagement
        m = _TOKEN_RE.search(searchable)
        if m:
            findings.append(
                ScanFinding(
                    tool=self.scanner_name,
                    severity=SeverityLevel.CRITICAL,
                    cwe="MCP01:2025",
                    title="MCP01 - Token Mismanagement",
                    description="Credential or token pattern detected in tool definition.",
                    file_path=base,
                    evidence=m.group(0)[:100],
                )
            )

        # MCP03 — Tool poisoning
        searchable_lower = searchable.lower()
        for phrase in _INJECTION_PHRASES:
            if phrase.lower() in searchable_lower:
                findings.append(
                    ScanFinding(
                        tool=self.scanner_name,
                        severity=SeverityLevel.CRITICAL,
                        cwe="MCP03:2025",
                        title="MCP03 - Tool Poisoning",
                        description="Prompt-injection phrase detected in tool definition.",
                        file_path=base,
                        evidence=phrase[:100],
                    )
                )
                break

        # MCP04 — Command injection
        cm = _CMD_RE.search(searchable)
        if cm:
            findings.append(
                ScanFinding(
                    tool=self.scanner_name,
                    severity=SeverityLevel.HIGH,
                    cwe="MCP04:2025",
                    title="MCP04 - Command Injection Risk",
                    description="Command execution pattern detected in tool definition.",
                    file_path=base,
                    evidence=cm.group(0)[:100],
                )
            )

        # MCP02 — Excessive permissions
        has_required = bool(
            isinstance(input_schema, dict) and input_schema.get("required")
        )
        pm = _PERM_RE.search(description)
        if not has_required and pm:
            findings.append(
                ScanFinding(
                    tool=self.scanner_name,
                    severity=SeverityLevel.MEDIUM,
                    cwe="MCP02:2025",
                    title="MCP02 - Excessive Permissions",
                    description="Tool has no required fields but grants broad access.",
                    file_path=base,
                    evidence=pm.group(0)[:100],
                )
            )

        return findings

    async def check_dynamic(
        self, server_url: str, tool_name: str
    ) -> list[ScanFinding]:
        """Probe a tool endpoint for missing authentication (MCP05).

        Args:
            server_url: The MCP server base URL.
            tool_name: Name of the tool to probe.

        Returns:
            List of :class:`~schemas.finding.ScanFinding` if auth bypass detected.
        """
        findings: list[ScanFinding] = []
        url = f"{server_url.rstrip('/')}/tools/{tool_name}"
        try:
            async with httpx.AsyncClient(timeout=_HTTP_PROBE_TIMEOUT) as client:
                response = await client.post(url, json={})
            if response.status_code not in (401, 403):
                findings.append(
                    ScanFinding(
                        tool=self.scanner_name,
                        severity=SeverityLevel.HIGH,
                        cwe="MCP05:2025",
                        title="MCP05 - Auth Bypass",
                        description="Tool endpoint has no authentication.",
                        file_path=f"mcp://{server_url}/tools/{tool_name}",
                        evidence=f"HTTP {response.status_code} returned without auth",
                    )
                )
        except Exception as exc:
            logger.debug("check_dynamic probe failed for %s: %s", url, exc)

        return findings

    async def run(self, target: str) -> list[ScanFinding]:
        """Run the full MCP security scan pipeline against *target*.

        Args:
            target: MCP server URL.

        Returns:
            All findings from static and dynamic checks.
        """
        findings: list[ScanFinding] = []
        enumeration = await self.connect_and_enumerate(target)
        tools: list[dict[str, Any]] = enumeration.get("tools", [])

        for tool in tools:
            findings.extend(self.check_static(tool, server_url=target))

        for tool in tools:
            tool_name = tool.get("name", "")
            if tool_name:
                findings.extend(await self.check_dynamic(target, tool_name))

        from services.injection_detector import scan_for_injection  # noqa: PLC0415

        for tool in tools:
            injection_findings = await scan_for_injection(
                tool.get("description", ""), tool["name"], target
            )
            findings.extend(injection_findings)

        return findings
