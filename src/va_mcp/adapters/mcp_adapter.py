from __future__ import annotations

from typing import Any

from va_mcp.services.endpoint_analysis import analyze_endpoint


def analyze_endpoint_tool(raw_input: dict[str, Any]) -> dict[str, Any]:
    """MCP tool 진입점: 서비스에 그대로 위임한다."""
    return analyze_endpoint(raw_input)
