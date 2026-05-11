from __future__ import annotations

from dataclasses import dataclass, field

from va_mcp.core.schemas import ToolResult


@dataclass
class ScenarioResult:
    owasp: str
    tool_results: list[ToolResult] = field(default_factory=list)
    poc: str = ""
