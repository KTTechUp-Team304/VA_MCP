from __future__ import annotations

from dataclasses import dataclass, field

from va_mcp.endpoint_profile.endpoint_profile import EndpointProfile


@dataclass
class ScenarioPlan:
    owasp: str
    tool_ids: list[str] = field(default_factory=list)
    endpoint: EndpointProfile | None = None
