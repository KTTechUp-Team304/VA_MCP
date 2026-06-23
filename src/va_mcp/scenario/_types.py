from __future__ import annotations

from typing import Protocol, runtime_checkable

from va_mcp.endpoint_profile.endpoint_profile import EndpointProfile
from va_mcp.core.schemas import ToolResult


@runtime_checkable
class OrchestratorProtocol(Protocol):
    """
    Scenario가 의존하는 Orchestrator 인터페이스.

    Orchestrator 구현체는 이 Protocol을 명시적으로 상속하지 않아도
    구조적 타이핑(structural subtyping)으로 자동으로 호환된다.
    run()은 tool_ids 목록과 EndpointProfile을 받아 ToolResult 리스트를 반환해야 한다.
    """

    def run(self, tool_ids: list[str], profile: EndpointProfile) -> list[ToolResult]: ...
