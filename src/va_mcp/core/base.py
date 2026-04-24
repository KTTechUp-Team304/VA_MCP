from __future__ import annotations

from abc import ABC, abstractmethod

from va_mcp.core.schemas import ToolInput, ToolResult


class BaseTool(ABC):
    """
    모든 tool이 상속받아야 하는 기본 인터페이스.

    구현 규칙:
    - tool_id: snake_case 고정 (예: "idor_bola")
    - tool_name: 사람이 읽는 표시용 이름 (예: "IDOR / BOLA Testing")
    - run(): ToolInput 받아서 ToolResult 반환
    - status=error 시 severity="info", confidence="low" 고정
    - status=skipped 시 evidence=[] 고정
    """

    tool_id: str
    tool_name: str

    @abstractmethod
    def run(self, tool_input: ToolInput) -> ToolResult:
        """취약점 분석을 실행하고 ToolResult를 반환한다."""
        ...
