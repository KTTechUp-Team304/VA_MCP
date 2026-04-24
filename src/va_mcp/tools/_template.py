from __future__ import annotations

from va_mcp.core.base import BaseTool
from va_mcp.core.constants import Confidence, ErrorCode, Severity, ToolStatus
from va_mcp.core.schemas import ToolInput, ToolResult
from va_mcp.core.utils import build_tool_error, utc_now_iso


class SampleTool(BaseTool):
    """
    새 tool 구현 시 이 파일을 복사해서 시작한다.

    체크리스트:
    - [ ] TOOL_ID, TOOL_NAME 변경 (tool_id는 snake_case)
    - [ ] run() 내부 분석 로직 구현
    - [ ] tests/ 에 passed / vulnerable / error 케이스 3개 작성
    """

    tool_id = "sample_tool"
    tool_name = "Sample Tool"

    def run(self, tool_input: ToolInput) -> ToolResult:
        started_at = utc_now_iso()

        try:
            # tool별 추가 옵션은 extra에서 꺼내 쓴다. core/schemas.py 수정 불필요.
            # 현재 위치에 아래 예시처럼 사용하면 된다.
            # 예: payload_list = tool_input.options.extra.get("payload_list", [])
            # 예: repeat_count = tool_input.options.extra.get("repeat_count", 5)
            # 예: interval_ms  = tool_input.options.extra.get("interval_ms", 500)

            # TODO: 실제 분석 로직 구현
            ended_at = utc_now_iso()
            return ToolResult(
                tool_id=self.tool_id,
                tool_name=self.tool_name,
                status=ToolStatus.PASSED,
                severity=Severity.INFO,
                confidence=Confidence.MEDIUM,
                title="이상 없음",
                description="취약점이 발견되지 않았습니다.",
                started_at=started_at,
                ended_at=ended_at,
            )

        except Exception as exc:
            ended_at = utc_now_iso()
            return ToolResult(
                tool_id=self.tool_id,
                tool_name=self.tool_name,
                status=ToolStatus.ERROR,
                severity=Severity.INFO,
                confidence=Confidence.LOW,
                title="실행 오류",
                description="예상치 못한 오류가 발생했습니다.",
                started_at=started_at,
                ended_at=ended_at,
                errors=[
                    build_tool_error(
                        error_code=ErrorCode.INTERNAL_ERROR,
                        error_message=str(exc),
                        retryable=False,
                    )
                ],
            )
