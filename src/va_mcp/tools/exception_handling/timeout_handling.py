from va_mcp.core import (
    BaseTool,
    ToolInput,
    ToolResult,
    Evidence,
    ToolStatus,
    Severity,
    Confidence,
    ErrorCode,
)
from va_mcp.core.utils import (
    build_tool_error,
    utc_now_iso,
    mask_sensitive,
    sanitize_response_sample,
)

class TimeoutHandlingTool(BaseTool):
    tool_id = "timeout_handling"
    tool_name = "Timeout Handling Testing"

    def run(self, tool_input: ToolInput) -> ToolResult:
        started_at = utc_now_iso()

        # extra 옵션에서 임의의 지연 시간 설정 (예: 10초)
        delay_seconds = tool_input.options.extra.get("delay_seconds", 10)

        try:
            # TODO: 실제 통신 시에는 강제로 서버에 지연을 유발하는 페이로드를 보내거나,
            # 클라이언트 측에서 타임아웃을 짧게 주어 서버의 반응을 확인합니다.
            # MVP 단계이므로 Mock 데이터로 분기합니다.
            
            # (가상) 취약한 서버는 타임아웃을 제어하지 못하고 500 에러를 뱉거나 
            # 아무 응답 없이 연결이 끊어질 때까지 대기(hang)한다고 가정합니다.
            mock_response_status = 500
            mock_response_body = "Internal Server Error (Timeout occurred internally)"

            # 정상적인 방어는 408(Request Timeout) 또는 504(Gateway Timeout), 503(Service Unavailable)
            safe_status_codes = [408, 503, 504]
            is_vulnerable = mock_response_status not in safe_status_codes

            if is_vulnerable:
                ended_at = utc_now_iso()
                return ToolResult(
                    tool_id=self.tool_id,
                    tool_name=self.tool_name,
                    status=ToolStatus.VULNERABLE,
                    severity=Severity.MEDIUM,
                    confidence=Confidence.HIGH,
                    title="타임아웃 예외 처리 취약점 발견",
                    description=f"서버가 {delay_seconds}초 이상의 장기 요청에 대해 적절한 타임아웃(408, 504 등)을 반환하지 못하고 자원을 낭비하거나 내부 에러를 발생시킵니다.",
                    owasp=["A05 Security Misconfiguration"],
                    cwe=["CWE-400"], # Uncontrolled Resource Consumption
                    evidence=[
                        Evidence(
                            request={
                                "method": tool_input.request.method if tool_input.request else "GET",
                                "path": tool_input.request.path if tool_input.request else "/",
                                "headers": mask_sensitive({"Authorization": "Bearer TEST_TOKEN"}),
                                "note": f"Delay simulated for {delay_seconds} seconds"
                            },
                            response_status=mock_response_status,
                            response_headers={},
                            response_body_sample=sanitize_response_sample(mock_response_body),
                            note="시간 초과 상황에서 명확한 타임아웃 상태 코드가 아닌 500 에러 반환됨"
                        )
                    ],
                    recommendation="애플리케이션 및 웹 서버(Nginx, Apache 등) 레벨에서 적절한 Request Timeout을 설정하여, 비정상적으로 오래 걸리는 요청은 자원 고갈을 막기 위해 신속히 차단(408 또는 504 반환)해야 합니다.",
                    started_at=started_at,
                    ended_at=ended_at,
                )

            # 취약점이 없는 경우 (408, 504 등으로 잘 방어함)
            ended_at = utc_now_iso()
            return ToolResult(
                tool_id=self.tool_id,
                tool_name=self.tool_name,
                status=ToolStatus.PASSED,
                severity=Severity.INFO,
                confidence=Confidence.HIGH,
                title="타임아웃 처리 안전",
                description="서버가 응답 지연 시 안전하게 타임아웃 상태 코드를 반환하며 자원을 해제합니다.",
                started_at=started_at,
                ended_at=ended_at,
            )

        except Exception as e:
            ended_at = utc_now_iso()
            return ToolResult(
                tool_id=self.tool_id,
                tool_name=self.tool_name,
                status=ToolStatus.ERROR,
                severity=Severity.INFO,
                confidence=Confidence.LOW,
                title="도구 실행 오류",
                description="타임아웃 점검 중 내부 오류가 발생했습니다.",
                errors=[build_tool_error(ErrorCode.INTERNAL_ERROR, str(e))],
                started_at=started_at,
                ended_at=ended_at,
            )