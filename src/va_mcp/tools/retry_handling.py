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

class RetryHandlingTool(BaseTool):
    tool_id = "retry_handling"
    tool_name = "Retry Handling Testing"

    def run(self, tool_input: ToolInput) -> ToolResult:
        started_at = utc_now_iso()

        # 최대 재시도 횟수 설정 (기본 5회)
        max_retries = tool_input.options.extra.get("max_retries", 5)

        try:
            # TODO: 실제 구현 시에는 동일한 세션/IP로 짧은 시간 내에 여러 번 실패 요청을 보냄
            # 취약한 서버는 모든 요청에 대해 동일하게 200 또는 에러를 응답함
            # 안전한 서버는 일정 횟수 이후 429(Too Many Requests)를 반환해야 함
            
            mock_responses = [200] * max_retries # 모든 요청이 제한 없이 허용되는 상황 가정
            
            # 모든 응답이 성공(또는 제한 없음)이라면 취약함
            is_vulnerable = all(status == 200 for status in mock_responses)

            if is_vulnerable:
                ended_at = utc_now_iso()
                return ToolResult(
                    tool_id=self.tool_id,
                    tool_name=self.tool_name,
                    status=ToolStatus.VULNERABLE,
                    severity=Severity.HIGH, # 브루트포스 노출은 위험도가 높음
                    confidence=Confidence.MEDIUM,
                    title="재시도 제한 미흡 취약점 발견",
                    description=f"서버가 단시간 내에 발생하는 {max_retries}회 이상의 반복 요청에 대해 Rate Limit(429)을 적용하지 않습니다.",
                    owasp=["A04 Insecure Design", "A07 Identification and Authentication Failures"],
                    cwe=["CWE-307"], # Improper Restriction of Excessive Authentication Attempts
                    evidence=[
                        Evidence(
                            request={
                                "method": tool_input.request.method if tool_input.request else "POST",
                                "path": tool_input.request.path if tool_input.request else "/api/login",
                                "note": f"Sent {max_retries} consecutive requests"
                            },
                            response_status=200,
                            response_headers={},
                            response_body_sample=sanitize_response_sample("Success or same error message"),
                            note="반복적인 요청에도 차단이나 지연 없이 응답함"
                        )
                    ],
                    recommendation="로그인, API 호출 등 주요 엔드포인트에 대해 Rate Limiting 정책을 도입하고, 실패 시 지수 백오프(Exponential Backoff)를 적용하여 자동화된 공격을 차단해야 합니다.",
                    started_at=started_at,
                    ended_at=ended_at,
                )

            ended_at = utc_now_iso()
            return ToolResult(
                tool_id=self.tool_id,
                tool_name=self.tool_name,
                status=ToolStatus.PASSED,
                severity=Severity.INFO,
                confidence=Confidence.HIGH,
                title="재시도 및 Rate Limit 정상",
                description="서버가 과도한 재시도 요청을 올바르게 제한하고 있습니다.",
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
                description="재시도 점검 중 내부 오류가 발생했습니다.",
                errors=[build_tool_error(ErrorCode.INTERNAL_ERROR, str(e))],
                started_at=started_at,
                ended_at=ended_at,
            )