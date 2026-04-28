from va_mcp.core import (
    BaseTool,
    ToolInput,
    ToolResult,
    Evidence,
    ToolError,
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

class StackTraceExposureTool(BaseTool):
    tool_id = "stack_trace_exposure"
    tool_name = "Stack Trace Exposure Testing"

    def run(self, tool_input: ToolInput) -> ToolResult:
        started_at = utc_now_iso()

        # extra 옵션에서 테스트할 악의적 페이로드 가져오기 (기본값 세팅)
        # 예: 고의적인 타입 에러, 구문 에러, 길이 초과 등을 유발
        payloads = tool_input.options.extra.get(
            "payloads", ["'", "\"", "%00", "A" * 5000, "{\"malformed_json:"]
        )

        try:
            # TODO: 실제 HTTP 요청 로직 (requests, httpx 등)이 들어갈 자리
            # 현재는 MVP 단계의 Mock 데이터로 분석 로직을 대체합니다.
            
            # (가상) 응답 결과에 스택 트레이스 키워드가 포함되었는지 확인
            # 실제 구현에서는 payloads를 순회하며 응답 바디를 검사해야 합니다.
            mock_response_status = 500
            mock_response_body = "java.lang.NullPointerException\n\tat com.example.api.UserController..."
            
            error_keywords = ["Exception", "Traceback", "stack trace", "java.lang.", "Fatal error"]
            
            is_vulnerable = any(keyword in mock_response_body for keyword in error_keywords)

            if is_vulnerable:
                ended_at = utc_now_iso()
                return ToolResult(
                    tool_id=self.tool_id,
                    tool_name=self.tool_name,
                    status=ToolStatus.VULNERABLE,
                    severity=Severity.HIGH,      # 내부 구조 노출은 위험도가 높음
                    confidence=Confidence.HIGH,  # 명확한 키워드 탐지
                    title="스택 트레이스 노출 취약점 발견",
                    description="서버 내부 오류 메시지와 스택 트레이스가 클라이언트에게 노출되고 있습니다.",
                    owasp=["A05 Security Misconfiguration"],
                    cwe=["CWE-209"], # Information Exposure Through an Error Message
                    evidence=[
                        Evidence(
                            request={
                                "method": tool_input.request.method if tool_input.request else "GET",
                                "path": tool_input.request.path if tool_input.request else "/",
                                # 헤더 마스킹 필수
                                "headers": mask_sensitive({"Authorization": "Bearer TEST_TOKEN", "Content-Type": "application/json"}),
                                "body": payloads[0] # 에러를 유발한 페이로드 샘플
                            },
                            response_status=mock_response_status,
                            response_headers={},
                            # 응답 바디 길이 2000자 제한 필수
                            response_body_sample=sanitize_response_sample(mock_response_body),
                            note="의도적인 예외 유발 페이로드 전송 시 스택 트레이스 문자열 노출됨"
                        )
                    ],
                    recommendation="운영 환경(Production)에서는 사용자에게 포괄적인 에러 메시지(예: '서버 내부 오류가 발생했습니다')만 노출하고, 상세 스택 트레이스는 서버 내부 로그로만 기록되도록 예외 처리기(Global Exception Handler)를 설정해야 합니다.",
                    started_at=started_at,
                    ended_at=ended_at,
                )

            # 취약점이 없는 경우 (안전한 예외 처리)
            ended_at = utc_now_iso()
            return ToolResult(
                tool_id=self.tool_id,
                tool_name=self.tool_name,
                status=ToolStatus.PASSED,
                severity=Severity.INFO,
                confidence=Confidence.HIGH,
                title="스택 트레이스 노출 없음",
                description="비정상적인 입력에도 서버가 안전한 형태의 에러 응답을 반환합니다.",
                started_at=started_at,
                ended_at=ended_at,
            )

        except Exception as e:
            # 실행 중 예외 처리 규칙: status=ERROR, severity=INFO 고정
            ended_at = utc_now_iso()
            return ToolResult(
                tool_id=self.tool_id,
                tool_name=self.tool_name,
                status=ToolStatus.ERROR,
                severity=Severity.INFO,
                confidence=Confidence.LOW,
                title="도구 실행 오류",
                description="스택 트레이스 점검 중 내부 오류가 발생했습니다.",
                errors=[build_tool_error(ErrorCode.INTERNAL_ERROR, str(e))],
                started_at=started_at,
                ended_at=ended_at,
            )