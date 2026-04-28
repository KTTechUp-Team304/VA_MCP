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

class ErrorCodeConsistencyTool(BaseTool):
    tool_id = "error_code_consistency"
    tool_name = "Error Code Consistency Testing"

    def run(self, tool_input: ToolInput) -> ToolResult:
        started_at = utc_now_iso()

        try:
            # TODO: 실제 구현 시에는 400(잘못된 요청), 401(인증 실패), 404(없는 경로), 405(잘못된 메서드) 등
            # 다양한 종류의 에러를 유발하는 요청을 보내고 응답의 Content-Type과 구조(Schema)를 비교합니다.
            
            # MVP Mock 시나리오: 
            # 400 에러는 JSON으로 예쁘게 나오는데, 404 에러는 Nginx나 Tomcat의 기본 HTML 페이지가 나오는 상황 가정
            mock_400_body = '{"success": false, "error_code": "INVALID_PARAM"}'
            mock_404_body = '<html><body><h1>404 Not Found</h1>nginx/1.18.0</body></html>'

            # 응답 구조가 다르면 취약(일관성 없음)
            is_vulnerable = True 

            if is_vulnerable:
                ended_at = utc_now_iso()
                return ToolResult(
                    tool_id=self.tool_id,
                    tool_name=self.tool_name,
                    status=ToolStatus.VULNERABLE,
                    severity=Severity.LOW, # 직접적인 치명적 해킹보단 구조적 결함/정보 노출에 가까움
                    confidence=Confidence.HIGH,
                    title="오류 응답 규격 불일치 (일관성 없음)",
                    description="발생하는 HTTP 상태 코드나 에러 종류에 따라 응답 데이터의 형식(JSON vs HTML)이나 구조가 다르게 반환됩니다.",
                    owasp=["A05 Security Misconfiguration"],
                    cwe=["CWE-703"], # Improper Check or Handling of Exceptional Conditions
                    evidence=[
                        Evidence(
                            request={"method": "POST", "path": "/api/test (유효성 실패 유발)"},
                            response_status=400,
                            response_headers={"Content-Type": "application/json"},
                            response_body_sample=sanitize_response_sample(mock_400_body),
                            note="400 에러는 규격화된 JSON 응답 반환"
                        ),
                        Evidence(
                            request={"method": "GET", "path": "/api/not-exist (404 유발)"},
                            response_status=404,
                            response_headers={"Content-Type": "text/html"},
                            response_body_sample=sanitize_response_sample(mock_404_body),
                            note="404 에러는 웹 서버 기본 HTML 반환 (버전 정보 노출 위험 포함)"
                        )
                    ],
                    recommendation="Global Exception Handler(전역 예외 처리기)를 도입하고, 웹 서버(Nginx/Apache)의 기본 에러 페이지(error_page) 설정도 API 규격과 동일한 JSON 포맷을 반환하도록 통일해야 합니다.",
                    started_at=started_at,
                    ended_at=ended_at,
                )

            # 안전한 경우
            ended_at = utc_now_iso()
            return ToolResult(
                tool_id=self.tool_id,
                tool_name=self.tool_name,
                status=ToolStatus.PASSED,
                severity=Severity.INFO,
                confidence=Confidence.HIGH,
                title="오류 응답 일관성 유지됨",
                description="모든 에러 상황에서 사전에 정의된 표준 오류 규격(예: JSON 기반 ErrorResponse)을 준수합니다.",
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
                description="오류 코드 일관성 점검 중 내부 오류가 발생했습니다.",
                errors=[build_tool_error(ErrorCode.INTERNAL_ERROR, str(e))],
                started_at=started_at,
                ended_at=ended_at,
            )