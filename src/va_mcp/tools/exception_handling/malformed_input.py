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

class MalformedInputTool(BaseTool):
    tool_id = "malformed_input"
    tool_name = "Malformed Input Testing"

    def run(self, tool_input: ToolInput) -> ToolResult:
        started_at = utc_now_iso()

        # extra 옵션에서 비정상 페이로드 리스트 가져오기
        # 예: 깨진 JSON, 타입 불일치, 매우 긴 값 등
        payloads = tool_input.options.extra.get(
            "payloads", ["{malformed: json", "A" * 10000, "null", "undefined", "<xml>"]
        )

        try:
            # TODO: 실제 HTTP 요청 로직
            # MVP 단계이므로 하드코딩된 Mock 데이터로 분석합니다.
            # 가정: 비정상 입력을 보냈을 때 서버가 500(Internal Server Error)로 죽으면 취약,
            # 400(Bad Request)이나 422(Unprocessable Entity)로 방어하면 안전
            
            mock_response_status = 500  # 취약한 서버 가정
            mock_response_body = "Internal Server Error"

            # 500 에러는 서버가 예외를 제대로 핸들링하지 못하고 터졌음을 의미
            is_vulnerable = mock_response_status >= 500

            if is_vulnerable:
                ended_at = utc_now_iso()
                return ToolResult(
                    tool_id=self.tool_id,
                    tool_name=self.tool_name,
                    status=ToolStatus.VULNERABLE,
                    severity=Severity.MEDIUM,     # 스택 트레이스 노출보다는 낮음
                    confidence=Confidence.HIGH,
                    title="비정상 입력 처리 취약점 발견",
                    description="형식에 맞지 않는 입력값(Malformed Input)을 전송했을 때 서버가 정상적으로 거부하지 못하고 내부 에러(HTTP 500 등)를 반환합니다.",
                    owasp=["A04 Insecure Design", "A05 Security Misconfiguration"],
                    cwe=["CWE-20"], # Improper Input Validation
                    evidence=[
                        Evidence(
                            request={
                                "method": tool_input.request.method if tool_input.request else "POST",
                                "path": tool_input.request.path if tool_input.request else "/",
                                "headers": mask_sensitive({"Authorization": "Bearer TEST_TOKEN", "Content-Type": "application/json"}),
                                "body": payloads[0] # 에러를 유발한 비정상 데이터 샘플
                            },
                            response_status=mock_response_status,
                            response_headers={},
                            response_body_sample=sanitize_response_sample(mock_response_body),
                            note="깨진 데이터 전송 시 5xx 에러 발생 (입력값 검증 미흡)"
                        )
                    ],
                    recommendation="모든 사용자 입력값에 대해 강력한 유효성 검사(Input Validation)를 수행하고, 형식이 맞지 않는 데이터가 들어올 경우 서버가 죽지 않고 HTTP 400(Bad Request) 상태 코드와 함께 명확한 에러 메시지를 반환하도록 예외 처리를 구현해야 합니다.",
                    started_at=started_at,
                    ended_at=ended_at,
                )

            # 취약점이 없는 경우 (400 등으로 잘 방어함)
            ended_at = utc_now_iso()
            return ToolResult(
                tool_id=self.tool_id,
                tool_name=self.tool_name,
                status=ToolStatus.PASSED,
                severity=Severity.INFO,
                confidence=Confidence.HIGH,
                title="비정상 입력 방어 확인",
                description="서버가 비정상적인 입력값을 올바르게 식별하고 안전하게 처리합니다.",
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
                description="비정상 입력 점검 중 내부 오류가 발생했습니다.",
                errors=[build_tool_error(ErrorCode.INTERNAL_ERROR, str(e))],
                started_at=started_at,
                ended_at=ended_at,
            )