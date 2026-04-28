import requests
from va_mcp.core.base import BaseTool
from va_mcp.core.constants import Confidence, ErrorCode, Severity, ToolStatus
from va_mcp.core.schemas import ToolInput, ToolResult, Evidence
from va_mcp.core.utils import build_tool_error, utc_now_iso, mask_sensitive, sanitize_response_sample

class StackTraceExposureTool(BaseTool):
    tool_id = "stack_trace_exposure"
    tool_name = "Stack Trace Exposure Testing"

    def run(self, tool_input: ToolInput) -> ToolResult:
        started_at = utc_now_iso()
        
        # schemas.py 옵션 적용 (수정 3)
        timeout_sec = tool_input.options.timeout / 1000.0
        max_req = tool_input.options.max_requests
        payloads = tool_input.options.extra.get("payloads", ["'", "\"", "@@", "1/0", "<script>"])

        # 빈 리스트 예외 처리 (수정 4)
        if not payloads:
            ended_at = utc_now_iso()
            return ToolResult(
                tool_id=self.tool_id, tool_name=self.tool_name, status=ToolStatus.ERROR.value,
                severity=Severity.INFO.value, confidence=Confidence.LOW.value,
                title="입력 오류", description="테스트할 payloads 리스트가 비어있습니다.",
                started_at=started_at, ended_at=ended_at,
                errors=[build_tool_error(error_code=ErrorCode.VALIDATION_ERROR, error_message="Empty payloads list", retryable=False)]
            )

        target_url = f"{tool_input.target.base_url}{tool_input.request.path if tool_input.request else '/'}"
        method = tool_input.request.method if tool_input.request else "GET"
        headers = tool_input.request.headers if tool_input.request else {}
        
        error_keywords = ["Exception", "Traceback", "Error:", "java.lang.", "Stack trace:"]
        vulnerable_evidence = []

        try:
            # 실제 HTTP 요청 로직 (수정 5) - 최대 요청 횟수 제한 적용
            for payload in payloads[:max_req]:
                params = {"q": payload} # 테스트용 파라미터 삽입
                
                response = requests.request(method=method, url=target_url, headers=headers, params=params, timeout=timeout_sec, verify=False)
                response_body = response.text

                if any(keyword.lower() in response_body.lower() for keyword in error_keywords):
                    vulnerable_evidence.append(
                        Evidence(
                            request={"method": method, "path": response.request.url, "headers": mask_sensitive(headers)},
                            response_status=response.status_code,
                            response_headers=dict(response.headers),
                            response_body_sample=sanitize_response_sample(response_body),
                            note=f"페이로드 '{payload}' 전송 시 내부 에러 정보 노출됨"
                        )
                    )
                    break # 하나라도 발견되면 즉시 취약으로 간주

            ended_at = utc_now_iso()
            if vulnerable_evidence:
                return ToolResult(
                    tool_id=self.tool_id, tool_name=self.tool_name, status=ToolStatus.VULNERABLE.value,
                    severity=Severity.HIGH.value, confidence=Confidence.HIGH.value,
                    title="스택 트레이스 노출 취약점 발견", description="서버 오류 발생 시 내부 시스템 경로 및 스택 트레이스가 노출됩니다.",
                    owasp=["A10:2025 Mishandling of Exceptional Conditions"], # 연도 표기 수정 (수정 1)
                    cwe=["CWE-209"],
                    evidence=vulnerable_evidence, recommendation="글로벌 예외 처리기를 통해 사용자에게는 일반적인 에러 메시지만 노출해야 합니다.",
                    started_at=started_at, ended_at=ended_at
                )

            return ToolResult(
                tool_id=self.tool_id, tool_name=self.tool_name, status=ToolStatus.PASSED.value,
                severity=Severity.INFO.value, confidence=Confidence.HIGH.value,
                title="스택 트레이스 안전", description="의도적인 에러 유발 시에도 내부 정보가 노출되지 않습니다.",
                started_at=started_at, ended_at=ended_at
            )

        except Exception as e:
            ended_at = utc_now_iso()
            return ToolResult(
                tool_id=self.tool_id, tool_name=self.tool_name, status=ToolStatus.ERROR.value,
                severity=Severity.INFO.value, confidence=Confidence.LOW.value,
                title="도구 실행 오류", description="점검 중 내부 통신 오류가 발생했습니다.",
                errors=[build_tool_error(error_code=ErrorCode.INTERNAL_ERROR, error_message=str(e), retryable=False)],
                started_at=started_at, ended_at=ended_at
            )