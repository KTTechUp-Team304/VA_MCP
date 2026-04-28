import requests
from va_mcp.core.base import BaseTool
from va_mcp.core.constants import Confidence, ErrorCode, Severity, ToolStatus
from va_mcp.core.schemas import ToolInput, ToolResult, Evidence
from va_mcp.core.utils import build_tool_error, utc_now_iso, mask_sensitive, sanitize_response_sample

class TimeoutHandlingTool(BaseTool):
    tool_id = "timeout_handling"
    tool_name = "Timeout Handling Testing"

    def run(self, tool_input: ToolInput) -> ToolResult:
        started_at = utc_now_iso()
        
        # 타임아웃 점검을 위해 강제로 매우 긴 타임아웃 허용 설정
        timeout_sec = tool_input.options.extra.get("delay_seconds", 15)
        
        target_url = f"{tool_input.target.base_url}{tool_input.request.path if tool_input.request else '/'}"
        method = tool_input.request.method if tool_input.request else "GET"
        headers = tool_input.request.headers if tool_input.request else {}
        
        try:
            # 의도적으로 지연을 유발하는 파라미터나 헤더 추가 (실무 환경에 따라 변형)
            headers["X-Test-Delay"] = "true"
            
            try:
                response = requests.request(method=method, url=target_url, headers=headers, timeout=timeout_sec, verify=False)
                status_code = response.status_code
                body_sample = sanitize_response_sample(response.text)
                res_headers = dict(response.headers)
            except requests.exceptions.Timeout:
                # 클라이언트 타임아웃까지 서버가 응답하지 않은 경우 (가장 취약한 상태)
                status_code = -1
                body_sample = "Request timed out on client side without server closing connection"
                res_headers = {}

            # 안전한 상태 코드: 408(Request Timeout), 503(Service Unavailable), 504(Gateway Timeout)
            safe_status_codes = [408, 503, 504]
            is_vulnerable = status_code not in safe_status_codes

            ended_at = utc_now_iso()
            if is_vulnerable:
                return ToolResult(
                    tool_id=self.tool_id, tool_name=self.tool_name, status=ToolStatus.VULNERABLE.value,
                    severity=Severity.MEDIUM.value, confidence=Confidence.HIGH.value,
                    title="타임아웃 예외 처리 취약점 발견", 
                    description="장기 대기 요청에 대해 서버가 자원을 안전하게 해제(408, 504 등 반환)하지 못합니다.",
                    owasp=["A10:2025 Mishandling of Exceptional Conditions"],
                    cwe=["CWE-400"],
                    evidence=[
                        Evidence(
                            request={"method": method, "path": target_url, "headers": mask_sensitive(headers)},
                            response_status=status_code if status_code != -1 else 500,
                            response_headers=res_headers,
                            response_body_sample=body_sample,
                            note="요청 지연 시 적절한 타임아웃 코드가 반환되지 않음"
                        )
                    ],
                    recommendation="웹 서버 레벨에서 적절한 Request Timeout(예: 10~30초)을 설정하세요.",
                    started_at=started_at, ended_at=ended_at
                )

            return ToolResult(
                tool_id=self.tool_id, tool_name=self.tool_name, status=ToolStatus.PASSED.value,
                severity=Severity.INFO.value, confidence=Confidence.HIGH.value,
                title="타임아웃 처리 안전", description="응답 지연 시 안전하게 타임아웃 상태 코드를 반환합니다.",
                started_at=started_at, ended_at=ended_at
            )

        except Exception as e:
            ended_at = utc_now_iso()
            return ToolResult(
                tool_id=self.tool_id, tool_name=self.tool_name, status=ToolStatus.ERROR.value,
                severity=Severity.INFO.value, confidence=Confidence.LOW.value,
                title="도구 실행 오류", description="점검 중 내부 오류가 발생했습니다.",
                errors=[build_tool_error(error_code=ErrorCode.INTERNAL_ERROR, error_message=str(e), retryable=False)],
                started_at=started_at, ended_at=ended_at
            )