import requests
from va_mcp.core.base import BaseTool
from va_mcp.core.constants import Confidence, ErrorCode, Severity, ToolStatus
from va_mcp.core.schemas import ToolInput, ToolResult, Evidence
from va_mcp.core.utils import build_tool_error, utc_now_iso, mask_sensitive, sanitize_response_sample

class RetryHandlingTool(BaseTool):
    tool_id = "retry_handling"
    tool_name = "Retry Handling Testing"

    def run(self, tool_input: ToolInput) -> ToolResult:
        started_at = utc_now_iso()
        
        timeout_sec = tool_input.options.timeout / 1000.0
        max_req = tool_input.options.max_requests  # Rate Limit 테스트용 횟수로 그대로 사용
        
        target_url = f"{tool_input.target.base_url}{tool_input.request.path if tool_input.request else '/api/login'}"
        method = tool_input.request.method if tool_input.request else "POST"
        headers = tool_input.request.headers if tool_input.request else {}
        
        responses = []
        try:
            # 연속 요청 발송
            for _ in range(max_req):
                res = requests.request(method=method, url=target_url, headers=headers, timeout=timeout_sec, verify=False)
                responses.append(res.status_code)

            # 모든 요청이 동일하게 성공(200)하거나 401 등을 뱉으며 429(Too Many Requests)로 막히지 않으면 취약
            is_vulnerable = 429 not in responses

            ended_at = utc_now_iso()
            if is_vulnerable:
                return ToolResult(
                    tool_id=self.tool_id, tool_name=self.tool_name, status=ToolStatus.VULNERABLE.value,
                    severity=Severity.HIGH.value, confidence=Confidence.MEDIUM.value,
                    title="재시도 제한(Rate Limit) 미흡 발견", 
                    description=f"단시간 내 {max_req}회의 반복 요청에도 429(Too Many Requests) 차단이 발생하지 않습니다.",
                    owasp=["A10:2025 Mishandling of Exceptional Conditions"],
                    cwe=["CWE-307"],
                    evidence=[
                        Evidence(
                            request={"method": method, "path": target_url, "headers": mask_sensitive(headers)},
                            response_status=responses[-1],
                            response_body_sample=sanitize_response_sample(""),
                            note=f"{max_req}회의 반복적인 요청에도 차단이나 지연 정책이 적용되지 않음"
                        )
                    ],
                    recommendation="주요 API 엔드포인트에 IP 기반 또는 계정 기반의 Rate Limiting을 적용하세요.",
                    started_at=started_at, ended_at=ended_at
                )

            return ToolResult(
                tool_id=self.tool_id, tool_name=self.tool_name, status=ToolStatus.PASSED.value,
                severity=Severity.INFO.value, confidence=Confidence.HIGH.value,
                title="Rate Limit 작동 확인", description="과도한 요청에 대해 정상적으로 방어 메커니즘이 작동합니다.",
                started_at=started_at, ended_at=ended_at
            )

        except Exception as e:
            ended_at = utc_now_iso()
            return ToolResult(
                tool_id=self.tool_id, tool_name=self.tool_name, status=ToolStatus.ERROR.value,
                severity=Severity.INFO.value, confidence=Confidence.LOW.value,
                title="도구 실행 오류", description="점검 중 통신 오류가 발생했습니다.",
                errors=[build_tool_error(error_code=ErrorCode.INTERNAL_ERROR, error_message=str(e), retryable=False)],
                started_at=started_at, ended_at=ended_at
            )