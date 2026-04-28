import requests
from va_mcp.core.base import BaseTool
from va_mcp.core.constants import Confidence, ErrorCode, Severity, ToolStatus
from va_mcp.core.schemas import ToolInput, ToolResult, Evidence
from va_mcp.core.utils import build_tool_error, utc_now_iso, mask_sensitive, sanitize_request_body, sanitize_response_sample

class RetryHandlingTool(BaseTool):
    """
    단기간에 수많은 요청을 보낼 때, 서버가 속도 제한(Rate Limit)을 걸어 방어하는지 확인하는 도구입니다.(브루트포스 방어)
    모든 응답이 200(성공)이라면 방어 조치가 없다고 판단, 취약 판정을 내립니다.
    """

    tool_id = "retry_handling"
    tool_name = "Retry Handling Testing"

    def run(self, tool_input: ToolInput) -> ToolResult:
        started_at = utc_now_iso()

        if tool_input.request is None:
            return ToolResult(
                tool_id=self.tool_id,
                tool_name=self.tool_name,
                status=ToolStatus.SKIPPED.value,
                evidence=[],  # SKIPPED 규정 준수
                started_at=started_at,
                ended_at=utc_now_iso()
            )
        
        timeout_sec = tool_input.options.timeout / 1000.0
        max_req = tool_input.options.max_requests  # Rate Limit 테스트용 횟수로 그대로 사용
        
        target_url = f"{tool_input.target.base_url}{tool_input.request.path if tool_input.request else '/api/login'}"
        method = tool_input.request.method if tool_input.request else "POST"
        headers = dict(tool_input.request.headers)
        
        responses: list[requests.Response] = []
        try:
            # 연속 요청 발송
            for _ in range(max_req):
                res = requests.request(
                    method=method, 
                    url=target_url, 
                    headers=headers, 
                    timeout=timeout_sec, 
                    verify=False
                )
                # 🎯 res.status_code가 아니라 res 객체 자체를 저장
                responses.append(res)

            # 🎯 응답 객체 리스트에서 상태 코드만 다시 뽑아서 검사합니다.
            status_codes = [r.status_code for r in responses]
            is_vulnerable = 429 not in status_codes

            ended_at = utc_now_iso()
            if is_vulnerable:
                # 🎯 1. 리스트에 저장된 마지막 '응답 객체'를 변수로 빼냅니다.
                last_response = responses[-1]
                
                return ToolResult(
                    tool_id=self.tool_id, tool_name=self.tool_name, status=ToolStatus.VULNERABLE.value,
                    severity=Severity.HIGH.value, confidence=Confidence.MEDIUM.value,
                    title="재시도 제한(Rate Limit) 미흡 발견", 
                    description=f"단시간 내 {max_req}회의 반복 요청에도 429(Too Many Requests) 차단이 발생하지 않습니다.",
                    owasp=["A10:2025 Mishandling of Exceptional Conditions"],
                    cwe=["CWE-307"],
                    evidence=[
                        Evidence(
                            request={
                                "method": method, 
                                "path": target_url, 
                                "headers": mask_sensitive(headers),
                                "body": sanitize_request_body(tool_input.request.body)  # 🎯 프로젝트 규정: 요청 바디도 추가
                            },
                            # 🎯 2. 비어있던 텍스트("") 대신, 진짜 텍스트(last_response.text)를 넣습니다.
                            response_status=last_response.status_code,
                            response_body_sample=sanitize_response_sample(last_response.text),
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
                errors=[build_tool_error(error_code=ErrorCode.INTERNAL_ERROR.value, error_message=str(e), retryable=False)],
                started_at=started_at, ended_at=ended_at
            )