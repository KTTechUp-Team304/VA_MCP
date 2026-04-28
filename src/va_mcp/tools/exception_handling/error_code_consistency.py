import requests
from va_mcp.core.base import BaseTool
from va_mcp.core.constants import Confidence, ErrorCode, Severity, ToolStatus
from va_mcp.core.schemas import ToolInput, ToolResult, Evidence
from va_mcp.core.utils import build_tool_error, utc_now_iso, mask_sensitive, sanitize_response_sample

class ErrorCodeConsistencyTool(BaseTool):
    tool_id = "error_code_consistency"
    tool_name = "Error Code Consistency Testing"

    def run(self, tool_input: ToolInput) -> ToolResult:
        started_at = utc_now_iso()
        
        timeout_sec = tool_input.options.timeout / 1000.0
        base_url = tool_input.target.base_url
        headers = tool_input.request.headers if tool_input.request else {}
        
        try:
            # 테스트 1: 400 Bad Request 유발 (비정상 메소드 또는 경로)
            req1_url = f"{base_url}/api/invalid-format-test"
            res1 = requests.post(req1_url, headers=headers, data="invalid", timeout=timeout_sec, verify=False)
            
            # 테스트 2: 404 Not Found 유발 (존재하지 않는 경로)
            req2_url = f"{base_url}/api/this-path-does-not-exist-12345"
            res2 = requests.get(req2_url, headers=headers, timeout=timeout_sec, verify=False)

            ct1 = res1.headers.get("Content-Type", "").lower()
            ct2 = res2.headers.get("Content-Type", "").lower()

            # Content-Type 구조가 명확하게 다르면 (예: 하나는 json, 하나는 html) 일관성 없음으로 판단
            is_vulnerable = ("json" in ct1 and "html" in ct2) or ("html" in ct1 and "json" in ct2)

            ended_at = utc_now_iso()
            if is_vulnerable:
                return ToolResult(
                    tool_id=self.tool_id, tool_name=self.tool_name, status=ToolStatus.VULNERABLE.value,
                    severity=Severity.LOW.value, confidence=Confidence.HIGH.value,
                    title="오류 응답 규격 불일치", 
                    description="발생하는 에러 종류에 따라 응답 데이터의 Content-Type 형식이 다르게 반환됩니다.",
                    owasp=["A10:2025 Mishandling of Exceptional Conditions"],
                    cwe=["CWE-703"],
                    evidence=[
                        Evidence(
                            request={"method": "POST", "path": req1_url, "headers": mask_sensitive(headers)},
                            response_status=res1.status_code, response_headers=dict(res1.headers),
                            response_body_sample=sanitize_response_sample(res1.text), note="Type 1 Error Response"
                        ),
                        Evidence(
                            request={"method": "GET", "path": req2_url, "headers": mask_sensitive(headers)},
                            response_status=res2.status_code, response_headers=dict(res2.headers),
                            response_body_sample=sanitize_response_sample(res2.text), note="Type 2 Error Response"
                        )
                    ],
                    recommendation="웹 서버 에러 페이지(Nginx/Apache) 설정을 오버라이드하여 API 규격과 동일한 JSON 포맷을 반환하도록 통일하세요.",
                    started_at=started_at, ended_at=ended_at
                )

            return ToolResult(
                tool_id=self.tool_id, tool_name=self.tool_name, status=ToolStatus.PASSED.value,
                severity=Severity.INFO.value, confidence=Confidence.HIGH.value,
                title="오류 응답 일관성 유지됨", description="에러 상황에서도 일관된 Content-Type으로 응답합니다.",
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