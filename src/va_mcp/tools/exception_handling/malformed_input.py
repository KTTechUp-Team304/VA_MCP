import requests
from va_mcp.core.base import BaseTool
from va_mcp.core.constants import Confidence, ErrorCode, Severity, ToolStatus
from va_mcp.core.schemas import ToolInput, ToolResult, Evidence
from va_mcp.core.utils import build_tool_error, utc_now_iso, mask_sensitive, sanitize_response_sample

class MalformedInputTool(BaseTool):
    tool_id = "malformed_input"
    tool_name = "Malformed Input Testing"

    def run(self, tool_input: ToolInput) -> ToolResult:
        started_at = utc_now_iso()
        
        timeout_sec = tool_input.options.timeout / 1000.0
        max_req = tool_input.options.max_requests
        payloads = tool_input.options.extra.get("payloads", ["{malformed: json", "A" * 5000, "null", "<xml>"])

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
        method = tool_input.request.method if tool_input.request else "POST"
        headers = tool_input.request.headers if tool_input.request else {}
        headers.setdefault("Content-Type", "application/json")
        
        vulnerable_evidence = []

        try:
            for payload in payloads[:max_req]:
                response = requests.request(method=method, url=target_url, headers=headers, data=payload, timeout=timeout_sec, verify=False)
                
                # 비정상 입력을 500 계열 에러로 뱉으면 취약
                if response.status_code >= 500:
                    vulnerable_evidence.append(
                        Evidence(
                            request={"method": method, "path": target_url, "headers": mask_sensitive(headers), "body": payload[:100]},
                            response_status=response.status_code,
                            response_headers=dict(response.headers),
                            response_body_sample=sanitize_response_sample(response.text),
                            note="형식에 맞지 않는 입력에 대해 5xx 에러(예외 처리 실패)를 반환함"
                        )
                    )
                    break

            ended_at = utc_now_iso()
            if vulnerable_evidence:
                return ToolResult(
                    tool_id=self.tool_id, tool_name=self.tool_name, status=ToolStatus.VULNERABLE.value,
                    severity=Severity.MEDIUM.value, confidence=Confidence.HIGH.value,
                    title="비정상 입력 처리 취약점 발견", description="형식에 맞지 않는 입력값을 안전하게 거부(400)하지 못하고 내부 에러가 발생합니다.",
                    owasp=["A10:2025 Mishandling of Exceptional Conditions"],
                    cwe=["CWE-20"], evidence=vulnerable_evidence,
                    recommendation="강력한 입력값 검증(Input Validation)을 구현하여 400 Bad Request를 반환하도록 처리하세요.",
                    started_at=started_at, ended_at=ended_at
                )

            return ToolResult(
                tool_id=self.tool_id, tool_name=self.tool_name, status=ToolStatus.PASSED.value,
                severity=Severity.INFO.value, confidence=Confidence.HIGH.value,
                title="비정상 입력 방어 확인", description="서버가 비정상적인 입력값을 올바르게 식별하고 처리합니다.",
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