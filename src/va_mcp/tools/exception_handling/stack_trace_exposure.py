from __future__ import annotations

# extra 옵션 키:
#   "payloads": list[str] — 오류 유발용 페이로드 목록
#                           (기본값: ["'", '"', "@@", "1/0", "<script>"])

import requests

from va_mcp.core import (
    BaseTool,
    Confidence,
    ErrorCode,
    Evidence,
    Severity,
    ToolInput,
    ToolResult,
    ToolStatus,
)
from va_mcp.core.utils import (
    build_tool_error,
    mask_sensitive,
    sanitize_response_sample,
    utc_now_iso,
)


class StackTraceExposureTool(BaseTool):
    """
    에러 발생 시 서버의 내부 정보(코드 경로, 프레임워크 종류 등)이 노출되는지 점검하는 도구입니다.
    서버 응답 안에 위험한 단어들이 포함되어 있는지 검사합니다.
    """

    tool_id = "stack_trace_exposure"
    tool_name = "Stack Trace Exposure Testing"

    def run(self, tool_input: ToolInput) -> ToolResult:
        started_at = utc_now_iso()

        if tool_input.request is None:
            ended_at = utc_now_iso()
            return ToolResult(
                tool_id=self.tool_id,
                tool_name=self.tool_name,
                status=ToolStatus.SKIPPED,
                severity=Severity.INFO,
                confidence=Confidence.LOW,
                title="요청 정보 없음",
                description="request가 제공되지 않아 점검을 건너뜁니다.",
                evidence=[],
                started_at=started_at,
                ended_at=ended_at,
            )

        timeout_sec = tool_input.options.timeout / 1000.0
        max_req = tool_input.options.max_requests
        payloads = tool_input.options.extra.get(
            "payloads", ["'", '"', "@@", "1/0", "<script>"]
        )

        if not payloads:
            ended_at = utc_now_iso()
            return ToolResult(
                tool_id=self.tool_id,
                tool_name=self.tool_name,
                status=ToolStatus.ERROR,
                severity=Severity.INFO,
                confidence=Confidence.LOW,
                title="입력 오류",
                description="테스트할 payloads 리스트가 비어있습니다.",
                started_at=started_at,
                ended_at=ended_at,
                errors=[
                    build_tool_error(
                        error_code=ErrorCode.INVALID_INPUT,
                        error_message="Empty payloads list",
                        retryable=False,
                    )
                ],
            )

        target_url = f"{tool_input.target.base_url}{tool_input.request.path}"
        method = tool_input.request.method
        headers = dict(tool_input.request.headers)

        error_keywords = ["Exception", "Traceback", "Error:", "java.lang.", "Stack trace:"]
        vulnerable_evidence = []

        try:
            for payload in payloads[:max_req]:
                params = {"q": payload}

                response = requests.request(
                    method=method,
                    url=target_url,
                    headers=headers,
                    params=params,
                    timeout=timeout_sec,
                    verify=False,
                )
                response_body = response.text

                if any(keyword.lower() in response_body.lower() for keyword in error_keywords):
                    vulnerable_evidence.append(
                        Evidence(
                            request={
                                "method": method,
                                "url": target_url,
                                "headers": mask_sensitive(headers),
                            },
                            response_status=response.status_code,
                            response_headers=dict(response.headers),
                            response_body_sample=sanitize_response_sample(response_body),
                            note=f"페이로드 '{payload}' 전송 시 내부 에러 정보 노출됨",
                        )
                    )
                    break

            ended_at = utc_now_iso()
            if vulnerable_evidence:
                return ToolResult(
                    tool_id=self.tool_id,
                    tool_name=self.tool_name,
                    status=ToolStatus.VULNERABLE,
                    severity=Severity.HIGH,
                    confidence=Confidence.HIGH,
                    title="스택 트레이스 노출 취약점 발견",
                    description="서버 오류 발생 시 내부 시스템 경로 및 스택 트레이스가 노출됩니다.",
                    owasp=["A10:2025 Mishandling of Exceptional Conditions"],
                    cwe=["CWE-209"],
                    evidence=vulnerable_evidence,
                    recommendation="글로벌 예외 처리기를 통해 사용자에게는 일반적인 에러 메시지만 노출해야 합니다.",
                    started_at=started_at,
                    ended_at=ended_at,
                )

            return ToolResult(
                tool_id=self.tool_id,
                tool_name=self.tool_name,
                status=ToolStatus.PASSED,
                severity=Severity.INFO,
                confidence=Confidence.HIGH,
                title="스택 트레이스 안전",
                description="의도적인 에러 유발 시에도 내부 정보가 노출되지 않습니다.",
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
                description="점검 중 내부 통신 오류가 발생했습니다.",
                errors=[
                    build_tool_error(
                        error_code=ErrorCode.INTERNAL_ERROR,
                        error_message=str(e),
                        retryable=False,
                    )
                ],
                started_at=started_at,
                ended_at=ended_at,
            )
