from __future__ import annotations

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
    sanitize_request_body,
    sanitize_response_sample,
    utc_now_iso,
)


class TimeoutHandlingTool(BaseTool):
    """
    서버의 타임아웃 처리 및 가용성(Availability)을 점검하는 도구입니다.
    인위적인 지연을 유발하는 요청에 대해 서버가 적절한 에러(504 등)로 대응하는지,
    혹은 내부 오류(500)가 발생하거나 응답을 무한 대기하여 자원을 고갈시키는지 확인합니다.
    """

    tool_id = "timeout_handling"
    tool_name = "Timeout Handling Check"

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

        target = tool_input.target
        request_info = tool_input.request
        target_url = f"{target.base_url.rstrip('/')}/{request_info.path.lstrip('/')}"
        method = request_info.method.upper()
        headers = dict(request_info.headers)
        headers.setdefault("X-Test-Delay", "true")

        evidence_list: list[Evidence] = []
        is_vulnerable = False

        try:
            response = requests.request(
                method=method,
                url=target_url,
                headers=headers,
                params=dict(request_info.query),
                json=request_info.body,
                timeout=timeout_sec,
                verify=False,
            )

            status_code = response.status_code
            is_vulnerable = (status_code == 500)

            evidence_list.append(
                Evidence(
                    request={
                        "method": method,
                        "url": target_url,
                        "headers": mask_sensitive(headers),
                        "body": sanitize_request_body(request_info.body),
                    },
                    response_status=status_code,
                    response_headers=dict(response.headers),
                    response_body_sample=sanitize_response_sample(response.text),
                    note=(
                        "서버 내부 오류(500) 발생으로 인한 가용성 저하 확인"
                        if is_vulnerable
                        else "정상 응답 혹은 적절한 에러 처리로 방어됨"
                    ),
                )
            )

        except requests.exceptions.Timeout:
            is_vulnerable = True
            evidence_list.append(
                Evidence(
                    request={
                        "method": method,
                        "url": target_url,
                        "headers": mask_sensitive(headers),
                        "body": sanitize_request_body(request_info.body),
                    },
                    response_status=0,
                    note=f"서버가 설정된 {timeout_sec}초 내에 응답을 반환하지 못해 타임아웃 발생",
                )
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
                description="점검 중 통신 오류가 발생했습니다.",
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

        ended_at = utc_now_iso()
        return ToolResult(
            tool_id=self.tool_id,
            tool_name=self.tool_name,
            status=ToolStatus.VULNERABLE if is_vulnerable else ToolStatus.PASSED,
            severity=Severity.HIGH if is_vulnerable else Severity.INFO,
            confidence=Confidence.HIGH if is_vulnerable else Confidence.LOW,
            title="불충분한 서버 측 타임아웃 처리" if is_vulnerable else "안전한 타임아웃 처리",
            description=(
                "인위적인 지연 요청 시 서버가 내부 오류를 일으키거나 응답을 무한 대기하여 가용성에 영향을 줄 수 있음"
                if is_vulnerable
                else "지연 요청 시에도 서버에 영향이 가지 않음을 확인하였음(정상)"
            ),
            owasp=["A10:2025 Mishandling of Exceptional Conditions"],
            cwe=["CWE-770"],
            recommendation=(
                "글로벌 타임아웃 적용 및 자원 점유 방지 조치가 필요합니다."
                if is_vulnerable
                else "조치가 필요하지 않습니다."
            ),
            evidence=evidence_list,
            started_at=started_at,
            ended_at=ended_at,
        )
