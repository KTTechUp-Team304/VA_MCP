from __future__ import annotations

# extra 옵션 키:
#   "custom_headers": list[str] — 기본 목록 외 추가로 점검할 헤더 이름 (기본값: [])

import requests

from va_mcp.core.base import BaseTool
from va_mcp.core.constants import Confidence, ErrorCode, Severity, ToolStatus
from va_mcp.core.schemas import AuthContext, Evidence, ToolInput, ToolResult
from va_mcp.core.utils import (
    build_tool_error,
    mask_sensitive,
    sanitize_response_sample,
    utc_now_iso,
)

REQUIRED_SECURITY_HEADERS = [
    "Content-Security-Policy",
    "Strict-Transport-Security",
    "X-Content-Type-Options",
    "X-Frame-Options",
    "Referrer-Policy",
    "Permissions-Policy",
]


class SecurityHeadersTool(BaseTool):
    """
    서버 HTTP 응답에서 필수 보안 헤더 누락 여부를 점검하는 도구.
    Content-Security-Policy, Strict-Transport-Security 등 6종의 헤더를 확인하며,
    누락된 헤더가 있을 경우 VULNERABLE로 판정하고 증거를 기록한다.
    """

    tool_id = "security_headers"
    tool_name = "Security Headers Analysis"

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
        custom_headers = tool_input.options.extra.get("custom_headers", [])
        headers_to_check = REQUIRED_SECURITY_HEADERS + list(custom_headers)

        target_url = f"{tool_input.target.base_url}{tool_input.request.path}"
        request_headers = dict(tool_input.request.headers)

        if tool_input.auth:
            auth: AuthContext = tool_input.auth[0]
            if auth.auth_type == "bearer" and auth.token:
                request_headers["Authorization"] = f"Bearer {auth.token}"
            elif auth.auth_type == "cookie" and auth.cookie:
                request_headers["Cookie"] = auth.cookie
            elif auth.auth_type == "api_key" and auth.token:
                request_headers["X-API-Key"] = auth.token

        try:
            response = requests.request(
                method=tool_input.request.method,
                url=target_url,
                headers=request_headers,
                params=dict(tool_input.request.query),
                timeout=timeout_sec,
                verify=False,
            )

            response_headers = dict(response.headers)
            response_header_keys_lower = {k.lower() for k in response_headers}
            missing_headers = [
                h for h in headers_to_check
                if h.lower() not in response_header_keys_lower
            ]

            ended_at = utc_now_iso()

            if missing_headers:
                evidence = [
                    Evidence(
                        request={
                            "method": tool_input.request.method,
                            "url": target_url,
                            "headers": mask_sensitive(request_headers),
                        },
                        response_status=response.status_code,
                        response_headers=response_headers,
                        response_body_sample=sanitize_response_sample(response.text),
                        note=f"누락된 보안 헤더 ({len(missing_headers)}개): {', '.join(missing_headers)}",
                    )
                ]
                return ToolResult(
                    tool_id=self.tool_id,
                    tool_name=self.tool_name,
                    status=ToolStatus.VULNERABLE,
                    severity=Severity.MEDIUM,
                    confidence=Confidence.HIGH,
                    title="보안 헤더 누락 발견",
                    description=(
                        f"응답에서 {len(missing_headers)}개의 보안 헤더가 누락되었습니다: "
                        f"{', '.join(missing_headers)}"
                    ),
                    owasp=["A05:2021 Security Misconfiguration"],
                    cwe=["CWE-16"],
                    evidence=evidence,
                    recommendation=(
                        "누락된 보안 헤더를 서버 응답에 추가하세요. "
                        "Content-Security-Policy와 Strict-Transport-Security는 필수입니다."
                    ),
                    started_at=started_at,
                    ended_at=ended_at,
                )

            return ToolResult(
                tool_id=self.tool_id,
                tool_name=self.tool_name,
                status=ToolStatus.PASSED,
                severity=Severity.INFO,
                confidence=Confidence.HIGH,
                title="보안 헤더 정상",
                description="모든 필수 보안 헤더가 응답에 포함되어 있습니다.",
                started_at=started_at,
                ended_at=ended_at,
            )

        except requests.exceptions.Timeout:
            ended_at = utc_now_iso()
            return ToolResult(
                tool_id=self.tool_id,
                tool_name=self.tool_name,
                status=ToolStatus.ERROR,
                severity=Severity.INFO,
                confidence=Confidence.LOW,
                title="요청 타임아웃",
                description="HTTP 요청이 제한 시간 내에 완료되지 않았습니다.",
                started_at=started_at,
                ended_at=ended_at,
                errors=[
                    build_tool_error(
                        error_code=ErrorCode.TIMEOUT,
                        error_message=f"요청이 {timeout_sec}초 안에 완료되지 않았습니다.",
                        retryable=True,
                    )
                ],
            )

        except requests.exceptions.ConnectionError as e:
            ended_at = utc_now_iso()
            return ToolResult(
                tool_id=self.tool_id,
                tool_name=self.tool_name,
                status=ToolStatus.ERROR,
                severity=Severity.INFO,
                confidence=Confidence.LOW,
                title="연결 오류",
                description="대상 서버에 연결할 수 없습니다.",
                started_at=started_at,
                ended_at=ended_at,
                errors=[
                    build_tool_error(
                        error_code=ErrorCode.HTTP_FAILURE,
                        error_message=str(e),
                        retryable=True,
                    )
                ],
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
                description="예상치 못한 오류가 발생했습니다.",
                started_at=started_at,
                ended_at=ended_at,
                errors=[
                    build_tool_error(
                        error_code=ErrorCode.INTERNAL_ERROR,
                        error_message=str(e),
                        retryable=False,
                    )
                ],
            )
