from __future__ import annotations

# extra 옵션 키:
#   "debug_paths": list[str] — 점검할 디버그 엔드포인트 경로 목록
#                              (기본값: DEFAULT_DEBUG_PATHS)

import requests

from va_mcp.core import (
    AuthContext,
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

DEFAULT_DEBUG_PATHS = [
    "/debug",
    "/__debug__",
    "/console",
    "/profiler",
    "/actuator",
    "/actuator/env",
    "/actuator/beans",
    "/actuator/metrics",
    "/actuator/loggers",
    "/actuator/threaddump",
    "/swagger-ui",
    "/swagger-ui.html",
    "/api-docs",
    "/v2/api-docs",
    "/v3/api-docs",
    "/graphiql",
    "/metrics",
    "/__admin__",
]

# 접근 가능(200) 판정 상태 코드
_ACCESSIBLE_STATUS = {200}
# 존재하지만 차단(403/401) 판정 상태 코드
_EXISTS_STATUS = {401, 403}


class DebugEndpointTool(BaseTool):
    """
    운영 환경에 노출된 디버그 및 관리용 엔드포인트를 탐지하는 도구.
    /actuator, /swagger-ui, /console 등 주요 경로에 요청을 보내며,
    HTTP 200이면 HIGH, 401/403이면 엔드포인트 존재 확인으로 MEDIUM을 판정한다.
    """

    tool_id = "debug_endpoint"
    tool_name = "Debug Endpoint Detection"

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
        debug_paths = tool_input.options.extra.get(
            "debug_paths", list(DEFAULT_DEBUG_PATHS)
        )

        base_url = tool_input.target.base_url
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
            vulnerable_evidence: list[Evidence] = []

            for path in debug_paths[:max_req]:
                target_url = f"{base_url}{path}"

                response = requests.get(
                    url=target_url,
                    headers=request_headers,
                    timeout=timeout_sec,
                    verify=False,
                    allow_redirects=False,
                )

                if response.status_code in _ACCESSIBLE_STATUS:
                    vulnerable_evidence.append(
                        Evidence(
                            request={
                                "method": "GET",
                                "url": target_url,
                                "headers": mask_sensitive(request_headers),
                            },
                            response_status=response.status_code,
                            response_headers=dict(response.headers),
                            response_body_sample=sanitize_response_sample(response.text),
                            note=f"디버그 엔드포인트 '{path}' 직접 접근 가능 (HTTP 200)",
                        )
                    )
                elif response.status_code in _EXISTS_STATUS:
                    vulnerable_evidence.append(
                        Evidence(
                            request={
                                "method": "GET",
                                "url": target_url,
                                "headers": mask_sensitive(request_headers),
                            },
                            response_status=response.status_code,
                            response_headers=dict(response.headers),
                            response_body_sample=sanitize_response_sample(response.text),
                            note=(
                                f"디버그 엔드포인트 '{path}' 존재 확인 "
                                f"(HTTP {response.status_code} - 접근 차단됨)"
                            ),
                        )
                    )

            ended_at = utc_now_iso()

            if vulnerable_evidence:
                has_accessible = any(
                    e.response_status in _ACCESSIBLE_STATUS for e in vulnerable_evidence
                )
                severity = Severity.HIGH if has_accessible else Severity.MEDIUM
                confidence = Confidence.HIGH if has_accessible else Confidence.MEDIUM

                return ToolResult(
                    tool_id=self.tool_id,
                    tool_name=self.tool_name,
                    status=ToolStatus.VULNERABLE,
                    severity=severity,
                    confidence=confidence,
                    title="디버그 엔드포인트 노출 발견",
                    description=f"{len(vulnerable_evidence)}개의 디버그 엔드포인트가 탐지되었습니다.",
                    owasp=["A02:2025 Security Misconfiguration"],
                    cwe=["CWE-215"],
                    evidence=vulnerable_evidence,
                    recommendation=(
                        "운영 환경에서는 디버그 및 관리용 엔드포인트를 비활성화하거나 "
                        "IP 화이트리스트 등으로 접근을 엄격히 제한하세요."
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
                title="디버그 엔드포인트 미노출",
                description="점검한 경로에서 노출된 디버그 엔드포인트가 발견되지 않았습니다.",
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
