from __future__ import annotations

# extra 옵션 키:
#   "error_payloads": list[str] — 오류 유발용 쿼리 파라미터 값 목록
#                                 (기본값: DEFAULT_ERROR_PAYLOADS)

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

DEFAULT_ERROR_PAYLOADS = [
    "'",
    "<script>",
    "../../../",
    "%00",
    "{{7*7}}",
]

SENSITIVE_HEADER_KEYS = [
    "Server",
    "X-Powered-By",
    "X-AspNet-Version",
    "X-AspNetMvc-Version",
    "X-Generator",
    "X-Runtime",
]

SENSITIVE_BODY_KEYWORDS = [
    "Traceback (most recent call last)",
    "java.lang.",
    "at com.",
    "at org.",
    "NullPointerException",
    "Exception in thread",
    "Fatal error",
    "Parse error",
    "System.Web.",
    "Microsoft.",
    "SQLException",
    "ORA-",
    "stack trace",
    "Stack Trace",
]


class ErrorInfoExposureTool(BaseTool):
    """
    오류 응답에서 서버 내부 정보(프레임워크, 버전, 스택 트레이스 등)가 노출되는지 점검하는 도구.
    의도적으로 잘못된 입력을 전송해 에러를 유발하고, 응답 헤더와 바디를 분석하며,
    스택 트레이스 노출 시 HIGH, 버전 헤더 노출 시 MEDIUM으로 판정한다.
    """

    tool_id = "error_info_exposure"
    tool_name = "Error Information Exposure Testing"

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
        error_payloads = tool_input.options.extra.get(
            "error_payloads", list(DEFAULT_ERROR_PAYLOADS)
        )

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
            vulnerable_evidence = []
            has_body_exposure = False

            for payload in error_payloads[:max_req]:
                params = dict(tool_input.request.query)
                params["_test"] = payload

                response = requests.request(
                    method=tool_input.request.method,
                    url=target_url,
                    headers=request_headers,
                    params=params,
                    timeout=timeout_sec,
                    verify=False,
                )

                response_headers = dict(response.headers)
                response_header_keys_lower = {k.lower(): k for k in response_headers}
                body = response.text

                exposed_headers = {
                    response_header_keys_lower[key.lower()]: response_headers[response_header_keys_lower[key.lower()]]
                    for key in SENSITIVE_HEADER_KEYS
                    if key.lower() in response_header_keys_lower
                }

                found_keywords = [
                    kw for kw in SENSITIVE_BODY_KEYWORDS
                    if kw.lower() in body.lower()
                ]

                if exposed_headers or found_keywords:
                    if found_keywords:
                        has_body_exposure = True

                    note_parts = []
                    if exposed_headers:
                        header_info = ", ".join(
                            f"{k}: {v}" for k, v in exposed_headers.items()
                        )
                        note_parts.append(f"노출된 헤더: {header_info}")
                    if found_keywords:
                        note_parts.append(f"노출된 키워드: {', '.join(found_keywords)}")

                    vulnerable_evidence.append(
                        Evidence(
                            request={
                                "method": tool_input.request.method,
                                "url": target_url,
                                "headers": mask_sensitive(request_headers),
                                "params": params,
                            },
                            response_status=response.status_code,
                            response_headers=response_headers,
                            response_body_sample=sanitize_response_sample(body),
                            note=" | ".join(note_parts),
                        )
                    )
                    break

            ended_at = utc_now_iso()

            if vulnerable_evidence:
                severity = Severity.HIGH if has_body_exposure else Severity.MEDIUM
                confidence = Confidence.HIGH if has_body_exposure else Confidence.MEDIUM

                return ToolResult(
                    tool_id=self.tool_id,
                    tool_name=self.tool_name,
                    status=ToolStatus.VULNERABLE,
                    severity=severity,
                    confidence=confidence,
                    title="오류 정보 노출 발견",
                    description="서버 오류 응답에서 내부 정보가 노출되었습니다.",
                    owasp=["A02:2025 Security Misconfiguration"],
                    cwe=["CWE-209"],
                    evidence=vulnerable_evidence,
                    recommendation=(
                        "운영 환경에서는 상세 오류 메시지 대신 일반적인 오류 응답만 반환하세요. "
                        "Server, X-Powered-By 등 버전 정보를 포함한 헤더를 제거하거나 변경하세요."
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
                title="오류 정보 미노출",
                description="오류 응답에서 내부 정보가 노출되지 않았습니다.",
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
