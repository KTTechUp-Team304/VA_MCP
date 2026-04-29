from __future__ import annotations

# extra 옵션 키:
#   "test_origins": list[str] — 테스트에 사용할 Origin 값 목록
#                               (기본값: ["https://evil.example.com", "null"])

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

DEFAULT_TEST_ORIGINS = [
    "https://evil.example.com",
    "null",
]


class CorsMisconfigurationTool(BaseTool):
    """
    대상 엔드포인트의 CORS 정책 오설정 여부를 점검하는 도구.
    임의의 Origin 헤더를 전송하여 서버가 이를 무분별하게 허용하는지 확인하며,
    자격 증명(Credentials) 허용 여부에 따라 위험도를 구분하여 판정한다.
    """

    tool_id = "cors_misconfiguration"
    tool_name = "CORS Misconfiguration Testing"

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
        test_origins = tool_input.options.extra.get("test_origins", list(DEFAULT_TEST_ORIGINS))

        target_url = f"{tool_input.target.base_url}{tool_input.request.path}"
        base_headers = dict(tool_input.request.headers)

        if tool_input.auth:
            auth: AuthContext = tool_input.auth[0]
            if auth.auth_type == "bearer" and auth.token:
                base_headers["Authorization"] = f"Bearer {auth.token}"
            elif auth.auth_type == "cookie" and auth.cookie:
                base_headers["Cookie"] = auth.cookie
            elif auth.auth_type == "api_key" and auth.token:
                base_headers["X-API-Key"] = auth.token

        try:
            vulnerable_evidence = []
            result_severity = Severity.INFO
            result_confidence = Confidence.LOW

            for origin in test_origins[:max_req]:
                request_headers = dict(base_headers)
                request_headers["Origin"] = origin

                response = requests.request(
                    method=tool_input.request.method,
                    url=target_url,
                    headers=request_headers,
                    params=dict(tool_input.request.query),
                    timeout=timeout_sec,
                    verify=False,
                )

                acao = response.headers.get("Access-Control-Allow-Origin", "")
                acac = response.headers.get("Access-Control-Allow-Credentials", "").lower()
                allows_credentials = acac == "true"
                is_reflected = acao == origin
                is_wildcard = acao == "*"

                if is_reflected and allows_credentials:
                    # 임의 Origin 반사 + 자격증명 허용 → 가장 위험, 실제 악용 가능
                    result_severity = Severity.HIGH
                    result_confidence = Confidence.HIGH
                    vulnerable_evidence.append(
                        Evidence(
                            request={
                                "method": tool_input.request.method,
                                "url": target_url,
                                "headers": mask_sensitive(request_headers),
                            },
                            response_status=response.status_code,
                            response_headers=dict(response.headers),
                            response_body_sample=sanitize_response_sample(response.text),
                            note=(
                                f"Origin '{origin}' 반사 및 자격 증명 허용 확인. "
                                f"ACAO: {acao}, ACAC: {acac}"
                            ),
                        )
                    )
                    break  # 가장 위험한 케이스 발견 시 즉시 중단

                elif is_wildcard and allows_credentials:
                    # 와일드카드 + 자격증명 → 브라우저 차단이지만 서버 설정 오류
                    result_severity = Severity.MEDIUM
                    result_confidence = Confidence.HIGH
                    vulnerable_evidence.append(
                        Evidence(
                            request={
                                "method": tool_input.request.method,
                                "url": target_url,
                                "headers": mask_sensitive(request_headers),
                            },
                            response_status=response.status_code,
                            response_headers=dict(response.headers),
                            response_body_sample=sanitize_response_sample(response.text),
                            note=(
                                "와일드카드(*)와 자격 증명 허용이 동시에 설정됨. "
                                f"ACAO: {acao}, ACAC: {acac}"
                            ),
                        )
                    )

                elif is_reflected and not allows_credentials:
                    # 임의 Origin 반사이지만 자격증명 없음 → 낮은 위험
                    if result_severity not in (Severity.HIGH, Severity.MEDIUM):
                        result_severity = Severity.LOW
                        result_confidence = Confidence.MEDIUM
                    vulnerable_evidence.append(
                        Evidence(
                            request={
                                "method": tool_input.request.method,
                                "url": target_url,
                                "headers": mask_sensitive(request_headers),
                            },
                            response_status=response.status_code,
                            response_headers=dict(response.headers),
                            response_body_sample=sanitize_response_sample(response.text),
                            note=(
                                f"Origin '{origin}' 반사 확인 (자격 증명 미허용). "
                                f"ACAO: {acao}"
                            ),
                        )
                    )

            ended_at = utc_now_iso()

            if vulnerable_evidence:
                return ToolResult(
                    tool_id=self.tool_id,
                    tool_name=self.tool_name,
                    status=ToolStatus.VULNERABLE,
                    severity=result_severity,
                    confidence=result_confidence,
                    title="CORS 오설정 발견",
                    description="대상 엔드포인트에서 CORS 정책 오설정이 발견되었습니다.",
                    owasp=["A02:2025 Security Misconfiguration"],
                    cwe=["CWE-942"],
                    evidence=vulnerable_evidence,
                    recommendation=(
                        "허용할 Origin을 명시적인 화이트리스트로 관리하세요. "
                        "Access-Control-Allow-Credentials: true 사용 시 "
                        "와일드카드(*) 및 임의 Origin 반사를 금지하세요."
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
                title="CORS 정책 정상",
                description="임의 Origin에 대한 무분별한 허용이 확인되지 않았습니다.",
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
