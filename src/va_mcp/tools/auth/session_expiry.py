import time
import requests

from va_mcp.core import (
    BaseTool,
    ToolInput,
    ToolResult,
    Evidence,
    ToolStatus,
    Severity,
    Confidence,
    ErrorCode,
)
from va_mcp.core.utils import (
    build_tool_error,
    utc_now_iso,
    mask_sensitive,
    sanitize_response_sample,
    sanitize_request_body,
)
from va_mcp.core.resolvers.auth_resolver import (
    parse_credentials,
    resolve_auth_headers,
    CredentialResolverError,
)


class SessionExpiryTool(BaseTool):
    tool_id = "auth_session"
    tool_name = "Session Expiry Testing"
    tool_version = "0.1.0"

    def run(self, tool_input: ToolInput) -> ToolResult:
        start_ts = time.time()
        started_at = utc_now_iso()

        # 1) 입력 검증
        req = tool_input.request
        auth_list = tool_input.auth
        options = tool_input.options
        extra = options.extra if options and options.extra else {}

        if not req or not auth_list:
            return ToolResult(
                tool_id=self.tool_id,
                tool_name=self.tool_name,
                status=ToolStatus.SKIPPED.value,
                severity=Severity.INFO.value,
                confidence=Confidence.LOW.value,
                title="입력 부족",
                description="request 또는 auth 정보가 없습니다.",
                evidence=[],
                owasp=[],
                cwe=[],
                recommendation="테스트할 Request와 AuthContext를 제공하세요.",
                started_at=started_at,
                ended_at=started_at,
                duration_ms=0,
                tool_version=self.tool_version,
            )

        try:
            # 2) bearer auth 컨텍스트 선택
            bearer_ctx = next(
                (
                    ctx for ctx in auth_list
                    if getattr(ctx, "auth_type", "").lower() == "bearer"
                       and getattr(ctx, "token", None)
                ),
                None,
            )

            if not bearer_ctx:
                return ToolResult(
                    tool_id=self.tool_id,
                    tool_name=self.tool_name,
                    status=ToolStatus.SKIPPED.value,
                    severity=Severity.INFO.value,
                    confidence=Confidence.LOW.value,
                    title="bearer AuthContext 없음",
                    description="auth 리스트에 bearer 타입과 token이 없습니다.",
                    evidence=[],
                    owasp=[],
                    cwe=[],
                    recommendation="bearer AuthContext를 제공하세요.",
                    started_at=started_at,
                    ended_at=started_at,
                    duration_ms=0,
                    tool_version=self.tool_version,
                )

            # 3) resolver로 토큰 파싱 및 헤더 생성
            try:
                _parsed = parse_credentials(bearer_ctx)
                auth_headers = resolve_auth_headers(bearer_ctx)
            except CredentialResolverError as e:
                ended_at = utc_now_iso()
                return ToolResult(
                    tool_id=self.tool_id,
                    tool_name=self.tool_name,
                    status=ToolStatus.SKIPPED.value,
                    severity=Severity.INFO.value,
                    confidence=Confidence.LOW.value,
                    title="Credential 해석 실패",
                    description=str(e),
                    evidence=[],
                    owasp=[],
                    cwe=[],
                    recommendation="bearer AuthContext를 검토하세요.",
                    started_at=started_at,
                    ended_at=ended_at,
                    duration_ms=int((time.time() - start_ts) * 1000),
                    tool_version=self.tool_version,
                )

            # 4) URL 및 headers 준비
            base = tool_input.target.base_url.rstrip("/")
            path = req.path.lstrip("/")
            url = f"{base}/{path}"

            orig_headers = req.headers or {}
            headers = {**orig_headers, **auth_headers}

            timeout_s = (
                options.timeout / 1000.0
                if options and options.timeout
                else 5
            )
            orig_body = req.body or {}

            # 5) 첫 번째 요청 (유효성 검증)
            res1 = requests.request(
                method=req.method,
                url=url,
                headers=headers,
                json=orig_body if orig_body else None,
                timeout=timeout_s,
            )

            if res1.status_code != 200:
                ended_at = utc_now_iso()
                return ToolResult(
                    tool_id=self.tool_id,
                    tool_name=self.tool_name,
                    status=ToolStatus.SKIPPED.value,
                    severity=Severity.INFO.value,
                    confidence=Confidence.LOW.value,
                    title="테스트 SKIPPED",
                    description=(
                        "첫 번째 요청이 200 OK가 아니어서 "
                        "세션 재사용 테스트를 건너뛰었습니다."
                    ),
                    evidence=[
                        Evidence(
                            request={
                                "method": req.method,
                                "path": req.path,
                                "headers": mask_sensitive(headers),
                                "body": sanitize_request_body(orig_body),
                            },
                            response_status=res1.status_code,
                            response_headers=mask_sensitive(dict(res1.headers)),
                            response_body_sample=sanitize_response_sample(res1.text),
                            note="첫 번째 요청",
                        )
                    ],
                    owasp=[
                        "A07:2025 Identification and Authentication Failures"
                    ],
                    cwe=["CWE-613"],
                    recommendation=(
                        "유효한 토큰으로 먼저 200 OK가 반환되는지 확인하세요."
                    ),
                    started_at=started_at,
                    ended_at=ended_at,
                    duration_ms=int((time.time() - start_ts) * 1000),
                    tool_version=self.tool_version,
                )

            # 6) 대기 후 재요청
            wait_sec = extra.get("wait_seconds", 30)
            time.sleep(wait_sec)

            res2 = requests.request(
                method=req.method,
                url=url,
                headers=headers,
                json=orig_body if orig_body else None,
                timeout=timeout_s,
            )

            # 7) 결과 판별
            if res2.status_code == 200:
                status = ToolStatus.VULNERABLE.value
                severity = Severity.MEDIUM.value
                confidence = Confidence.MEDIUM.value
                title = "세션 재사용 가능"
                description = (
                    f"{wait_sec}초 후에도 동일 토큰으로 접근이 가능합니다."
                )
            else:
                status = ToolStatus.PASSED.value
                severity = Severity.INFO.value
                confidence = Confidence.LOW.value
                title = "세션 재사용 차단"
                description = (
                    f"{wait_sec}초 후 접근이 차단됨 ({res2.status_code})."
                )

            ended_at = utc_now_iso()
            duration_ms = int((time.time() - start_ts) * 1000)

            evidence = [
                Evidence(
                    request={
                        "method": req.method,
                        "path": req.path,
                        "headers": mask_sensitive(headers),
                        "body": sanitize_request_body(orig_body),
                    },
                    response_status=res1.status_code,
                    response_headers=mask_sensitive(dict(res1.headers)),
                    response_body_sample=sanitize_response_sample(res1.text),
                    note="첫 번째 요청 (유효성 검증)",
                ),
                Evidence(
                    request={
                        "method": req.method,
                        "path": req.path,
                        "headers": mask_sensitive(headers),
                        "body": sanitize_request_body(orig_body),
                    },
                    response_status=res2.status_code,
                    response_headers=mask_sensitive(dict(res2.headers)),
                    response_body_sample=sanitize_response_sample(res2.text),
                    note=f"{wait_sec}초 후 두 번째 요청",
                ),
            ]

            return ToolResult(
                tool_id=self.tool_id,
                tool_name=self.tool_name,
                status=status,
                severity=severity,
                confidence=confidence,
                title=title,
                description=description,
                evidence=evidence,
                owasp=[
                    "A07:2025 Identification and Authentication Failures"
                ],
                cwe=["CWE-613"],
                recommendation=(
                    "세션 만료 시간과 토큰 재발급 정책을 검토하세요."
                ),
                started_at=started_at,
                ended_at=ended_at,
                duration_ms=duration_ms,
                tool_version=self.tool_version,
            )

        except requests.Timeout as e:
            ended_at = utc_now_iso()
            return ToolResult(
                tool_id=self.tool_id,
                tool_name=self.tool_name,
                status=ToolStatus.ERROR.value,
                severity=Severity.INFO.value,
                confidence=Confidence.LOW.value,
                title="세션 테스트 타임아웃",
                description=str(e),
                evidence=[],
                errors=[
                    build_tool_error(
                        ErrorCode.TIMEOUT.value,
                        str(e),
                        retryable=True,
                    )
                ],
                owasp=[],
                cwe=[],
                recommendation="네트워크 상태 및 타임아웃 설정을 확인하세요.",
                started_at=started_at,
                ended_at=ended_at,
                duration_ms=0,
                tool_version=self.tool_version,
            )

        except requests.RequestException as e:
            ended_at = utc_now_iso()
            return ToolResult(
                tool_id=self.tool_id,
                tool_name=self.tool_name,
                status=ToolStatus.ERROR.value,
                severity=Severity.INFO.value,
                confidence=Confidence.LOW.value,
                title="HTTP 요청 실패",
                description=str(e),
                evidence=[],
                errors=[
                    build_tool_error(
                        ErrorCode.HTTP_FAILURE.value,
                        str(e),
                        retryable=True,
                    )
                ],
                owasp=[],
                cwe=[],
                recommendation="네트워크 연결 및 요청 형식을 확인하세요.",
                started_at=started_at,
                ended_at=ended_at,
                duration_ms=0,
                tool_version=self.tool_version,
            )

        except Exception as e:
            ended_at = utc_now_iso()
            return ToolResult(
                tool_id=self.tool_id,
                tool_name=self.tool_name,
                status=ToolStatus.ERROR.value,
                severity=Severity.INFO.value,
                confidence=Confidence.LOW.value,
                title="세션 테스트 오류",
                description=str(e),
                evidence=[],
                errors=[
                    build_tool_error(
                        ErrorCode.INTERNAL_ERROR.value,
                        str(e),
                        retryable=False,
                    )
                ],
                owasp=[],
                cwe=[],
                recommendation="도구 내부 오류입니다. 로그를 확인하세요.",
                started_at=started_at,
                ended_at=ended_at,
                duration_ms=0,
                tool_version=self.tool_version,
            )