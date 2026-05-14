import requests
from datetime import datetime

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
)
from va_mcp.core.resolvers.auth_resolver import (
    parse_credentials,
    resolve_auth_headers,
    CredentialResolverError,
)


class JwtValidationTool(BaseTool):
    tool_id = "auth_jwt"
    tool_name = "JWT Validation Testing"

    def run(self, tool_input: ToolInput) -> ToolResult:
        started_at = utc_now_iso()

        # 1) 입력 검증
        if not tool_input.request or not tool_input.auth:
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
                recommendation="",
                started_at=started_at,
                ended_at=started_at,
                duration_ms=0,
            )

        try:
            # 2) bearer AuthContext 선택
            bearer_ctx = next(
                (
                    ctx for ctx in tool_input.auth
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
                )

            # 3) resolver로 토큰 파싱 및 header 생성
            try:
                parsed       = parse_credentials(bearer_ctx)
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
                    duration_ms=0,
                )

            token = parsed.get("token", "") or ""
            if not token:
                raise ValueError("JWT 토큰이 비어 있습니다")

            auth_headers_valid = resolve_auth_headers(bearer_ctx)

            # 4) 변조 토큰용 context 생성
            tampered = token[:-1] + "X"
            tampered_ctx = type("T", (), {
                "auth_type": getattr(bearer_ctx, "auth_type", "bearer"),
                "token": tampered
            })()
            auth_headers_tampered = resolve_auth_headers(tampered_ctx)

            # 5) URL 준비
            url = tool_input.target.base_url + tool_input.request.path
            timeout_s = tool_input.options.timeout / 1000

            orig_headers = {}
            orig_headers.update(auth_headers_valid)

            # 6) 정상/변조 토큰 요청
            res_valid = requests.request(
                method=tool_input.request.method,
                url=url,
                headers=orig_headers,
                json=tool_input.request.body if tool_input.request.body else None,  # 추가
                timeout=timeout_s,
            )
            res_tampered = requests.request(
                method=tool_input.request.method,
                url=url,
                headers=auth_headers_tampered,
                json=tool_input.request.body if tool_input.request.body else None,  # 추가
                timeout=timeout_s,
            )

            # 7) 첫 요청이 실패하면 SKIPPED
            if not (200 <= res_valid.status_code < 300):
                ended_at = utc_now_iso()
                return ToolResult(
                    tool_id=self.tool_id,
                    tool_name=self.tool_name,
                    status=ToolStatus.SKIPPED.value,
                    severity=Severity.INFO.value,
                    confidence=Confidence.LOW.value,
                    title="테스트 SKIPPED",
                    description="정상 토큰이 유효하지 않아 JWT 변조 테스트를 건너뛰었습니다.",
                    evidence=[],
                    owasp=[],
                    cwe=[],
                    recommendation="",
                    started_at=started_at,
                    ended_at=ended_at,
                    duration_ms=0,
                )

            # 8) 취약 여부 판단
            vulnerable = 200 <= res_tampered.status_code < 300

            # 9) 결과 설정
            owasp = ["A02:2025 Cryptographic Failures"]
            cwe   = ["CWE-347"]
            if vulnerable:
                status = ToolStatus.VULNERABLE.value
                severity = Severity.HIGH.value
                confidence = Confidence.HIGH.value
                title = "JWT 검증 실패"
                description = "변조된 토큰이 허용됩니다."
                recommendation = "서버에서 JWT 서명 및 유효성 검증을 반드시 수행하세요."
            else:
                status = ToolStatus.PASSED.value
                severity = Severity.INFO.value
                confidence = Confidence.LOW.value
                title = "JWT 검증 정상"
                description = "변조된 토큰이 차단됩니다."
                recommendation = "변조 토큰이 차단되는지 확인되었습니다."

            ended_at = utc_now_iso()

            # 10) evidence 생성 (변조 토큰 결과만)
            evidence = [
                Evidence(
                    request={
                        "method": tool_input.request.method,
                        "path": tool_input.request.path,
                        "headers": mask_sensitive(auth_headers_tampered),
                    },
                    response_status=res_tampered.status_code,
                    response_headers=mask_sensitive(dict(res_tampered.headers)),
                    response_body_sample=sanitize_response_sample(res_tampered.text),
                    note="변조 토큰 테스트",
                )
            ]

            # 11) duration 계산
            duration_ms = int(
                (
                    datetime.fromisoformat(ended_at.replace("Z", ""))
                    - datetime.fromisoformat(started_at.replace("Z", ""))
                ).total_seconds()
                * 1000
            )

            return ToolResult(
                tool_id=self.tool_id,
                tool_name=self.tool_name,
                status=status,
                severity=severity,
                confidence=confidence,
                title=title,
                description=description,
                evidence=evidence,
                owasp=owasp,
                cwe=cwe,
                recommendation=recommendation,
                started_at=started_at,
                ended_at=ended_at,
                duration_ms=duration_ms,
            )

        except requests.Timeout as e:
            ended_at = utc_now_iso()
            return ToolResult(
                tool_id=self.tool_id,
                tool_name=self.tool_name,
                status=ToolStatus.ERROR.value,
                severity=Severity.INFO.value,
                confidence=Confidence.LOW.value,
                title="JWT 테스트 타임아웃",
                description=str(e),
                evidence=[],
                owasp=[],
                cwe=[],
                recommendation="",
                errors=[build_tool_error(ErrorCode.TIMEOUT.value, str(e), retryable=True)],
                started_at=started_at,
                ended_at=ended_at,
                duration_ms=0,
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
                errors=[build_tool_error(ErrorCode.HTTP_FAILURE.value, str(e), retryable=True)],
                started_at=started_at,
                ended_at=ended_at,
                duration_ms=0,
            )

        except Exception as e:
            ended_at = utc_now_iso()
            return ToolResult(
                tool_id=self.tool_id,
                tool_name=self.tool_name,
                status=ToolStatus.ERROR.value,
                severity=Severity.INFO.value,
                confidence=Confidence.LOW.value,
                title="JWT 테스트 오류",
                description=str(e),
                evidence=[],
                errors=[build_tool_error(ErrorCode.INTERNAL_ERROR.value, str(e), retryable=False)],
                started_at=started_at,
                ended_at=ended_at,
                duration_ms=0,
            )