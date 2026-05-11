import time
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
    sanitize_request_body,
)
# 필드 매핑 적용을 위한 resolver 추가
from va_mcp.core.resolvers.auth_resolver import parse_credentials, CredentialResolverError


class RateLimitTool(BaseTool):
    tool_id = "auth_rate_limit"
    tool_name = "Login Rate Limit Testing"
    tool_version = "0.1.0"

    def run(self, tool_input: ToolInput) -> ToolResult:
        # 0) 시작 타임스탬프(ms)
        start_ts = time.time()
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
                recommendation="request와 auth를 확인하세요.",
                started_at=started_at,
                ended_at=started_at,
                duration_ms=0,
                tool_version=self.tool_version,
            )

        # 2) credential_fields 매핑 꺼내기
        #    Planner → options.extra.field_mapping.credential_fields 전달 가정
        mapping = (
            tool_input.options.extra
            .get("field_mapping", {})
            .get("credential_fields")
        )
        if not isinstance(mapping, dict) or "username" not in mapping or "password" not in mapping:
            return ToolResult(
                tool_id=self.tool_id,
                tool_name=self.tool_name,
                status=ToolStatus.SKIPPED.value,
                severity=Severity.INFO.value,
                confidence=Confidence.LOW.value,
                title="매핑 누락",
                description="credential_fields 매핑이 없습니다.",
                evidence=[],
                owasp=[],
                cwe=[],
                recommendation="options.extra.field_mapping.credential_fields를 설정하세요.",
                started_at=started_at,
                ended_at=started_at,
                duration_ms=0,
                tool_version=self.tool_version,
            )

        # 3) basic auth 컨텍스트만 사용
        basic_ctx = next(
            (ctx for ctx in tool_input.auth
             if ctx.auth_type == "basic" and ctx.token),
            None
        )
        if not basic_ctx:
            return ToolResult(
                tool_id=self.tool_id,
                tool_name=self.tool_name,
                status=ToolStatus.SKIPPED.value,
                severity=Severity.INFO.value,
                confidence=Confidence.LOW.value,
                title="basic AuthContext 없음",
                description="auth 리스트에 basic 타입과 token이 없습니다.",
                evidence=[],
                owasp=[],
                cwe=[],
                recommendation="basic AuthContext를 제공하세요.",
                started_at=started_at,
                ended_at=started_at,
                duration_ms=0,
                tool_version=self.tool_version,
            )

        # 4) URL 안전 조합
        base = tool_input.target.base_url.rstrip("/")
        path = tool_input.request.path.lstrip("/")
        url = f"{base}/{path}"

        orig_body = tool_input.request.body or {}
        headers = tool_input.request.headers or {}

        status_codes: list[int] = []
        response_times: list[float] = []
        last_res = None

        try:
            # 5) burst: 동일 credential로 max_requests 회 시도
            for _ in range(tool_input.options.max_requests):
                # creds 객체: { mapped_username_field: value, mapped_password_field: value }
                try:
                    creds = parse_credentials(basic_ctx, mapping)
                except CredentialResolverError as e:
                    # 매핑 오류 시 즉시 skipped
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
                        recommendation="basic AuthContext와 mapping을 검토하세요.",
                        started_at=started_at,
                        ended_at=utc_now_iso(),
                        duration_ms=int((time.time() - start_ts) * 1000),
                        tool_version=self.tool_version,
                    )

                body = orig_body.copy()
                body.update(creds)

                t1 = time.time()
                res = requests.request(
                    method=tool_input.request.method,
                    url=url,
                    headers=headers,
                    json=body,
                    timeout=tool_input.options.timeout / 1000,
                )
                t2 = time.time()

                status_codes.append(res.status_code)
                response_times.append((t2 - t1) * 1000)
                last_res = res

            # 6) 요청이 하나도 없으면 skipped
            if not status_codes:
                return ToolResult(
                    tool_id=self.tool_id,
                    tool_name=self.tool_name,
                    status=ToolStatus.SKIPPED.value,
                    severity=Severity.INFO.value,
                    confidence=Confidence.LOW.value,
                    title="요청 없음",
                    description="유효한 요청이 전송되지 않았습니다.",
                    evidence=[],
                    owasp=[],
                    cwe=[],
                    recommendation="basic AuthContext와 mapping을 검토하세요.",
                    started_at=started_at,
                    ended_at=utc_now_iso(),
                    duration_ms=int((time.time() - start_ts) * 1000),
                    tool_version=self.tool_version,
                )

            # 7) 평균 응답시간 및 쓰로틀링 감지
            avg = sum(response_times) / len(response_times)
            is_limited = (
                429 in status_codes
                or status_codes.count(403) > len(status_codes) * 0.3
            )

            # 8) 상태·심각도·신뢰도 결정
            if is_limited:
                status = ToolStatus.PASSED.value
                severity = Severity.INFO.value
            else:
                status = ToolStatus.VULNERABLE.value
                severity = Severity.MEDIUM.value

            confidence = (
                Confidence.HIGH.value if 429 in status_codes
                else Confidence.MEDIUM.value
            )

            title = "Rate Limit 정상" if is_limited else "Rate Limit 없음"
            description = (
                "요청 제한 동작이 확인되었습니다."
                if is_limited
                else "무차별 요청이 가능합니다."
            )

            owasp = ["A07:2025 Identification and Authentication Failures"]
            cwe = ["CWE-770"]
            recommendation = (
                "서버 측에 적절한 rate limiting 정책을 도입하고, "
                "과도 요청 시 429 상태코드를 반환하도록 설정하세요."
            )

            ended_at = utc_now_iso()
            duration_ms = int((time.time() - start_ts) * 1000)

            # 9) 증거 생성
            evidence: list[Evidence] = []
            if last_res:
                evidence.append(
                    Evidence(
                        request={
                            "method": tool_input.request.method,
                            "path": tool_input.request.path,
                            "headers": mask_sensitive(headers),
                            "body": sanitize_request_body(orig_body),
                        },
                        response_status=last_res.status_code,
                        response_headers=mask_sensitive(dict(last_res.headers)),
                        response_body_sample=sanitize_response_sample(last_res.text),
                        note=f"{len(status_codes)}회 요청, avg={avg:.2f}ms",
                    )
                )

            # 10) ToolResult 반환
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
                tool_version=self.tool_version,
            )

        # 11) 에러 처리
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
                title="내부 오류",
                description=str(e),
                evidence=[],
                errors=[build_tool_error(ErrorCode.INTERNAL_ERROR.value, str(e), retryable=False)],
                started_at=started_at,
                ended_at=ended_at,
                duration_ms=0,
                tool_version=self.tool_version,
            )