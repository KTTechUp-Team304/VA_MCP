"""
Cookie Security Attribute Check Tool

API 응답의 Set-Cookie 헤더를 분석하여
Secure, HttpOnly, SameSite 보안 속성이 올바르게 설정되었는지 확인한다.

OWASP: A04 Cryptographic Failures
CWE:   CWE-319 (Cleartext Transmission of Sensitive Information)
       CWE-523 (Unprotected Transport of Credentials)

* request가 있어야 실행된다 (쿠키를 받을 엔드포인트 필요).
"""

from __future__ import annotations

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
import requests

from va_mcp.core.utils import (
    build_tool_error,
    mask_sensitive,
    sanitize_response_sample,
    utc_now_iso,
)


def _parse_cookie_attributes(set_cookie_value: str) -> dict:
    """Set-Cookie 헤더 값을 파싱하여 속성 딕셔너리를 반환한다."""
    parts = [p.strip() for p in set_cookie_value.split(";")]
    name_value = parts[0] if parts else ""
    cookie_name = name_value.split("=")[0].strip() if "=" in name_value else name_value

    samesite = None
    for p in parts[1:]:
        if p.lower().startswith("samesite"):
            samesite = p.split("=")[-1].strip() if "=" in p else ""
            break

    return {
        "name": cookie_name,
        "raw": set_cookie_value,
        "secure": any(p.lower() == "secure" for p in parts[1:]),
        "httponly": any(p.lower() == "httponly" for p in parts[1:]),
        "samesite": samesite,
    }


class CookieSecurityTool(BaseTool):
    """
    응답의 Set-Cookie 헤더를 분석하여 보안 속성 설정 여부를 확인한다.

    - Secure, HttpOnly, SameSite 모두 설정됨: PASSED
    - 하나라도 누락됨:                        VULNERABLE
    - Set-Cookie 헤더 없음:                   SKIPPED
    """

    tool_id = "cookie_security"
    tool_name = "Cookie Security Attribute Check"

    def run(self, tool_input: ToolInput) -> ToolResult:
        started_at = utc_now_iso()

        try:
            # ── 입력 검증 ──
            if tool_input.request is None:
                ended_at = utc_now_iso()
                return ToolResult(
                    tool_id=self.tool_id,
                    tool_name=self.tool_name,
                    status=ToolStatus.SKIPPED,
                    severity=Severity.INFO,
                    confidence=Confidence.LOW,
                    title="요청 정보 없음",
                    description="request가 제공되지 않아 검사를 수행할 수 없습니다.",
                    started_at=started_at,
                    ended_at=ended_at,
                )

            # ── URL 조립 ──
            base_url = tool_input.target.base_url.rstrip("/")
            path = tool_input.request.path
            url = f"{base_url}{path}"

            method = tool_input.request.method.upper()
            headers = dict(tool_input.request.headers)
            query = dict(tool_input.request.query)
            body = tool_input.request.body
            timeout_sec = tool_input.options.timeout / 1000

            # ── 인증 헤더 주입 ──
            if tool_input.auth:
                auth_ctx = tool_input.auth[0]
                if auth_ctx.auth_type == "bearer" and auth_ctx.token:
                    headers["Authorization"] = f"Bearer {auth_ctx.token}"
                elif auth_ctx.auth_type == "cookie" and auth_ctx.cookie:
                    headers["Cookie"] = auth_ctx.cookie

            # ── 요청 전송 ──
            resp = requests.request(
                method=method,
                url=url,
                headers=headers,
                params=query,
                json=body if method in ("POST", "PUT", "PATCH") else None,
                timeout=timeout_sec,
                allow_redirects=False,  # 리다이렉트 전 Set-Cookie도 캡처
            )

            # ── Set-Cookie 헤더 수집 ──
            # requests는 동일 키를 하나로 합치므로 raw headers에서 직접 수집
            set_cookie_headers: list[str] = []
            for key, value in resp.raw.headers.items():
                if key.lower() == "set-cookie":
                    set_cookie_headers.append(value)

            if not set_cookie_headers:
                ended_at = utc_now_iso()
                return ToolResult(
                    tool_id=self.tool_id,
                    tool_name=self.tool_name,
                    status=ToolStatus.SKIPPED,
                    severity=Severity.INFO,
                    confidence=Confidence.LOW,
                    title="쿠키 없음",
                    description="응답에 Set-Cookie 헤더가 없어 쿠키 보안 속성을 검사할 수 없습니다.",
                    started_at=started_at,
                    ended_at=ended_at,
                )

            # ── 쿠키별 속성 분석 ──
            vulnerable_cookies: list[dict] = []
            all_cookies: list[dict] = []

            for raw_cookie in set_cookie_headers:
                parsed = _parse_cookie_attributes(raw_cookie)
                all_cookies.append(parsed)

                cookie_issues: list[str] = []
                is_samesite_none = (
                    parsed["samesite"] is not None
                    and parsed["samesite"].lower() == "none"
                )

                # Secure 속성 누락 — SameSite=None 케이스는 아래에서 더 구체적인 메시지로 처리
                if not parsed["secure"] and not is_samesite_none:
                    cookie_issues.append("Secure 속성 누락")
                if not parsed["httponly"]:
                    cookie_issues.append("HttpOnly 속성 누락")
                if parsed["samesite"] is None:
                    cookie_issues.append("SameSite 속성 누락")
                elif parsed["samesite"] == "":
                    cookie_issues.append("SameSite 속성에 값이 없음 (유효하지 않은 설정)")
                elif is_samesite_none:
                    if not parsed["secure"]:
                        # Secure 없음 + SameSite=None → 평문 전송 + CSRF 위험을 하나의 메시지로 통합
                        cookie_issues.append(
                            "SameSite=None이고 Secure 속성이 없습니다. "
                            "쿠키가 HTTP로 평문 전송되며 CSRF 공격에도 취약합니다."
                        )
                    # SameSite=None + Secure 조합은 크로스사이트 쿠키로 유효한 설정

                if cookie_issues:
                    parsed["issues"] = cookie_issues
                    vulnerable_cookies.append(parsed)

            # ── 결과 판정 ──
            evidence = Evidence(
                request={
                    "method": method,
                    "url": url,
                    "headers": mask_sensitive(headers),
                },
                response_status=resp.status_code,
                response_headers=dict(resp.headers),
                response_body_sample=sanitize_response_sample(resp.text),
                note="",
            )

            if vulnerable_cookies:
                issues_summary = "; ".join(
                    f"{c['name']}: {', '.join(c['issues'])}"
                    for c in vulnerable_cookies
                )
                evidence.note = (
                    f"{len(vulnerable_cookies)}/{len(all_cookies)}개 쿠키에서 보안 속성 누락. "
                    f"상세: {issues_summary}"
                )
                ended_at = utc_now_iso()
                return ToolResult(
                    tool_id=self.tool_id,
                    tool_name=self.tool_name,
                    status=ToolStatus.VULNERABLE,
                    severity=Severity.MEDIUM,
                    confidence=Confidence.HIGH,
                    title="쿠키 보안 속성 누락",
                    description=(
                        f"{len(all_cookies)}개 쿠키 중 {len(vulnerable_cookies)}개에서 "
                        f"보안 속성이 누락되었습니다. 상세: {issues_summary}"
                    ),
                    owasp=["A04 Cryptographic Failures"],
                    cwe=["CWE-319", "CWE-523"],
                    evidence=[evidence],
                    recommendation=(
                        "모든 쿠키에 Secure, HttpOnly, SameSite=Strict(또는 Lax) 속성을 설정하세요. "
                        "Secure: HTTPS 전송만 허용. "
                        "HttpOnly: JavaScript 접근 차단(XSS 방어). "
                        "SameSite: CSRF 공격 방어."
                    ),
                    started_at=started_at,
                    ended_at=ended_at,
                )

            evidence.note = (
                f"{len(all_cookies)}개 쿠키 모두 Secure, HttpOnly, SameSite 속성이 설정되어 있습니다."
            )
            ended_at = utc_now_iso()
            return ToolResult(
                tool_id=self.tool_id,
                tool_name=self.tool_name,
                status=ToolStatus.PASSED,
                severity=Severity.INFO,
                confidence=Confidence.HIGH,
                title="쿠키 보안 속성 적용됨",
                description=(
                    f"{len(all_cookies)}개 쿠키 모두 Secure, HttpOnly, SameSite 속성이 "
                    f"올바르게 설정되어 있습니다."
                ),
                owasp=["A04 Cryptographic Failures"],
                cwe=["CWE-319", "CWE-523"],
                evidence=[evidence],
                recommendation=(
                    "현재 쿠키 보안 설정이 적절합니다. "
                    "새로운 쿠키 추가 시에도 동일한 기준을 적용하세요."
                ),
                started_at=started_at,
                ended_at=ended_at,
            )

        except requests.exceptions.Timeout as exc:
            ended_at = utc_now_iso()
            return ToolResult(
                tool_id=self.tool_id,
                tool_name=self.tool_name,
                status=ToolStatus.ERROR,
                severity=Severity.INFO,
                confidence=Confidence.LOW,
                title="요청 시간 초과",
                description="대상 서버로의 요청이 시간 초과되었습니다.",
                started_at=started_at,
                ended_at=ended_at,
                errors=[
                    build_tool_error(
                        error_code=ErrorCode.TIMEOUT,
                        error_message=str(exc),
                        retryable=True,
                    )
                ],
            )

        except requests.exceptions.RequestException as exc:
            ended_at = utc_now_iso()
            return ToolResult(
                tool_id=self.tool_id,
                tool_name=self.tool_name,
                status=ToolStatus.ERROR,
                severity=Severity.INFO,
                confidence=Confidence.LOW,
                title="HTTP 요청 실패",
                description="대상 서버로의 HTTP 요청이 실패했습니다.",
                started_at=started_at,
                ended_at=ended_at,
                errors=[
                    build_tool_error(
                        error_code=ErrorCode.HTTP_FAILURE,
                        error_message=str(exc),
                        retryable=True,
                    )
                ],
            )

        except Exception as exc:
            ended_at = utc_now_iso()
            return ToolResult(
                tool_id=self.tool_id,
                tool_name=self.tool_name,
                status=ToolStatus.ERROR,
                severity=Severity.INFO,
                confidence=Confidence.LOW,
                title="실행 오류",
                description="예상치 못한 오류가 발생했습니다.",
                started_at=started_at,
                ended_at=ended_at,
                errors=[
                    build_tool_error(
                        error_code=ErrorCode.INTERNAL_ERROR,
                        error_message=str(exc),
                        retryable=False,
                    )
                ],
            )
