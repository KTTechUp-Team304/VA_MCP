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

import requests
import time
from typing import Any, Dict, List

from va_mcp.core import (
    AuthContext,
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
    mask_sensitive,
    sanitize_request_body,
    sanitize_response_sample,
    utc_now_iso,
)
from va_mcp.core.resolvers.auth_resolver import (
    parse_credentials,
    resolve_auth_headers,
    CredentialResolverError,
)


def _parse_cookie_attributes(set_cookie_value: str) -> Dict[str, Any]:
    """Set-Cookie 헤더 값을 파싱하여 속성 딕셔너리를 반환합니다."""
    parts = [p.strip() for p in set_cookie_value.split(";")]
    name_value = parts[0] if parts else ""
    cookie_name = name_value.split("=", 1)[0].strip() if "=" in name_value else name_value

    samesite = None
    for p in parts[1:]:
        if p.lower().startswith("samesite"):
            samesite = p.split("=", 1)[-1].strip() if "=" in p else ""
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
    응답의 Set-Cookie 헤더를 분석하여 보안 속성 설정 여부를 확인합니다.

    - Secure, HttpOnly, SameSite 모두 설정됨: PASSED
    - 하나라도 누락됨:                        VULNERABLE
    - Set-Cookie 헤더 없음:                   SKIPPED
    """
    tool_id = "cookie_security"
    tool_name = "Cookie Security Attribute Check"
    tool_version = "0.1.0"

    def run(self, tool_input: ToolInput) -> ToolResult:
        start_ts   = time.time()
        started_at = utc_now_iso()

        # 1) request 방어
        req = tool_input.request
        if not req:
            ended_at = utc_now_iso()
            return ToolResult(
                tool_id=self.tool_id,
                tool_name=self.tool_name,
                status=ToolStatus.SKIPPED.value,
                severity=Severity.INFO.value,
                confidence=Confidence.LOW.value,
                title="요청 정보 없음",
                description="request가 제공되지 않아 검사를 수행할 수 없습니다.",
                evidence=[],
                started_at=started_at,
                ended_at=ended_at,
                duration_ms=0,
                tool_version=self.tool_version,
            )

        # 2) options/extra 방어
        opts: Any = tool_input.options
        extra: Dict[str, Any] = opts.extra if opts and opts.extra else {}
        timeout_s = (opts.timeout / 1000.0) if opts and opts.timeout else 5

        # 3) URL 안전 조합
        base = tool_input.target.base_url.rstrip("/")
        path = req.path.lstrip("/")
        url = f"{base}/{path}"

        # 4) headers 방어 및 auth_resolver 적용
        orig_headers = req.headers.copy() if req.headers else {}
        auth_ctx: AuthContext | None = tool_input.auth[0] if tool_input.auth else None
        if auth_ctx:
            try:
                parse_credentials(auth_ctx)
                auth_headers = resolve_auth_headers(auth_ctx)
                headers = {**orig_headers, **auth_headers}
            except CredentialResolverError as e:
                ended_at = utc_now_iso()
                duration_ms = int((time.time() - start_ts) * 1000)
                return ToolResult(
                    tool_id=self.tool_id,
                    tool_name=self.tool_name,
                    status=ToolStatus.SKIPPED.value,
                    severity=Severity.INFO.value,
                    confidence=Confidence.LOW.value,
                    title="Credential 해석 실패",
                    description=str(e),
                    evidence=[],
                    started_at=started_at,
                    ended_at=ended_at,
                    duration_ms=duration_ms,
                    tool_version=self.tool_version,
                )
        else:
            headers = orig_headers

        try:
            # 5) 요청 전송 (리다이렉트 전 Set-Cookie 캡처)
            resp = requests.request(
                method=req.method.upper(),
                url=url,
                headers=headers,
                params=req.query or None,
                json=req.body if req.method.upper() in ("POST", "PUT", "PATCH") else None,
                timeout=timeout_s,
                allow_redirects=False,
            )

            # 6) 중복 Set-Cookie 헤더 수집
            #    urllib3 으로부터 getlist 지원
            raw_headers = getattr(resp.raw, "headers", None)
            set_cookie_headers: List[str] = (
                raw_headers.getlist("Set-Cookie") if raw_headers else []
            )

            ended_at = utc_now_iso()
            duration_ms = int((time.time() - start_ts) * 1000)

            # 7) Set-Cookie 없으면 SKIPPED
            if not set_cookie_headers:
                return ToolResult(
                    tool_id=self.tool_id,
                    tool_name=self.tool_name,
                    status=ToolStatus.SKIPPED.value,
                    severity=Severity.INFO.value,
                    confidence=Confidence.LOW.value,
                    title="쿠키 없음",
                    description="응답에 Set-Cookie 헤더가 없어 검사할 수 없습니다.",
                    evidence=[],
                    started_at=started_at,
                    ended_at=ended_at,
                    duration_ms=duration_ms,
                    tool_version=self.tool_version,
                )

            # 8) 쿠키별 속성 분석
            vulnerable: List[Dict[str, Any]] = []
            all_cookies: List[Dict[str, Any]] = []
            for raw in set_cookie_headers:
                parsed = _parse_cookie_attributes(raw)
                all_cookies.append(parsed)

                issues: List[str] = []
                samesite_none = (
                    parsed["samesite"] is not None
                    and parsed["samesite"].lower() == "none"
                )
                if not parsed["secure"] and not samesite_none:
                    issues.append("Secure 속성 누락")
                if not parsed["httponly"]:
                    issues.append("HttpOnly 속성 누락")
                if parsed["samesite"] is None:
                    issues.append("SameSite 속성 누락")
                elif parsed["samesite"] == "":
                    issues.append("SameSite 값 없음")
                elif samesite_none and not parsed["secure"]:
                    issues.append(
                        "SameSite=None이고 Secure 속성 없음 (CSRF 위험)"
                    )

                if issues:
                    parsed["issues"] = issues
                    vulnerable.append(parsed)

            # 9) Evidence 생성
            ev = Evidence(
                request={
                    "method": req.method.upper(),
                    "url": url,
                    "headers": mask_sensitive(headers),
                    "body": sanitize_request_body(req.body),
                },
                response_status=resp.status_code,
                response_headers=dict(resp.headers),
                response_body_sample=sanitize_response_sample(resp.text),
                note="",
            )

            # 10) 결과 반환
            if vulnerable:
                summary = "; ".join(
                    f"{c['name']}: {', '.join(c['issues'])}"
                    for c in vulnerable
                )
                ev.note = (
                    f"{len(vulnerable)}/{len(all_cookies)}개 쿠키 보안 속성 누락: {summary}"
                )
                return ToolResult(
                    tool_id=self.tool_id,
                    tool_name=self.tool_name,
                    status=ToolStatus.VULNERABLE.value,
                    severity=Severity.MEDIUM.value,
                    confidence=Confidence.HIGH.value,
                    title="쿠키 보안 속성 누락",
                    description=(
                        f"{len(all_cookies)}개 쿠키 중 {len(vulnerable)}개에 "
                        "Secure/HttpOnly/SameSite 속성이 누락되었습니다."
                    ),
                    owasp=["A04 Cryptographic Failures"],
                    cwe=["CWE-319", "CWE-523"],
                    evidence=[ev],
                    recommendation=(
                        "모든 쿠키에 Secure, HttpOnly, SameSite 속성을 설정하세요. "
                        "HTTPS 전송 · XSS/CSRF 보호 강화 필요."
                    ),
                    started_at=started_at,
                    ended_at=ended_at,
                    duration_ms=duration_ms,
                    tool_version=self.tool_version,
                )

            ev.note = (
                f"{len(all_cookies)}개 쿠키 모두 Secure/HttpOnly/SameSite 속성이 올바르게 설정됨"
            )
            return ToolResult(
                tool_id=self.tool_id,
                tool_name=self.tool_name,
                status=ToolStatus.PASSED.value,
                severity=Severity.INFO.value,
                confidence=Confidence.HIGH.value,
                title="쿠키 보안 속성 적용됨",
                description="모든 쿠키에 올바른 보안 속성이 설정되어 있습니다.",
                owasp=["A04 Cryptographic Failures"],
                cwe=["CWE-319", "CWE-523"],
                evidence=[ev],
                recommendation=(
                    "현재 설정을 유지하고, 새로운 쿠키에도 동일한 보호 속성을 적용하세요."
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
                title="요청 타임아웃",
                description=str(e),
                evidence=[],
                errors=[build_tool_error(ErrorCode.TIMEOUT.value, str(e), retryable=True)],
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
                title="실행 오류",
                description=str(e),
                evidence=[],
                errors=[build_tool_error(ErrorCode.INTERNAL_ERROR.value, str(e), retryable=False)],
                started_at=started_at,
                ended_at=ended_at,
                duration_ms=0,
                tool_version=self.tool_version,
            )