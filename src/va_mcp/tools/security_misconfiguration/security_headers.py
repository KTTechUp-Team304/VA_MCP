from __future__ import annotations

# extra 옵션 키:
#   "custom_headers": list[str] — 기본 목록 외 추가로 점검할 헤더 이름 (기본값: [])

import requests
import time
from typing import Any, Dict, List

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
from va_mcp.core.resolvers.auth_resolver import (
    parse_credentials,
    resolve_auth_headers,
    CredentialResolverError,
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
    tool_version = "0.1.0"

    def run(self, tool_input: ToolInput) -> ToolResult:
        start_ts = time.time()
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
                description="request가 제공되지 않아 점검을 건너뜁니다.",
                evidence=[],
                started_at=started_at,
                ended_at=ended_at,
                duration_ms=0,
                tool_version=self.tool_version,
            )

        # 2) options/extra 안전 처리
        opts: Any = tool_input.options
        extra: Dict[str, Any] = opts.extra if opts and opts.extra else {}
        timeout_s = (opts.timeout / 1000.0) if opts and opts.timeout else 5
        max_req = opts.max_requests if opts and opts.max_requests is not None else 1
        custom = extra.get("custom_headers", [])
        headers_to_check = REQUIRED_SECURITY_HEADERS + list(custom)

        # 3) URL 안전 조합
        base = tool_input.target.base_url.rstrip("/")
        url = f"{base}/{req.path.lstrip('/')}"
        method = req.method.upper()

        # 4) headers 방어 및 auth_resolver 적용
        orig_headers = req.headers or {}
        auth_ctx: AuthContext | None = tool_input.auth[0] if tool_input.auth else None
        if auth_ctx:
            try:
                parse_credentials(auth_ctx)
                auth_headers = resolve_auth_headers(auth_ctx)
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
                    started_at=started_at,
                    ended_at=ended_at,
                    duration_ms=int((time.time() - start_ts) * 1000),
                    tool_version=self.tool_version,
                )
        else:
            auth_headers = {}

        headers = {**orig_headers, **auth_headers}

        try:
            # 5) 실제 요청
            resp = requests.request(
                method=method,
                url=url,
                headers=headers,
                params=req.query or None,
                timeout=timeout_s,
            )

            response_headers = dict(resp.headers)
            lower_keys = {k.lower() for k in response_headers}

            # 6) 누락 헤더 판단
            missing = [
                h for h in headers_to_check
                if h.lower() not in lower_keys
            ]

            ended_at = utc_now_iso()
            duration_ms = int((time.time() - start_ts) * 1000)

            if missing:
                ev = Evidence(
                    request={
                        "method": method,
                        "url": url,
                        "headers": mask_sensitive(headers),
                    },
                    response_status=resp.status_code,
                    response_headers=response_headers,
                    response_body_sample=sanitize_response_sample(resp.text),
                    note=(
                        f"누락된 보안 헤더 ({len(missing)}개): "
                        f"{', '.join(missing)}"
                    ),
                )
                return ToolResult(
                    tool_id=self.tool_id,
                    tool_name=self.tool_name,
                    status=ToolStatus.VULNERABLE.value,
                    severity=Severity.MEDIUM.value,
                    confidence=Confidence.HIGH.value,
                    title="보안 헤더 누락 발견",
                    description=(
                        f"응답에서 {len(missing)}개의 보안 헤더가 누락되었습니다: "
                        f"{', '.join(missing)}"
                    ),
                    owasp=["A02:2025 Security Misconfiguration"],
                    cwe=["CWE-16"],
                    evidence=[ev],
                    recommendation=(
                        "누락된 보안 헤더를 서버 응답에 추가하세요. "
                        "Content-Security-Policy와 Strict-Transport-Security는 필수입니다."
                    ),
                    started_at=started_at,
                    ended_at=ended_at,
                    duration_ms=duration_ms,
                    tool_version=self.tool_version,
                )

            # 7) 정상
            return ToolResult(
                tool_id=self.tool_id,
                tool_name=self.tool_name,
                status=ToolStatus.PASSED.value,
                severity=Severity.INFO.value,
                confidence=Confidence.HIGH.value,
                title="보안 헤더 정상",
                description="모든 필수 보안 헤더가 응답에 포함되어 있습니다.",
                evidence=[],
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
                title="도구 실행 오류",
                description="예상치 못한 오류가 발생했습니다.",
                evidence=[],
                errors=[build_tool_error(ErrorCode.INTERNAL_ERROR.value, str(e), retryable=False)],
                started_at=started_at,
                ended_at=ended_at,
                duration_ms=0,
                tool_version=self.tool_version,
            )