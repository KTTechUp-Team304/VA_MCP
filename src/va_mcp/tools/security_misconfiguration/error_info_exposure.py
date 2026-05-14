from __future__ import annotations

# extra 옵션 키:
#   "error_payloads": list[str] — 오류 유발용 쿼리 파라미터 값 목록
#                                 (기본값: DEFAULT_ERROR_PAYLOADS)

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
    tool_id = "error_info_exposure"
    tool_name = "Error Information Exposure Testing"
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
        max_req = opts.max_requests if opts and opts.max_requests is not None else len(DEFAULT_ERROR_PAYLOADS)
        error_payloads: List[str] = extra.get("error_payloads", DEFAULT_ERROR_PAYLOADS)

        # 3) URL 안전 조합
        base = tool_input.target.base_url.rstrip("/")
        path = req.path.lstrip("/")
        url = f"{base}/{path}"

        # 4) headers 방어 및 auth_resolver 적용
        headers: Dict[str, Any] = req.headers.copy() if req.headers else {}
        auth_ctx: AuthContext | None = tool_input.auth[0] if tool_input.auth else None
        if auth_ctx:
            try:
                parse_credentials(auth_ctx)
                auth_headers = resolve_auth_headers(auth_ctx)
                headers = {**headers, **auth_headers}
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

        vulnerable_evidence: List[Evidence] = []
        has_body_exposure = False

        try:
            # 5) 에러 페이로드별 테스트
            for payload in error_payloads[:max_req]:
                params = {**(req.query or {}), "_test": payload}

                resp = requests.request(
                    method=req.method,
                    url=url,
                    headers=headers,
                    params=params,
                    json=req.body if req.method.upper() in ("POST", "PUT", "PATCH") and req.body else None,
                    timeout=timeout_s,
                    allow_redirects=False,
                )

                response_headers = dict(resp.headers)
                lower_keys = {k.lower(): k for k in response_headers}
                exposed_headers = {
                    lower_keys[k.lower()]: response_headers[lower_keys[k.lower()]]
                    for k in SENSITIVE_HEADER_KEYS
                    if k.lower() in lower_keys
                }

                body = resp.text or ""
                found_keywords = [
                    kw for kw in SENSITIVE_BODY_KEYWORDS
                    if kw.lower() in body.lower()
                ]
                if found_keywords:
                    has_body_exposure = True

                if exposed_headers or found_keywords:
                    note_parts: List[str] = []
                    if exposed_headers:
                        hdrs = ", ".join(f"{k}: {v}" for k, v in exposed_headers.items())
                        note_parts.append(f"노출된 헤더: {hdrs}")
                    if found_keywords:
                        note_parts.append(f"노출된 키워드: {', '.join(found_keywords)}")

                    vulnerable_evidence.append(
                        Evidence(
                            request={
                                "method": req.method,
                                "url": url,
                                "headers": mask_sensitive(headers),
                                "params": params,
                            },
                            response_status=resp.status_code,
                            response_headers=response_headers,
                            response_body_sample=sanitize_response_sample(body),
                            note=" | ".join(note_parts),
                        )
                    )
                    break

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

        ended_at = utc_now_iso()
        duration_ms = int((time.time() - start_ts) * 1000)

        # 6) 결과 반환
        if vulnerable_evidence:
            severity   = Severity.HIGH if has_body_exposure else Severity.MEDIUM
            confidence = Confidence.HIGH if has_body_exposure else Confidence.MEDIUM

            return ToolResult(
                tool_id=self.tool_id,
                tool_name=self.tool_name,
                status=ToolStatus.VULNERABLE.value,
                severity=severity.value,
                confidence=confidence.value,
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
                duration_ms=duration_ms,
                tool_version=self.tool_version,
            )

        return ToolResult(
            tool_id=self.tool_id,
            tool_name=self.tool_name,
            status=ToolStatus.PASSED.value,
            severity=Severity.INFO.value,
            confidence=Confidence.HIGH.value,
            title="오류 정보 미노출",
            description="오류 응답에서 내부 정보가 노출되지 않았습니다.",
            evidence=[],
            started_at=started_at,
            ended_at=ended_at,
            duration_ms=duration_ms,
            tool_version=self.tool_version,
        )