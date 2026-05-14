from __future__ import annotations

import requests
import time
from typing import Any, Dict, List

from va_mcp.core import (
    BaseTool,
    ToolInput,
    ToolResult,
    Evidence,
    ToolStatus,
    Severity,
    Confidence,
    ErrorCode,
    AuthContext,
)
from va_mcp.core.utils import (
    build_tool_error,
    mask_sensitive,
    sanitize_response_sample,
    sanitize_request_body,
    utc_now_iso,
)
from va_mcp.core.resolvers.auth_resolver import (
    parse_credentials,
    resolve_auth_headers,
    CredentialResolverError,
)


class RetryHandlingTool(BaseTool):
    """
    단기간에 수많은 요청을 보낼 때, 서버가 속도 제한(Rate Limit)을 걸어 방어하는지 확인하는 도구입니다.
    모든 응답이 200(성공)이라면 방어 조치가 없다고 판단, 취약 판정을 내립니다.
    """
    tool_id = "retry_handling"
    tool_name = "Retry Handling Testing"
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
                description="request가 제공되지 않아 점검을 건너뜁니다.",
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
        max_req = opts.max_requests if opts and opts.max_requests is not None else 1

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
            headers = {**orig_headers, **auth_headers}
        else:
            headers = orig_headers

        responses: List[requests.Response] = []

        try:
            # 5) 반복 요청
            for _ in range(max_req):
                res = requests.request(
                    method=method,
                    url=url,
                    headers=headers,
                    json=req.body if method in ("POST", "PUT", "PATCH") and req.body else None,
                    timeout=timeout_s,
                    allow_redirects=False,
                    verify=False,
                )
                responses.append(res)

            status_codes = [r.status_code for r in responses]
            is_vulnerable = 429 not in status_codes

            ended_at   = utc_now_iso()
            duration_ms = int((time.time() - start_ts) * 1000)

            if is_vulnerable:
                last_res = responses[-1]
                ev = Evidence(
                    request={
                        "method": method,
                        "url": url,
                        "headers": mask_sensitive(headers),
                        "body": sanitize_request_body(req.body),
                    },
                    response_status=last_res.status_code,
                    response_headers=dict(last_res.headers),
                    response_body_sample=sanitize_response_sample(last_res.text),
                    note=f"{max_req}회의 반복 요청에도 Rate Limit 차단(429) 미발생",
                )
                return ToolResult(
                    tool_id=self.tool_id,
                    tool_name=self.tool_name,
                    status=ToolStatus.VULNERABLE.value,
                    severity=Severity.HIGH.value,
                    confidence=Confidence.MEDIUM.value,
                    title="재시도 제한(Rate Limit) 미흡 발견",
                    description=(
                        f"단시간 내 {max_req}회의 반복 요청에도 "
                        "429(Too Many Requests) 차단이 발생하지 않습니다."
                    ),
                    owasp=["A10:2025 Mishandling of Exceptional Conditions"],
                    cwe=["CWE-307"],
                    evidence=[ev],
                    recommendation="주요 API 엔드포인트에 IP 기반 또는 계정 기반의 Rate Limiting을 적용하세요.",
                    started_at=started_at,
                    ended_at=ended_at,
                    duration_ms=duration_ms,
                    tool_version=self.tool_version,
                )

            # PASSED
            return ToolResult(
                tool_id=self.tool_id,
                tool_name=self.tool_name,
                status=ToolStatus.PASSED.value,
                severity=Severity.INFO.value,
                confidence=Confidence.HIGH.value,
                title="Rate Limit 작동 확인",
                description="과도한 요청에 대해 정상적으로 방어 메커니즘이 작동합니다.",
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
                description=str(e),
                evidence=[],
                errors=[build_tool_error(ErrorCode.INTERNAL_ERROR.value, str(e), retryable=False)],
                started_at=started_at,
                ended_at=ended_at,
                duration_ms=0,
                tool_version=self.tool_version,
            )