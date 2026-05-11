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


class ErrorCodeConsistencyTool(BaseTool):
    """
    어떤 종류의 에러(400, 404, 500 등)든 상관없이 항상 똑같은 형식으로 응답하는지 확인하는 도구입니다.
    응답의 형식(Content-Type이나 스키마 등)이 다르다면 취약 판정을 내립니다.
    """

    tool_id = "error_code_consistency"
    tool_name = "Error Code Consistency Testing"
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

        # 3) URL 및 headers 준비
        base = tool_input.target.base_url.rstrip("/")
        url1 = f"{base}/api/invalid-format-test"
        url2 = f"{base}/api/this-path-does-not-exist-12345"

        orig_headers = req.headers or {}

        # 4) auth_resolver 적용
        auth_ctx = tool_input.auth[0] if tool_input.auth else None
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

        try:
            # 5) 두 가지 에러 상황 요청
            res1 = requests.post(
                url=url1,
                headers=headers,
                data="invalid",
                timeout=timeout_s,
                allow_redirects=False,
                verify=False,
            )
            res2 = requests.get(
                url=url2,
                headers=headers,
                timeout=timeout_s,
                allow_redirects=False,
                verify=False,
            )

            ct1 = res1.headers.get("Content-Type", "").lower()
            ct2 = res2.headers.get("Content-Type", "").lower()

            is_vuln = (
                ("json" in ct1 and "html" in ct2)
                or ("html" in ct1 and "json" in ct2)
            )

            ended_at   = utc_now_iso()
            duration_ms = int((time.time() - start_ts) * 1000)

            if is_vuln:
                evidence: List[Evidence] = [
                    Evidence(
                        request={
                            "method": "POST",
                            "url": url1,
                            "headers": mask_sensitive(headers),
                        },
                        response_status=res1.status_code,
                        response_headers=dict(res1.headers),
                        response_body_sample=sanitize_response_sample(res1.text),
                        note="Type 1 Error Response",
                    ),
                    Evidence(
                        request={
                            "method": "GET",
                            "url": url2,
                            "headers": mask_sensitive(headers),
                        },
                        response_status=res2.status_code,
                        response_headers=dict(res2.headers),
                        response_body_sample=sanitize_response_sample(res2.text),
                        note="Type 2 Error Response",
                    ),
                ]
                return ToolResult(
                    tool_id=self.tool_id,
                    tool_name=self.tool_name,
                    status=ToolStatus.VULNERABLE.value,
                    severity=Severity.LOW.value,
                    confidence=Confidence.HIGH.value,
                    title="오류 응답 규격 불일치",
                    description="발생하는 에러 종류에 따라 응답 데이터의 Content-Type 형식이 다르게 반환됩니다.",
                    owasp=["A10:2025 Mishandling of Exceptional Conditions"],
                    cwe=["CWE-203"],
                    evidence=evidence,
                    recommendation=(
                        "웹 서버 에러 페이지(Nginx/Apache) 설정을 오버라이드하여 "
                        "API 규격과 동일한 JSON 포맷을 반환하도록 통일하세요."
                    ),
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
                title="오류 응답 일관성 유지됨",
                description="에러 상황에서도 일관된 Content-Type으로 응답합니다.",
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