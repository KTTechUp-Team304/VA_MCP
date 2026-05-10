"""
Rate Limit Check Tool

대상 엔드포인트에 동일 요청을 반복 전송하여
API Rate Limit(요청 제한) 존재 여부를 확인한다.

OWASP: A06 Insecure Design
CWE:   CWE-770 (Allocation of Resources Without Limits or Throttling)

extra 옵션:
    extra["repeat_count"]  : int  - 반복 요청 횟수 (기본값: 10)
    extra["interval_ms"]   : int  - 요청 간 대기 시간 밀리초 (기본값: 0)
"""

from __future__ import annotations

import requests
import time
from typing import Any, Dict, List

from urllib.parse import urljoin

from va_mcp.core.base import BaseTool
from va_mcp.core.schemas import ToolInput, ToolResult, Evidence
from va_mcp.core.constants import ToolStatus, Severity, Confidence, ErrorCode
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


class RateLimitCheckTool(BaseTool):
    """
    동일 요청을 반복 전송하여 429 응답 여부로 Rate Limit 존재를 판단합니다.

    - 429 응답이 오면: PASSED (Rate Limit 존재)
    - 모두 200이면: VULNERABLE (Rate Limit 미존재)
    """
    tool_id = "rate_limit_check"
    tool_name = "API Rate Limit Check"
    tool_version = "0.1.0"

    def run(self, tool_input: ToolInput) -> ToolResult:
        start_ts   = time.time()
        started_at = utc_now_iso()

        # 1) request 방어
        req = tool_input.request
        if not req:
            ended_at   = utc_now_iso()
            duration_ms = int((time.time() - start_ts) * 1000)
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
                duration_ms=duration_ms,
                tool_version=self.tool_version,
            )

        # 2) safe_mode 체크
        opts: Any = tool_input.options
        safe_mode = getattr(opts, "safe_mode", False)
        if safe_mode:
            ended_at   = utc_now_iso()
            duration_ms = int((time.time() - start_ts) * 1000)
            return ToolResult(
                tool_id=self.tool_id,
                tool_name=self.tool_name,
                status=ToolStatus.SKIPPED.value,
                severity=Severity.INFO.value,
                confidence=Confidence.LOW.value,
                title="Safe Mode 활성화",
                description="safe_mode=True 상태에서는 반복 요청을 전송하지 않습니다.",
                evidence=[],
                started_at=started_at,
                ended_at=ended_at,
                duration_ms=duration_ms,
                tool_version=self.tool_version,
            )

        # 3) options/extra 방어
        extra: Dict[str, Any] = opts.extra if opts and opts.extra else {}
        repeat_count = extra.get("repeat_count", 10)
        interval_ms  = extra.get("interval_ms", 0)
        timeout_s    = (opts.timeout / 1000.0) if opts and opts.timeout else 5
        max_req      = opts.max_requests if opts and opts.max_requests is not None else repeat_count

        # repeat_count 유효성
        if not isinstance(repeat_count, int) or repeat_count < 1:
            ended_at   = utc_now_iso()
            duration_ms = int((time.time() - start_ts) * 1000)
            return ToolResult(
                tool_id=self.tool_id,
                tool_name=self.tool_name,
                status=ToolStatus.ERROR.value,
                severity=Severity.INFO.value,
                confidence=Confidence.LOW.value,
                title="입력값 오류",
                description="repeat_count는 1 이상의 정수여야 합니다.",
                evidence=[],
                errors=[build_tool_error(
                    ErrorCode.INVALID_INPUT.value,
                    f"repeat_count 값이 유효하지 않습니다: {repeat_count!r}",
                    retryable=False,
                )],
                started_at=started_at,
                ended_at=ended_at,
                duration_ms=duration_ms,
                tool_version=self.tool_version,
            )

        # 실제 반복 횟수 결정
        actual_count = min(repeat_count, max_req)
        if actual_count < 1:
            ended_at   = utc_now_iso()
            duration_ms = int((time.time() - start_ts) * 1000)
            return ToolResult(
                tool_id=self.tool_id,
                tool_name=self.tool_name,
                status=ToolStatus.ERROR.value,
                severity=Severity.INFO.value,
                confidence=Confidence.LOW.value,
                title="입력값 오류",
                description="max_requests 또는 repeat_count가 1 미만입니다.",
                evidence=[],
                errors=[build_tool_error(
                    ErrorCode.INVALID_INPUT.value,
                    f"actual_count가 0 이하입니다: repeat_count={repeat_count}, max_requests={max_req}",
                    retryable=False,
                )],
                started_at=started_at,
                ended_at=ended_at,
                duration_ms=duration_ms,
                tool_version=self.tool_version,
            )

        # 4) URL 안전 조합
        base = tool_input.target.base_url.rstrip("/")
        url  = f"{base}/{req.path.lstrip('/')}"

        # 5) headers 방어 및 auth_resolver 적용
        orig_headers = req.headers or {}
        auth_ctx = tool_input.auth[0] if tool_input.auth else None
        if auth_ctx:
            try:
                parse_credentials(auth_ctx)
                auth_headers = resolve_auth_headers(auth_ctx)
                headers = {**orig_headers, **auth_headers}
            except CredentialResolverError as e:
                ended_at   = utc_now_iso()
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

        # 6) 반복 요청
        status_codes: List[int] = []
        rate_limited = False
        rate_limit_evidence: Evidence | None = None

        try:
            for i in range(actual_count):
                resp = requests.request(
                    method=req.method,
                    url=url,
                    headers=headers,
                    params=req.query or None,
                    json=req.body if req.method.upper() in ("POST","PUT","PATCH") else None,
                    timeout=timeout_s,
                    allow_redirects=False,
                )
                status_codes.append(resp.status_code)

                if resp.status_code == 429:
                    rate_limited = True
                    rate_limit_evidence = Evidence(
                        request={
                            "method": req.method,
                            "url": url,
                            "headers": mask_sensitive(headers),
                            "body": sanitize_request_body(req.body),
                        },
                        response_status=resp.status_code,
                        response_headers=dict(resp.headers),
                        response_body_sample=sanitize_response_sample(resp.text),
                        note=f"{i+1}번째 요청에서 429 응답 수신",
                    )
                    break

                if interval_ms > 0:
                    time.sleep(interval_ms/1000.0)

            ended_at   = utc_now_iso()
            duration_ms = int((time.time() - start_ts) * 1000)

            # 7) 결과 판정
            if rate_limited and rate_limit_evidence:
                return ToolResult(
                    tool_id=self.tool_id,
                    tool_name=self.tool_name,
                    status=ToolStatus.PASSED.value,
                    severity=Severity.INFO.value,
                    confidence=Confidence.HIGH.value,
                    title="Rate Limit 적용됨",
                    description=(
                        f"{len(status_codes)}번째 요청에서 429 Too Many Requests를 수신했습니다."
                    ),
                    owasp=["A06 Insecure Design"],
                    cwe=["CWE-770"],
                    evidence=[rate_limit_evidence],
                    recommendation="현재 Rate Limit이 적용되어 있습니다.",
                    started_at=started_at,
                    ended_at=ended_at,
                    duration_ms=duration_ms,
                    tool_version=self.tool_version,
                )

            # Rate Limit 미존재 → 취약
            last_resp = resp
            last_evidence = Evidence(
                request={
                    "method": req.method,
                    "url": url,
                    "headers": mask_sensitive(headers),
                    "body": sanitize_request_body(req.body),
                },
                response_status=last_resp.status_code,
                response_headers=dict(last_resp.headers),
                response_body_sample=sanitize_response_sample(last_resp.text),
                note=(
                    f"{actual_count}회 요청 후에도 429 응답 없음 "
                    f"(응답 코드 분포: {status_codes})"
                ),
            )
            return ToolResult(
                tool_id=self.tool_id,
                tool_name=self.tool_name,
                status=ToolStatus.VULNERABLE.value,
                severity=Severity.MEDIUM.value,
                confidence=Confidence.MEDIUM.value,
                title="Rate Limit 미적용",
                description=(
                    f"{actual_count}회 반복 요청에도 429가 발생하지 않았습니다."
                ),
                owasp=["A06 Insecure Design"],
                cwe=["CWE-770"],
                evidence=[last_evidence],
                recommendation="API 엔드포인트에 Rate Limiting을 적용하세요.",
                started_at=started_at,
                ended_at=ended_at,
                duration_ms=duration_ms,
                tool_version=self.tool_version,
            )

        except requests.Timeout as exc:
            ended_at = utc_now_iso()
            return ToolResult(
                tool_id=self.tool_id,
                tool_name=self.tool_name,
                status=ToolStatus.ERROR.value,
                severity=Severity.INFO.value,
                confidence=Confidence.LOW.value,
                title="요청 시간 초과",
                description=str(exc),
                evidence=[],
                errors=[build_tool_error(
                    ErrorCode.TIMEOUT.value, str(exc), retryable=True
                )],
                started_at=started_at,
                ended_at=ended_at,
                duration_ms=0,
                tool_version=self.tool_version,
            )
        except requests.RequestException as exc:
            ended_at = utc_now_iso()
            return ToolResult(
                tool_id=self.tool_id,
                tool_name=self.tool_name,
                status=ToolStatus.ERROR.value,
                severity=Severity.INFO.value,
                confidence=Confidence.LOW.value,
                title="HTTP 요청 실패",
                description=str(exc),
                evidence=[],
                errors=[build_tool_error(
                    ErrorCode.HTTP_FAILURE.value, str(exc), retryable=True
                )],
                started_at=started_at,
                ended_at=ended_at,
                duration_ms=0,
                tool_version=self.tool_version,
            )
        except Exception as exc:
            ended_at = utc_now_iso()
            return ToolResult(
                tool_id=self.tool_id,
                tool_name=self.tool_name,
                status=ToolStatus.ERROR.value,
                severity=Severity.INFO.value,
                confidence=Confidence.LOW.value,
                title="Rate Limit 테스트 실행 오류",
                description=str(exc),
                evidence=[],
                errors=[build_tool_error(
                    ErrorCode.INTERNAL_ERROR.value, str(exc), retryable=False
                )],
                started_at=started_at,
                ended_at=ended_at,
                duration_ms=0,
                tool_version=self.tool_version,
            )