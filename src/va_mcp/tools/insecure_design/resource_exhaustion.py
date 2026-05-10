"""
Resource Exhaustion Check Tool

비정상적으로 큰 입력값을 전송하여
서버가 요청 크기를 제한하고 있는지 확인한다.

OWASP: A06 Insecure Design
CWE:   CWE-400 (Uncontrolled Resource Consumption)

extra 옵션:
    extra["payload_size"]   : int  - 페이로드 문자열 크기 (기본값: 100000)
    extra["test_field"]     : str  - 큰 값을 넣을 필드명 (기본값: "data")
"""

from __future__ import annotations

import requests
import time
from typing import Any, Dict

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


class ResourceExhaustionTool(BaseTool):
    """
    비정상적으로 큰 페이로드를 전송하여 서버의 요청 크기 제한 여부를 확인합니다.

    - 413 응답이 오면: PASSED (크기 제한 존재)
    - 200 응답이면: VULNERABLE (크기 제한 미존재)
    - 500 또는 타임아웃이면: VULNERABLE (서버 과부하 가능성)
    """
    tool_id = "resource_exhaustion"
    tool_name = "Resource Exhaustion Check"
    tool_version = "0.1.0"

    def run(self, tool_input: ToolInput) -> ToolResult:
        start_ts   = time.time()
        started_at = utc_now_iso()

        # 1) request 방어
        req = tool_input.request
        if not req:
            ended_at    = utc_now_iso()
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

        method = req.method.upper()
        # 2) 메서드 방어
        if method not in ("POST", "PUT", "PATCH"):
            ended_at    = utc_now_iso()
            duration_ms = int((time.time() - start_ts) * 1000)
            return ToolResult(
                tool_id=self.tool_id,
                tool_name=self.tool_name,
                status=ToolStatus.SKIPPED.value,
                severity=Severity.INFO.value,
                confidence=Confidence.LOW.value,
                title="검사 대상 아님",
                description="Resource Exhaustion 검사는 POST/PUT/PATCH 메서드 전용입니다.",
                evidence=[],
                started_at=started_at,
                ended_at=ended_at,
                duration_ms=duration_ms,
                tool_version=self.tool_version,
            )

        # 3) safe_mode 방어
        opts: Any = tool_input.options
        safe_mode = getattr(opts, "safe_mode", False)
        if safe_mode:
            ended_at    = utc_now_iso()
            duration_ms = int((time.time() - start_ts) * 1000)
            return ToolResult(
                tool_id=self.tool_id,
                tool_name=self.tool_name,
                status=ToolStatus.SKIPPED.value,
                severity=Severity.INFO.value,
                confidence=Confidence.LOW.value,
                title="Safe Mode 활성화",
                description="safe_mode=True 상태에서는 대형 페이로드를 전송하지 않습니다.",
                evidence=[],
                started_at=started_at,
                ended_at=ended_at,
                duration_ms=duration_ms,
                tool_version=self.tool_version,
            )

        # 4) options/extra 방어
        extra: Dict[str, Any] = opts.extra if opts and opts.extra else {}
        payload_size = extra.get("payload_size", 100000)
        test_field   = extra.get("test_field", "data")
        timeout_s    = (opts.timeout / 1000.0) if opts and opts.timeout else 5

        # payload_size 검증
        if not isinstance(payload_size, int) or payload_size < 1:
            ended_at    = utc_now_iso()
            duration_ms = int((time.time() - start_ts) * 1000)
            return ToolResult(
                tool_id=self.tool_id,
                tool_name=self.tool_name,
                status=ToolStatus.ERROR.value,
                severity=Severity.INFO.value,
                confidence=Confidence.LOW.value,
                title="입력값 오류",
                description="payload_size는 1 이상의 정수여야 합니다.",
                evidence=[],
                errors=[build_tool_error(
                    ErrorCode.INVALID_INPUT.value,
                    f"payload_size 값이 유효하지 않습니다: {payload_size!r}",
                    retryable=False,
                )],
                started_at=started_at,
                ended_at=ended_at,
                duration_ms=duration_ms,
                tool_version=self.tool_version,
            )

        # test_field 검증
        if not isinstance(test_field, str) or not test_field.strip():
            ended_at    = utc_now_iso()
            duration_ms = int((time.time() - start_ts) * 1000)
            return ToolResult(
                tool_id=self.tool_id,
                tool_name=self.tool_name,
                status=ToolStatus.ERROR.value,
                severity=Severity.INFO.value,
                confidence=Confidence.LOW.value,
                title="입력값 오류",
                description="test_field는 비어 있지 않은 문자열이어야 합니다.",
                evidence=[],
                errors=[build_tool_error(
                    ErrorCode.INVALID_INPUT.value,
                    f"test_field 값이 유효하지 않습니다: {test_field!r}",
                    retryable=False,
                )],
                started_at=started_at,
                ended_at=ended_at,
                duration_ms=duration_ms,
                tool_version=self.tool_version,
            )

        # 5) URL 안전 조합
        base = tool_input.target.base_url.rstrip("/")
        path = req.path.lstrip("/")
        url  = f"{base}/{path}"

        # 6) headers 방어
        orig_headers = req.headers.copy() if req.headers else {}

        # 7) auth_resolver 적용
        auth_ctx = tool_input.auth[0] if tool_input.auth else None
        if auth_ctx:
            try:
                parse_credentials(auth_ctx)
                auth_headers = resolve_auth_headers(auth_ctx)
                headers = {**orig_headers, **auth_headers}
            except CredentialResolverError as e:
                ended_at    = utc_now_iso()
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

        # 8) original body
        orig_body = req.body or {}

        try:
            # 9) 대형 페이로드 전송
            large_body = {**orig_body, test_field: "A" * payload_size}
            resp = requests.request(
                method=req.method.upper(),
                url=url,
                headers=headers,
                json=large_body,
                timeout=timeout_s,
                allow_redirects=False,
            )

            ended_at    = utc_now_iso()
            duration_ms = int((time.time() - start_ts) * 1000)

            # 10) 413 응답 시 PASSED
            if resp.status_code == 413:
                ev = Evidence(
                    request={
                        "method": req.method.upper(),
                        "url": url,
                        "headers": mask_sensitive(headers),
                        "body": sanitize_request_body({test_field: "[A]" * payload_size}),
                    },
                    response_status=resp.status_code,
                    response_headers=dict(resp.headers),
                    response_body_sample=sanitize_response_sample(resp.text),
                    note="413 Payload Too Large 응답 수신. 크기 제한 존재.",
                )
                return ToolResult(
                    tool_id=self.tool_id,
                    tool_name=self.tool_name,
                    status=ToolStatus.PASSED.value,
                    severity=Severity.INFO.value,
                    confidence=Confidence.HIGH.value,
                    title="요청 크기 제한 적용됨",
                    description=(
                        f"{payload_size}자 페이로드 전송 시 413 응답을 수신하였습니다."
                    ),
                    owasp=["A06 Insecure Design"],
                    cwe=["CWE-400"],
                    evidence=[ev],
                    recommendation="현재 요청 크기 제한이 적용되어 있습니다.",
                    started_at=started_at,
                    ended_at=ended_at,
                    duration_ms=duration_ms,
                    tool_version=self.tool_version,
                )

            # 11) 서버 오류(>=500) 시 VULNERABLE
            if resp.status_code >= 500:
                ev = Evidence(
                    request={
                        "method": req.method.upper(),
                        "url": url,
                        "headers": mask_sensitive(headers),
                        "body": sanitize_request_body({test_field: "[A]" * payload_size}),
                    },
                    response_status=resp.status_code,
                    response_headers=dict(resp.headers),
                    response_body_sample=sanitize_response_sample(resp.text),
                    note=f"{resp.status_code} 서버 오류 발생 — 리소스 과부하 가능성",
                )
                return ToolResult(
                    tool_id=self.tool_id,
                    tool_name=self.tool_name,
                    status=ToolStatus.VULNERABLE.value,
                    severity=Severity.HIGH.value,
                    confidence=Confidence.MEDIUM.value,
                    title="서버 과부하 가능성",
                    description=(
                        f"{payload_size}자 페이로드 전송 시 {resp.status_code} 오류가 발생했습니다."
                    ),
                    owasp=["A06 Insecure Design"],
                    cwe=["CWE-400"],
                    evidence=[ev],
                    recommendation="서버에 요청 크기 제한을 적용하세요.",
                    started_at=started_at,
                    ended_at=ended_at,
                    duration_ms=duration_ms,
                    tool_version=self.tool_version,
                )

            # 12) 200 응답 시 VULNERABLE
            ev = Evidence(
                request={
                    "method": req.method.upper(),
                    "url": url,
                    "headers": mask_sensitive(headers),
                    "body": sanitize_request_body({test_field: "[A]" * payload_size}),
                },
                response_status=resp.status_code,
                response_headers=dict(resp.headers),
                response_body_sample=sanitize_response_sample(resp.text),
                note="200 OK로 처리됨 — 요청 크기 제한이 없음",
            )
            return ToolResult(
                tool_id=self.tool_id,
                tool_name=self.tool_name,
                status=ToolStatus.VULNERABLE.value,
                severity=Severity.MEDIUM.value,
                confidence=Confidence.MEDIUM.value,
                title="요청 크기 제한 미적용",
                description=(
                    f"{payload_size}자 페이로드가 {resp.status_code}로 정상 처리되었습니다."
                ),
                owasp=["A06 Insecure Design"],
                cwe=["CWE-400"],
                evidence=[ev],
                recommendation="서버에 요청 크기 제한을 적용하세요.",
                started_at=started_at,
                ended_at=ended_at,
                duration_ms=duration_ms,
                tool_version=self.tool_version,
            )

        except requests.Timeout as exc:
            # 타임아웃도 취약으로 간주
            ended_at    = utc_now_iso()
            duration_ms = int((time.time() - start_ts) * 1000)
            ev = Evidence(
                request={
                    "method": req.method.upper(),
                    "url": url,
                    "headers": mask_sensitive(headers),
                    "body": sanitize_request_body({test_field: "[A]" * payload_size}),
                },
                response_status=0,
                response_headers={},
                response_body_sample="",
                note=f"타임아웃 발생 — 리소스 소진 가능성 ({exc})",
            )
            return ToolResult(
                tool_id=self.tool_id,
                tool_name=self.tool_name,
                status=ToolStatus.VULNERABLE.value,
                severity=Severity.HIGH.value,
                confidence=Confidence.MEDIUM.value,
                title="타임아웃에 의한 리소스 소진 가능성",
                description="대형 페이로드 전송 시 서버가 응답하지 못했습니다.",
                owasp=["A06 Insecure Design"],
                cwe=["CWE-400"],
                evidence=[ev],
                recommendation="서버에 요청 크기 및 처리 시간 제한을 적용하세요.",
                started_at=started_at,
                ended_at=ended_at,
                duration_ms=duration_ms,
                tool_version=self.tool_version,
            )
        except requests.RequestException as exc:
            ended_at    = utc_now_iso()
            duration_ms = int((time.time() - start_ts) * 1000)
            return ToolResult(
                tool_id=self.tool_id,
                tool_name=self.tool_name,
                status=ToolStatus.ERROR.value,
                severity=Severity.INFO.value,
                confidence=Confidence.LOW.value,
                title="HTTP 요청 실패",
                description="대상 서버로의 HTTP 요청이 실패했습니다.",
                evidence=[],
                errors=[build_tool_error(
                    ErrorCode.HTTP_FAILURE.value, str(exc), retryable=True
                )],
                started_at=started_at,
                ended_at=ended_at,
                duration_ms=duration_ms,
                tool_version=self.tool_version,
            )
        except Exception as exc:
            ended_at    = utc_now_iso()
            duration_ms = int((time.time() - start_ts) * 1000)
            return ToolResult(
                tool_id=self.tool_id,
                tool_name=self.tool_name,
                status=ToolStatus.ERROR.value,
                severity=Severity.INFO.value,
                confidence=Confidence.LOW.value,
                title="실행 오류",
                description="예상치 못한 오류가 발생했습니다.",
                evidence=[],
                errors=[build_tool_error(
                    ErrorCode.INTERNAL_ERROR.value, str(exc), retryable=False
                )],
                started_at=started_at,
                ended_at=ended_at,
                duration_ms=duration_ms,
                tool_version=self.tool_version,
            )