"""
HTTP Header Injection (CRLF Injection) Testing Tool

OWASP: A05:2025 - Injection
CWE:   CWE-113 (HTTP Response Splitting)

extra 옵션:
    - payload_list (list[str]): 테스트할 헤더 인젝션 페이로드 목록
      기본값: 기본 CRLF 페이로드 세트 사용
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

# 기본 CRLF / Header Injection 페이로드
DEFAULT_PAYLOADS = [
    "%0d%0aInjected-Header:true",
    "%0d%0aSet-Cookie:hacked=1",
    "\r\nInjected-Header:true",
    "\r\nSet-Cookie:hacked=1",
    "%0d%0a%0d%0a<script>alert(1)</script>",
    "\r\n\r\n<script>alert(1)</script>",
    "%0aInjected-Header:true",
    "%0dInjected-Header:true",
    "값%0d%0aX-Injected:true",
]

# 응답 헤더에서 인젝션 성공을 감지하는 키 (소문자 비교)
INJECTED_HEADER_SIGNATURES = [
    "injected-header",
    "x-injected",
]

# 응답 본문에서 인젝션 성공을 감지하는 시그니처
INJECTED_BODY_SIGNATURES = [
    "set-cookie:hacked",
    "<script>alert(1)</script>",
    "injected-header:true",
]


class HeaderInjectionTool(BaseTool):
    tool_id = "header_injection"
    tool_name = "HTTP Header Injection (CRLF) Testing"
    tool_version = "0.1.0"

    def run(self, tool_input: ToolInput) -> ToolResult:
        start_ts   = time.time()
        started_at = utc_now_iso()

        try:
            # ── 입력 검증 ──────────────────────────────────
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
                    description="ToolInput.request가 None입니다.",
                    evidence=[],
                    started_at=started_at,
                    ended_at=ended_at,
                    duration_ms=duration_ms,
                    tool_version=self.tool_version,
                )

            # ── 옵션 추출 ──────────────────────────────────
            opts: Any = tool_input.options
            extra: Dict[str, Any] = opts.extra if opts and opts.extra else {}
            timeout_s = (opts.timeout / 1000.0) if opts and opts.timeout else 5
            max_req   = opts.max_requests if opts and opts.max_requests is not None else len(DEFAULT_PAYLOADS)
            payload_list: List[str] = extra.get("payload_list", DEFAULT_PAYLOADS)

            # ── 테스트 대상 파라미터 결정 ─────────────────────
            method = req.method.upper()
            path   = req.path
            query  = req.query or {}
            body   = req.body or {}
            orig_headers = req.headers or {}

            if method == "GET":
                test_params = list(query.keys())
            else:
                test_params = list(body.keys())

            if not test_params:
                ended_at   = utc_now_iso()
                duration_ms = int((time.time() - start_ts) * 1000)
                return ToolResult(
                    tool_id=self.tool_id,
                    tool_name=self.tool_name,
                    status=ToolStatus.SKIPPED.value,
                    severity=Severity.INFO.value,
                    confidence=Confidence.LOW.value,
                    title="테스트할 파라미터 없음",
                    description="요청에서 테스트할 파라미터를 찾지 못했습니다.",
                    evidence=[],
                    started_at=started_at,
                    ended_at=ended_at,
                    duration_ms=duration_ms,
                    tool_version=self.tool_version,
                )

            # ── 타겟 URL 구성 ─────────────────────────────
            base_url = tool_input.target.base_url.rstrip("/")
            full_url = urljoin(f"{base_url}/", path.lstrip("/"))

            # ── 인증 헤더 주입(resolver) ──────────────────────
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

            # ── 페이로드 테스트 루프 ──────────────────────────
            evidences: List[Evidence] = []
            request_count = 0

            for param in test_params:
                for payload in payload_list:
                    if request_count >= max_req:
                        break

                    if method == "GET":
                        test_q = dict(query)
                        test_q[param] = payload
                        resp = requests.get(
                            full_url,
                            params=test_q,
                            headers=headers,
                            timeout=timeout_s,
                            allow_redirects=False,
                        )
                        request_info = {
                            "method": "GET",
                            "path": path,
                            "headers": mask_sensitive(headers),
                            "query": {param: test_q[param]},
                        }
                    else:
                        test_b = dict(body)
                        test_b[param] = payload
                        resp = requests.request(
                            method,
                            full_url,
                            headers=headers,
                            json=test_b,
                            timeout=timeout_s,
                            allow_redirects=False,
                        )
                        request_info = {
                            "method": method,
                            "path": path,
                            "headers": mask_sensitive(headers),
                            "body": sanitize_request_body(test_b),
                        }

                    request_count += 1

                    # ── 응답 헤더에서 인젝션 감지 ────────────
                    hdr_lower = {k.lower(): v for k, v in resp.headers.items()}
                    hdr_detect = [
                        sig for sig in INJECTED_HEADER_SIGNATURES
                        if sig in hdr_lower
                    ]

                    # ── 응답 본문에서 인젝션 감지 ────────────
                    body_lower = resp.text.lower()
                    body_detect = [
                        sig for sig in INJECTED_BODY_SIGNATURES
                        if sig in body_lower
                    ]

                    detected = hdr_detect + body_detect
                    if detected:
                        evidences.append(
                            Evidence(
                                request=request_info,
                                response_status=resp.status_code,
                                response_headers=dict(resp.headers),
                                response_body_sample=sanitize_response_sample(resp.text),
                                note=(
                                    f"파라미터 '{param}'에 페이로드 '{payload}' 삽입 시 "
                                    f"인젝션 시그니처 감지: {detected[:3]}"
                                ),
                            )
                        )

                if request_count >= max_req:
                    break

            # ── 결과 판정 ──────────────────────────────────
            ended_at   = utc_now_iso()
            duration_ms = int((time.time() - start_ts) * 1000)

            if evidences:
                return ToolResult(
                    tool_id=self.tool_id,
                    tool_name=self.tool_name,
                    status=ToolStatus.VULNERABLE.value,
                    severity=Severity.MEDIUM.value,
                    confidence=Confidence.HIGH.value,
                    title="HTTP Header Injection (CRLF) 취약점 발견",
                    description=(
                        f"총 {len(evidences)}건의 헤더 인젝션 징후가 감지되었습니다. "
                        f"테스트 파라미터: {test_params}"
                    ),
                    owasp=["A05:2025 Injection"],
                    cwe=["CWE-113"],
                    evidence=evidences,
                    recommendation=(
                        "1. 사용자 입력을 헤더에 직접 포함하지 마세요.\n"
                        "2. CRLF 문자를 필터링하세요.\n"
                        "3. 프레임워크 API를 통해 헤더 처리하세요.\n"
                        "4. URL 인코딩된 CRLF(%0d%0a)도 필터링하세요."
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
                confidence=Confidence.MEDIUM.value,
                title="HTTP Header Injection 취약점 미발견",
                description=(
                    f"테스트한 파라미터({test_params})에서 헤더 인젝션 징후 미감지 "
                    f"(총 {request_count}회 요청)"
                ),
                evidence=[],
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
                title="요청 타임아웃",
                description=str(exc),
                evidence=[],
                errors=[build_tool_error(ErrorCode.TIMEOUT.value, str(exc), retryable=True)],
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
                errors=[build_tool_error(ErrorCode.HTTP_FAILURE.value, str(exc), retryable=True)],
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
                title="Header Injection 테스트 오류",
                description=str(exc),
                evidence=[],
                errors=[build_tool_error(ErrorCode.INTERNAL_ERROR.value, str(exc), retryable=False)],
                started_at=started_at,
                ended_at=ended_at,
                duration_ms=0,
                tool_version=self.tool_version,
            )