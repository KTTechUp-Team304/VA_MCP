"""
Reflected XSS (Cross-Site Scripting) Testing Tool

OWASP: A05:2025 - Injection
CWE:   CWE-79 (Cross-site Scripting)

extra 옵션:
    - payload_list (list[str]): 테스트할 XSS 페이로드 목록
      기본값: 기본 페이로드 세트 사용
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

# 기본 Reflected XSS 페이로드
DEFAULT_PAYLOADS = [
    '<script>alert(1)</script>',
    '"><script>alert(1)</script>',
    "'><script>alert(1)</script>",
    '<img src=x onerror=alert(1)>',
    '"><img src=x onerror=alert(1)>',
    '<svg onload=alert(1)>',
    '"><svg onload=alert(1)>',
    "javascript:alert(1)",
    '<body onload=alert(1)>',
    '<iframe src="javascript:alert(1)">',
]


class XssReflectedTool(BaseTool):
    tool_id = "xss_reflected"
    tool_name = "Reflected XSS Testing"
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
                description="ToolInput.request가 None입니다.",
                evidence=[],
                started_at=started_at,
                ended_at=ended_at,
                duration_ms=duration_ms,
                tool_version=self.tool_version,
            )

        # 2) options/extra 방어
        opts: Any = tool_input.options
        extra: Dict[str, Any] = opts.extra if opts and opts.extra else {}
        timeout_s = (opts.timeout / 1000.0) if opts and opts.timeout else 5
        max_req   = opts.max_requests if opts and opts.max_requests is not None else len(DEFAULT_PAYLOADS)
        payload_list: List[str] = extra.get("payload_list", DEFAULT_PAYLOADS)

        # 3) 테스트 대상 파라미터 결정
        method       = req.method.upper()
        path         = req.path
        query        = req.query or {}
        body         = req.body or {}
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

        # 4) 타겟 URL 구성
        base_url = tool_input.target.base_url.rstrip("/")
        full_url = urljoin(f"{base_url}/", path.lstrip("/"))

        # 5) auth_resolver로 인증 헤더 주입
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

        evidences: List[Evidence] = []
        request_count = 0

        try:
            # 6) 페이로드 테스트 루프
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
                            "query": {param: payload},
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

                    # ── 반사 여부 확인
                    if payload in (resp.text or ""):
                        content_type = resp.headers.get("Content-Type", "").lower()
                        is_html = "text/html" in content_type
                        note = (
                            f"파라미터 '{param}'에 페이로드 '{payload}' 삽입 시 응답에 반사됨"
                            + (" (text/html)" if is_html else "")
                        )
                        evidences.append(
                            Evidence(
                                request=request_info,
                                response_status=resp.status_code,
                                response_headers=dict(resp.headers),
                                response_body_sample=sanitize_response_sample(resp.text),
                                note=note,
                            )
                        )

                if request_count >= max_req:
                    break

            # 7) 결과 판정
            ended_at   = utc_now_iso()
            duration_ms = int((time.time() - start_ts) * 1000)

            if evidences:
                return ToolResult(
                    tool_id=self.tool_id,
                    tool_name=self.tool_name,
                    status=ToolStatus.VULNERABLE.value,
                    severity=Severity.HIGH.value,
                    confidence=Confidence.MEDIUM.value,
                    title="Reflected XSS 취약점 발견",
                    description=(
                        f"총 {len(evidences)}건 반사형 XSS 징후 감지: {test_params}"
                    ),
                    owasp=["A05:2025 Injection"],
                    cwe=["CWE-79"],
                    evidence=evidences,
                    recommendation=(
                        "1. 모든 사용자 입력을 HTML 이스케이프 처리하세요.\n"
                        "2. CSP를 설정하세요.\n"
                        "3. 자동 이스케이프 기능을 활성화하세요.\n"
                        "4. 입력값 화이트리스트 검증을 적용하세요."
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
                confidence=Confidence.MEDIUM.value,
                title="Reflected XSS 미발견",
                description=(
                    f"파라미터({test_params})에서 징후 미감지 (총 {request_count}회 요청)"
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
                title="Reflected XSS 타임아웃",
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
                title="XSS 테스트 실행 오류",
                description=str(exc),
                evidence=[],
                errors=[build_tool_error(ErrorCode.INTERNAL_ERROR.value, str(exc), retryable=False)],
                started_at=started_at,
                ended_at=ended_at,
                duration_ms=0,
                tool_version=self.tool_version,
            )