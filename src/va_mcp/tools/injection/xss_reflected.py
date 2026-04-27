"""
Reflected XSS (Cross-Site Scripting) Testing Tool

OWASP: A05:2025 - Injection
CWE:   CWE-79 (Cross-site Scripting)

extra 옵션:
    - payload_list (list[str]): 테스트할 XSS 페이로드 목록
      기본값: 기본 페이로드 세트 사용
"""

from __future__ import annotations

import requests as http_client
from urllib.parse import urljoin

from va_mcp.core.base import BaseTool
from va_mcp.core.constants import Confidence, ErrorCode, Severity, ToolStatus
from va_mcp.core.schemas import Evidence, ToolInput, ToolResult
from va_mcp.core.utils import (
    build_tool_error,
    mask_sensitive,
    sanitize_request_body,
    sanitize_response_sample,
    utc_now_iso,
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

    def run(self, tool_input: ToolInput) -> ToolResult:
        started_at = utc_now_iso()

        try:
            # ── 입력 검증 ──────────────────────────────────
            if tool_input.request is None:
                ended_at = utc_now_iso()
                return ToolResult(
                    tool_id=self.tool_id,
                    tool_name=self.tool_name,
                    status=ToolStatus.SKIPPED,
                    severity=Severity.INFO,
                    confidence=Confidence.LOW,
                    title="요청 정보 없음",
                    description="ToolInput.request가 None입니다.",
                    evidence=[],
                    started_at=started_at,
                    ended_at=ended_at,
                )

            # ── 옵션 추출 ──────────────────────────────────
            extra = tool_input.options.extra
            payload_list = extra.get("payload_list", DEFAULT_PAYLOADS)

            max_requests = tool_input.options.max_requests
            timeout_sec = tool_input.options.timeout / 1000

            # ── 테스트 대상 파라미터 결정 ─────────────────────
            method = tool_input.request.method.upper()
            path = tool_input.request.path
            headers = dict(tool_input.request.headers)
            query = dict(tool_input.request.query)
            body = dict(tool_input.request.body) if tool_input.request.body else {}

            if method == "GET":
                test_params = list(query.keys())
            else:
                test_params = list(body.keys())

            if not test_params:
                ended_at = utc_now_iso()
                return ToolResult(
                    tool_id=self.tool_id,
                    tool_name=self.tool_name,
                    status=ToolStatus.SKIPPED,
                    severity=Severity.INFO,
                    confidence=Confidence.LOW,
                    title="테스트할 파라미터 없음",
                    description="요청에서 테스트할 파라미터를 찾지 못했습니다.",
                    evidence=[],
                    started_at=started_at,
                    ended_at=ended_at,
                )

            # ── 타겟 URL 구성 ─────────────────────────────
            base_url = tool_input.target.base_url.rstrip("/")
            full_url = urljoin(base_url + "/", path.lstrip("/"))

            # ── 페이로드 테스트 루프 ──────────────────────────
            evidences: list[Evidence] = []
            request_count = 0

            for param in test_params:
                for payload in payload_list:
                    if request_count >= max_requests:
                        break

                    try:
                        if method == "GET":
                            test_query = dict(query)
                            test_query[param] = payload
                            resp = http_client.get(
                                full_url,
                                params=test_query,
                                headers=headers,
                                timeout=timeout_sec,
                                allow_redirects=False,
                            )
                            request_info = {
                                "method": "GET",
                                "path": path,
                                "headers": mask_sensitive(headers),
                                "query": {param: payload},
                            }
                        else:
                            test_body = dict(body)
                            test_body[param] = payload
                            resp = http_client.request(
                                method,
                                full_url,
                                headers=headers,
                                json=test_body,
                                timeout=timeout_sec,
                                allow_redirects=False,
                            )
                            request_info = {
                                "method": method,
                                "path": path,
                                "headers": mask_sensitive(headers),
                                "body": sanitize_request_body(test_body),
                            }

                        request_count += 1

                        # ── 반사 여부 확인: 페이로드가 응답에 그대로 포함되는지 ──
                        if payload in resp.text:
                            # Content-Type이 HTML인 경우 더 위험
                            content_type = resp.headers.get("Content-Type", "").lower()
                            is_html = "text/html" in content_type

                            evidences.append(
                                Evidence(
                                    request=request_info,
                                    response_status=resp.status_code,
                                    response_headers=dict(resp.headers),
                                    response_body_sample=sanitize_response_sample(resp.text),
                                    note=(
                                        f"파라미터 '{param}'에 페이로드 '{payload}' 삽입 시 "
                                        f"응답에 그대로 반사됨"
                                        f"{' (Content-Type: text/html)' if is_html else ''}"
                                    ),
                                )
                            )

                    except http_client.RequestException:
                        request_count += 1
                        continue

                if request_count >= max_requests:
                    break

            # ── 결과 판정 ──────────────────────────────────
            if evidences:
                ended_at = utc_now_iso()
                return ToolResult(
                    tool_id=self.tool_id,
                    tool_name=self.tool_name,
                    status=ToolStatus.VULNERABLE,
                    severity=Severity.HIGH,
                    confidence=Confidence.MEDIUM,
                    title="Reflected XSS 취약점 발견",
                    description=(
                        f"총 {len(evidences)}건의 반사형 XSS 징후가 감지되었습니다. "
                        f"테스트 파라미터: {test_params}"
                    ),
                    owasp=["A05:2025 Injection"],
                    cwe=["CWE-79"],
                    evidence=evidences,
                    recommendation=(
                        "1. 모든 사용자 입력을 출력 시 HTML 이스케이프 처리하세요.\n"
                        "2. Content-Security-Policy(CSP) 헤더를 설정하세요.\n"
                        "3. 프레임워크의 자동 이스케이프 기능을 활성화하세요.\n"
                        "4. 입력값에 대한 화이트리스트 검증을 적용하세요.\n"
                        "5. HttpOnly 쿠키 플래그를 설정하여 쿠키 탈취를 방지하세요."
                    ),
                    started_at=started_at,
                    ended_at=ended_at,
                )

            ended_at = utc_now_iso()
            return ToolResult(
                tool_id=self.tool_id,
                tool_name=self.tool_name,
                status=ToolStatus.PASSED,
                severity=Severity.INFO,
                confidence=Confidence.MEDIUM,
                title="Reflected XSS 취약점 미발견",
                description=(
                    f"테스트한 파라미터({test_params})에서 "
                    f"반사형 XSS 징후가 감지되지 않았습니다. "
                    f"(총 {request_count}건 요청)"
                ),
                owasp=["A05:2025 Injection"],
                cwe=["CWE-79"],
                started_at=started_at,
                ended_at=ended_at,
            )

        except Exception as exc:
            ended_at = utc_now_iso()
            return ToolResult(
                tool_id=self.tool_id,
                tool_name=self.tool_name,
                status=ToolStatus.ERROR,
                severity=Severity.INFO,
                confidence=Confidence.LOW,
                title="Reflected XSS 테스트 실행 오류",
                description=f"테스트 실행 중 예외가 발생했습니다: {str(exc)}",
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