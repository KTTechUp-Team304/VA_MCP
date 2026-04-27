"""
OS Command Injection Testing Tool

OWASP: A05:2025 - Injection
CWE:   CWE-78 (OS Command Injection)

extra 옵션:
    - payload_list (list[str]): 테스트할 명령어 인젝션 페이로드 목록
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


# 기본 OS Command Injection 페이로드
DEFAULT_PAYLOADS = [
    "; ls",
    "| ls",
    "& ls",
    "; cat /etc/passwd",
    "| cat /etc/passwd",
    "& cat /etc/passwd",
    "; whoami",
    "| whoami",
    "& whoami",
    "$(whoami)",
    "`whoami`",
    "; dir",
    "| dir",
    "& dir",
]

# 명령어 실행 성공을 나타내는 응답 시그니처 (소문자 비교)
CMD_SUCCESS_SIGNATURES = [
    "root:",                    # /etc/passwd 내용
    "daemon:",                  # /etc/passwd 내용
    "/bin/bash",                # /etc/passwd 내용
    "/bin/sh",                  # /etc/passwd 내용
    "uid=",                     # id 명령어 출력
    "gid=",                     # id 명령어 출력
    "total ",                   # ls -la 출력
    "drwx",                     # ls -la 출력
    "volume serial number",     # Windows dir 출력
    "directory of",             # Windows dir 출력
    "<dir>",                    # Windows dir 출력
]


class CmdInjectionTool(BaseTool):
    tool_id = "cmd_injection"
    tool_name = "OS Command Injection Testing"

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

            safe_mode = tool_input.options.safe_mode
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
                            test_query[param] = query.get(param, "") + payload
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
                                "query": {param: test_query[param]},
                            }
                        else:
                            test_body = dict(body)
                            original_value = str(body.get(param, ""))
                            test_body[param] = original_value + payload
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
                            sig for sig in CMD_SUCCESS_SIGNATURES
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
                                        f"명령어 실행 시그니처 감지: {detected[:3]}"
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
                    severity=Severity.CRITICAL,
                    confidence=Confidence.HIGH,
                    title="OS Command Injection 취약점 발견",
                    description=(
                        f"총 {len(evidences)}건의 명령어 인젝션 징후가 감지되었습니다. "
                        f"테스트 파라미터: {test_params}"
                    ),
                    owasp=["A05:2025 Injection"],
                    cwe=["CWE-78"],
                    evidence=evidences,
                    recommendation=(
                        "1. 사용자 입력을 OS 명령어에 직접 포함하지 마세요.\n"
                        "2. subprocess 사용 시 shell=False로 설정하세요.\n"
                        "3. 허용된 명령어/인자만 화이트리스트로 검증하세요.\n"
                        "4. 최소 권한 원칙을 적용하세요."
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
                title="OS Command Injection 취약점 미발견",
                description=(
                    f"테스트한 파라미터({test_params})에서 "
                    f"명령어 인젝션 징후가 감지되지 않았습니다. "
                    f"(총 {request_count}건 요청)"
                ),
                owasp=["A05:2025 Injection"],
                cwe=["CWE-78"],
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
                title="OS Command Injection 테스트 실행 오류",
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