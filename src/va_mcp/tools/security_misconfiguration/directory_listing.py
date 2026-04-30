from __future__ import annotations

# extra 옵션 키:
#   "check_paths": list[str] — 디렉터리 목록 노출 여부를 점검할 경로 목록
#                              (기본값: DEFAULT_DIRECTORY_PATHS)

import requests

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

DEFAULT_DIRECTORY_PATHS = [
    "/",
    "/static/",
    "/assets/",
    "/uploads/",
    "/files/",
    "/images/",
    "/backup/",
    "/public/",
    "/resources/",
    "/media/",
]

DIRECTORY_LISTING_KEYWORDS = [
    "Index of /",
    "Directory listing for",
    "[PARENTDIR]",
    "[DIR]",
    "<title>Index of",
    "Parent Directory",
    "Directory: /",
]


class DirectoryListingTool(BaseTool):
    """
    웹 서버에서 디렉터리 목록이 외부에 노출되는지 탐지하는 도구.
    주요 디렉터리 경로에 GET 요청을 보내 HTTP 200 응답 바디에서
    디렉터리 목록 전형 키워드를 탐지하며, 발견 시 HIGH로 판정한다.
    """

    tool_id = "directory_listing"
    tool_name = "Directory Listing Detection"

    def run(self, tool_input: ToolInput) -> ToolResult:
        started_at = utc_now_iso()

        if tool_input.request is None:
            ended_at = utc_now_iso()
            return ToolResult(
                tool_id=self.tool_id,
                tool_name=self.tool_name,
                status=ToolStatus.SKIPPED,
                severity=Severity.INFO,
                confidence=Confidence.LOW,
                title="요청 정보 없음",
                description="request가 제공되지 않아 점검을 건너뜁니다.",
                evidence=[],
                started_at=started_at,
                ended_at=ended_at,
            )

        timeout_sec = tool_input.options.timeout / 1000.0
        max_req = tool_input.options.max_requests
        check_paths = tool_input.options.extra.get(
            "check_paths", list(DEFAULT_DIRECTORY_PATHS)
        )

        base_url = tool_input.target.base_url
        request_headers = dict(tool_input.request.headers)

        if tool_input.auth:
            auth: AuthContext = tool_input.auth[0]
            if auth.auth_type == "bearer" and auth.token:
                request_headers["Authorization"] = f"Bearer {auth.token}"
            elif auth.auth_type == "cookie" and auth.cookie:
                request_headers["Cookie"] = auth.cookie
            elif auth.auth_type == "api_key" and auth.token:
                request_headers["X-API-Key"] = auth.token

        try:
            vulnerable_evidence: list[Evidence] = []

            for path in check_paths[:max_req]:
                target_url = f"{base_url}{path}"

                response = requests.get(
                    url=target_url,
                    headers=request_headers,
                    timeout=timeout_sec,
                    verify=False,
                    allow_redirects=False,
                )

                if response.status_code != 200:
                    continue

                body = response.text
                found_keywords = [
                    kw for kw in DIRECTORY_LISTING_KEYWORDS
                    if kw.lower() in body.lower()
                ]

                if found_keywords:
                    vulnerable_evidence.append(
                        Evidence(
                            request={
                                "method": "GET",
                                "url": target_url,
                                "headers": mask_sensitive(request_headers),
                            },
                            response_status=response.status_code,
                            response_headers=dict(response.headers),
                            response_body_sample=sanitize_response_sample(body),
                            note=(
                                f"경로 '{path}'에서 디렉터리 목록 노출 확인. "
                                f"탐지 키워드: {', '.join(found_keywords)}"
                            ),
                        )
                    )

            ended_at = utc_now_iso()

            if vulnerable_evidence:
                return ToolResult(
                    tool_id=self.tool_id,
                    tool_name=self.tool_name,
                    status=ToolStatus.VULNERABLE,
                    severity=Severity.HIGH,
                    confidence=Confidence.HIGH,
                    title="디렉터리 목록 노출 발견",
                    description=f"{len(vulnerable_evidence)}개의 경로에서 디렉터리 목록이 노출되었습니다.",
                    owasp=["A02:2025 Security Misconfiguration"],
                    cwe=["CWE-548"],
                    evidence=vulnerable_evidence,
                    recommendation=(
                        "웹 서버 설정에서 디렉터리 목록 기능을 비활성화하세요. "
                        "Apache는 Options -Indexes, Nginx는 autoindex off 설정을 적용하세요."
                    ),
                    started_at=started_at,
                    ended_at=ended_at,
                )

            return ToolResult(
                tool_id=self.tool_id,
                tool_name=self.tool_name,
                status=ToolStatus.PASSED,
                severity=Severity.INFO,
                confidence=Confidence.HIGH,
                title="디렉터리 목록 미노출",
                description="점검한 경로에서 디렉터리 목록 노출이 확인되지 않았습니다.",
                started_at=started_at,
                ended_at=ended_at,
            )

        except requests.exceptions.Timeout:
            ended_at = utc_now_iso()
            return ToolResult(
                tool_id=self.tool_id,
                tool_name=self.tool_name,
                status=ToolStatus.ERROR,
                severity=Severity.INFO,
                confidence=Confidence.LOW,
                title="요청 타임아웃",
                description="HTTP 요청이 제한 시간 내에 완료되지 않았습니다.",
                started_at=started_at,
                ended_at=ended_at,
                errors=[
                    build_tool_error(
                        error_code=ErrorCode.TIMEOUT,
                        error_message=f"요청이 {timeout_sec}초 안에 완료되지 않았습니다.",
                        retryable=True,
                    )
                ],
            )

        except requests.exceptions.ConnectionError as e:
            ended_at = utc_now_iso()
            return ToolResult(
                tool_id=self.tool_id,
                tool_name=self.tool_name,
                status=ToolStatus.ERROR,
                severity=Severity.INFO,
                confidence=Confidence.LOW,
                title="연결 오류",
                description="대상 서버에 연결할 수 없습니다.",
                started_at=started_at,
                ended_at=ended_at,
                errors=[
                    build_tool_error(
                        error_code=ErrorCode.HTTP_FAILURE,
                        error_message=str(e),
                        retryable=True,
                    )
                ],
            )

        except Exception as e:
            ended_at = utc_now_iso()
            return ToolResult(
                tool_id=self.tool_id,
                tool_name=self.tool_name,
                status=ToolStatus.ERROR,
                severity=Severity.INFO,
                confidence=Confidence.LOW,
                title="도구 실행 오류",
                description="예상치 못한 오류가 발생했습니다.",
                started_at=started_at,
                ended_at=ended_at,
                errors=[
                    build_tool_error(
                        error_code=ErrorCode.INTERNAL_ERROR,
                        error_message=str(e),
                        retryable=False,
                    )
                ],
            )
