from __future__ import annotations

# extra 옵션 키:
#   "sensitive_paths": list[str] — 점검할 민감 경로 목록
#                                  (기본값: DEFAULT_SENSITIVE_PATHS)

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

DEFAULT_SENSITIVE_PATHS = [
    "/.env",
    "/.git/config",
    "/.git/HEAD",
    "/backup",
    "/backup.zip",
    "/backup.sql",
    "/config.php",
    "/wp-config.php",
    "/.DS_Store",
    "/database.yml",
    "/config.yml",
    "/config.json",
    "/.htaccess",
    "/web.config",
    "/phpinfo.php",
    "/server-status",
]


class SensitivePathTool(BaseTool):
    """
    서버에 노출된 민감한 경로(설정 파일, 백업, 버전 관리 등)를 탐지하는 도구.
    .env, .git/config, backup.zip 등 주요 경로에 직접 요청을 보내며,
    HTTP 200 응답 시 HIGH, HTTP 403 응답 시 경로 존재 가능성으로 MEDIUM을 판정한다.
    """

    tool_id = "sensitive_path"
    tool_name = "Sensitive Path Detection"

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
        sensitive_paths = tool_input.options.extra.get(
            "sensitive_paths", list(DEFAULT_SENSITIVE_PATHS)
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

            for path in sensitive_paths[:max_req]:
                target_url = f"{base_url}{path}"

                response = requests.get(
                    url=target_url,
                    headers=request_headers,
                    timeout=timeout_sec,
                    verify=False,
                    allow_redirects=False,
                )

                if response.status_code == 200:
                    vulnerable_evidence.append(
                        Evidence(
                            request={
                                "method": "GET",
                                "url": target_url,
                                "headers": mask_sensitive(request_headers),
                            },
                            response_status=response.status_code,
                            response_headers=dict(response.headers),
                            response_body_sample=sanitize_response_sample(response.text),
                            note=f"민감 경로 '{path}' 직접 접근 가능 (HTTP 200)",
                        )
                    )
                elif response.status_code == 403:
                    vulnerable_evidence.append(
                        Evidence(
                            request={
                                "method": "GET",
                                "url": target_url,
                                "headers": mask_sensitive(request_headers),
                            },
                            response_status=response.status_code,
                            response_headers=dict(response.headers),
                            response_body_sample=sanitize_response_sample(response.text),
                            note=f"민감 경로 '{path}' 존재 확인 (HTTP 403 - 접근 차단됨)",
                        )
                    )

            ended_at = utc_now_iso()

            if vulnerable_evidence:
                has_accessible = any(e.response_status == 200 for e in vulnerable_evidence)
                severity = Severity.HIGH if has_accessible else Severity.MEDIUM
                confidence = Confidence.HIGH if has_accessible else Confidence.MEDIUM

                return ToolResult(
                    tool_id=self.tool_id,
                    tool_name=self.tool_name,
                    status=ToolStatus.VULNERABLE,
                    severity=severity,
                    confidence=confidence,
                    title="민감 경로 노출 발견",
                    description=f"{len(vulnerable_evidence)}개의 민감 경로가 탐지되었습니다.",
                    owasp=["A02:2025 Security Misconfiguration"],
                    cwe=["CWE-538"],
                    evidence=vulnerable_evidence,
                    recommendation=(
                        "민감한 파일과 디렉터리는 웹 루트 외부로 이동하거나 접근을 차단하세요. "
                        "웹 서버 설정에서 .env, .git 등 숨김 파일 및 백업 파일 접근을 금지하세요."
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
                title="민감 경로 미노출",
                description="점검한 민감 경로에서 외부 접근 가능한 경로가 발견되지 않았습니다.",
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
