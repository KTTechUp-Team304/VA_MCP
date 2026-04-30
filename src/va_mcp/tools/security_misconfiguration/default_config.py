from __future__ import annotations

# extra 옵션 키:
#   "login_path"       : str             — 로그인 엔드포인트 경로 (기본값: DEFAULT_LOGIN_PATH)
#   "credential_pairs" : list[list[str]] — 테스트할 [username, password] 쌍 목록
#                                          (기본값: DEFAULT_CREDENTIAL_PAIRS)
#   "admin_paths"      : list[str]       — 관리 페이지 경로 목록 (기본값: DEFAULT_ADMIN_PATHS)

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
    sanitize_request_body,
    sanitize_response_sample,
    utc_now_iso,
)

DEFAULT_LOGIN_PATH = "/login"

DEFAULT_CREDENTIAL_PAIRS = [
    ["admin", "admin"],
    ["admin", "password"],
    ["admin", "123456"],
    ["root", "root"],
    ["root", "password"],
    ["administrator", "administrator"],
    ["test", "test"],
    ["guest", "guest"],
]

DEFAULT_ADMIN_PATHS = [
    "/admin",
    "/admin/login",
    "/administrator",
    "/phpmyadmin",
    "/wp-admin",
    "/manager",
    "/console",
    "/dashboard",
    "/management",
    "/control",
]

_CREDENTIAL_SUCCESS_STATUS = {200, 302}
_ADMIN_ACCESSIBLE_STATUS = {200}
_ADMIN_PROTECTED_STATUS = {401, 403}


class DefaultConfigTool(BaseTool):
    """
    기본 자격증명과 관리 페이지 노출로 기본 설정 취약점을 탐지하는 도구.
    기본 계정(admin/admin 등)으로 로그인을 시도하고, 관리 페이지 접근 가능 여부를 점검하며,
    자격증명 성공 시 CRITICAL, 관리 페이지 노출 시 HIGH/MEDIUM으로 판정한다.
    """

    tool_id = "default_config"
    tool_name = "Default Configuration Vulnerability Detection"

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
        login_path = tool_input.options.extra.get("login_path", DEFAULT_LOGIN_PATH)
        credential_pairs = tool_input.options.extra.get(
            "credential_pairs", [list(p) for p in DEFAULT_CREDENTIAL_PAIRS]
        )
        admin_paths = tool_input.options.extra.get(
            "admin_paths", list(DEFAULT_ADMIN_PATHS)
        )

        base_url = tool_input.target.base_url
        login_url = f"{base_url}{login_path}"
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
            credential_evidence: list[Evidence] = []
            admin_accessible_evidence: list[Evidence] = []
            admin_protected_evidence: list[Evidence] = []
            total_requests = 0

            # Phase 1: 기본 자격증명 테스트
            post_headers = {**request_headers, "Content-Type": "application/json"}
            for pair in credential_pairs:
                if total_requests >= max_req:
                    break
                username, password = pair[0], pair[1]

                response = requests.post(
                    url=login_url,
                    headers=post_headers,
                    json={"username": username, "password": password},
                    timeout=timeout_sec,
                    verify=False,
                    allow_redirects=False,
                )
                total_requests += 1

                if response.status_code in _CREDENTIAL_SUCCESS_STATUS:
                    credential_evidence.append(
                        Evidence(
                            request={
                                "method": "POST",
                                "url": login_url,
                                "headers": mask_sensitive(post_headers),
                                "body": sanitize_request_body({"username": username, "password": "***"}),
                            },
                            response_status=response.status_code,
                            response_headers=dict(response.headers),
                            response_body_sample=sanitize_response_sample(response.text),
                            note=(
                                f"기본 자격증명 '{username}/***'으로 "
                                f"로그인 성공 가능성 확인 (HTTP {response.status_code})"
                            ),
                        )
                    )
                    break

            # Phase 2: 관리 페이지 노출 테스트
            for path in admin_paths:
                if total_requests >= max_req:
                    break
                target_url = f"{base_url}{path}"

                response = requests.get(
                    url=target_url,
                    headers=request_headers,
                    timeout=timeout_sec,
                    verify=False,
                    allow_redirects=False,
                )
                total_requests += 1

                if response.status_code in _ADMIN_ACCESSIBLE_STATUS:
                    admin_accessible_evidence.append(
                        Evidence(
                            request={
                                "method": "GET",
                                "url": target_url,
                                "headers": mask_sensitive(request_headers),
                            },
                            response_status=response.status_code,
                            response_headers=dict(response.headers),
                            response_body_sample=sanitize_response_sample(response.text),
                            note=f"관리 페이지 '{path}'가 인증 없이 접근 가능합니다.",
                        )
                    )
                elif response.status_code in _ADMIN_PROTECTED_STATUS:
                    admin_protected_evidence.append(
                        Evidence(
                            request={
                                "method": "GET",
                                "url": target_url,
                                "headers": mask_sensitive(request_headers),
                            },
                            response_status=response.status_code,
                            response_headers=dict(response.headers),
                            response_body_sample=sanitize_response_sample(response.text),
                            note=(
                                f"관리 페이지 '{path}'가 존재하나 "
                                f"인증으로 보호됩니다 (HTTP {response.status_code})."
                            ),
                        )
                    )

            ended_at = utc_now_iso()

            all_evidence = (
                credential_evidence + admin_accessible_evidence + admin_protected_evidence
            )

            if all_evidence:
                if credential_evidence:
                    severity = Severity.CRITICAL
                    confidence = Confidence.HIGH
                    title = "기본 자격증명으로 로그인 가능"
                    description = "기본 계정/비밀번호로 로그인에 성공하였습니다."
                elif admin_accessible_evidence:
                    severity = Severity.HIGH
                    confidence = Confidence.HIGH
                    title = "관리 페이지 무단 접근 가능"
                    description = (
                        f"{len(admin_accessible_evidence)}개의 관리 페이지가 "
                        "인증 없이 접근 가능합니다."
                    )
                else:
                    severity = Severity.MEDIUM
                    confidence = Confidence.MEDIUM
                    title = "관리 페이지 존재 확인"
                    description = (
                        f"{len(admin_protected_evidence)}개의 관리 페이지가 "
                        "존재하나 인증으로 보호됩니다."
                    )

                return ToolResult(
                    tool_id=self.tool_id,
                    tool_name=self.tool_name,
                    status=ToolStatus.VULNERABLE,
                    severity=severity,
                    confidence=confidence,
                    title=title,
                    description=description,
                    owasp=["A02:2025 Security Misconfiguration"],
                    cwe=["CWE-1188"],
                    evidence=all_evidence,
                    recommendation=(
                        "기본 자격증명을 즉시 변경하고, 관리 페이지에 강력한 인증을 적용하세요. "
                        "불필요한 관리 인터페이스는 비활성화하거나 IP 제한을 적용하세요."
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
                title="기본 설정 취약점 미발견",
                description="기본 자격증명 및 관리 페이지 노출이 확인되지 않았습니다.",
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
