"""
강제 브라우징 (Forced Browsing) 테스트 도구.

숨겨진 관리자 경로, 설정 파일, 내부 엔드포인트 등이 외부에 노출되어 있는지 확인한다.

auth 구성:
  auth[0] = 테스트에 사용할 인증 컨텍스트 (없으면 비인증 요청)

extra 옵션:
  extra["paths"] = ["/custom/path", "/internal/api"]
    → 기본 경로 목록에 추가로 테스트할 경로

판단 기준:
  200       → VULNERABLE (접근 성공, 차단 안 됨)
  403/401   → PASSED, severity=INFO (경로 존재, 서버가 정상 차단)
  302       → PASSED, severity=LOW  (리다이렉트, 확인 필요)
  404       → PASSED, severity=INFO (경로 없음)

SKIPPED 조건:
  - 없음 (target만 있으면 실행 가능)
"""

from __future__ import annotations

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

DEFAULT_PATHS = [
    "/admin",
    "/administrator",
    "/api/admin",
    "/dashboard",
    "/backup",
    "/config",
    "/.env",
    "/swagger",
    "/api-docs",
    "/actuator",
    "/actuator/env",
    "/health",
    "/.git/config",
]


class ForcedBrowsingTool(BaseTool):
    tool_id = "forced_browsing"
    tool_name = "Forced Browsing"

    def run(self, tool_input: ToolInput) -> ToolResult:
        started_at = utc_now_iso()

        base_url = tool_input.target.base_url.rstrip("/")
        timeout_s = tool_input.options.timeout / 1000
        max_requests = tool_input.options.max_requests

        extra_paths: list[str] = tool_input.options.extra.get("paths", [])
        all_paths = DEFAULT_PATHS + extra_paths

        auth = tool_input.auth[0] if tool_input.auth else None

        vulnerable_evidences: list[Evidence] = []
        request_count = 0

        try:
            for path in all_paths:
                if request_count >= max_requests:
                    break

                url = base_url + path
                resp = self._send(url, auth, timeout_s)
                request_count += 1

                if resp.status_code == 200:
                    evidence = Evidence(
                        request={
                            "method": "GET",
                            "url": url,
                            "headers": mask_sensitive(dict(resp.request.headers)),
                        },
                        response_status=resp.status_code,
                        response_headers=dict(resp.headers),
                        response_body_sample=sanitize_response_sample(resp.text),
                        note=f"숨겨진 경로에 인증 없이 접근 성공: {path}",
                    )
                    vulnerable_evidences.append(evidence)

        except requests.Timeout:
            return self._error(started_at, ErrorCode.TIMEOUT, "HTTP 요청 타임아웃이 발생했습니다.", retryable=True)
        except requests.RequestException as exc:
            return self._error(started_at, ErrorCode.HTTP_FAILURE, str(exc))

        ended_at = utc_now_iso()

        if vulnerable_evidences:
            exposed_paths = [e.note.split(": ")[-1] for e in vulnerable_evidences]
            return ToolResult(
                tool_id=self.tool_id,
                tool_name=self.tool_name,
                status=ToolStatus.VULNERABLE,
                severity=Severity.HIGH,
                confidence=Confidence.HIGH,
                title="숨겨진 경로 노출 확인 (강제 브라우징)",
                description=(
                    f"인증 없이 접근 가능한 숨겨진 경로가 발견되었습니다. "
                    f"노출 경로: {', '.join(exposed_paths)}"
                ),
                owasp=["A01 Broken Access Control"],
                cwe=["CWE-425"],
                evidence=vulnerable_evidences,
                recommendation=(
                    "민감한 경로에 인증 및 권한 검증을 적용하세요. "
                    "불필요한 관리 인터페이스와 설정 파일은 외부에서 접근 불가능하도록 제한하세요."
                ),
                started_at=started_at,
                ended_at=ended_at,
            )

        return ToolResult(
            tool_id=self.tool_id,
            tool_name=self.tool_name,
            status=ToolStatus.PASSED,
            severity=Severity.INFO,
            confidence=Confidence.MEDIUM,
            title="강제 브라우징 취약 경로 미발견",
            description=(
                f"테스트한 {request_count}개 경로에서 무단 접근 가능한 경로가 발견되지 않았습니다."
            ),
            owasp=["A01 Broken Access Control"],
            cwe=["CWE-425"],
            started_at=started_at,
            ended_at=ended_at,
        )

    # ------------------------------------------------------------------
    # helpers
    # ------------------------------------------------------------------

    def _send(
        self,
        url: str,
        auth: AuthContext | None,
        timeout_s: float,
    ) -> requests.Response:
        headers = self._auth_headers(auth) if auth else {}
        return requests.get(
            url=url,
            headers=headers,
            timeout=timeout_s,
            allow_redirects=False,
        )

    def _auth_headers(self, auth: AuthContext) -> dict[str, str]:
        headers: dict[str, str] = {}
        if auth.auth_type == "bearer" and auth.token:
            headers["Authorization"] = f"Bearer {auth.token}"
        elif auth.auth_type == "api_key" and auth.token:
            headers["X-API-Key"] = auth.token
        elif auth.auth_type == "cookie" and auth.cookie:
            headers["Cookie"] = auth.cookie
        return headers

    def _skipped(self, started_at: str, reason: str) -> ToolResult:
        return ToolResult(
            tool_id=self.tool_id,
            tool_name=self.tool_name,
            status=ToolStatus.SKIPPED,
            severity=Severity.INFO,
            confidence=Confidence.LOW,
            title="테스트 건너뜀",
            description=reason,
            started_at=started_at,
            ended_at=utc_now_iso(),
        )

    def _error(
        self,
        started_at: str,
        error_code: ErrorCode,
        message: str,
        retryable: bool = False,
    ) -> ToolResult:
        return ToolResult(
            tool_id=self.tool_id,
            tool_name=self.tool_name,
            status=ToolStatus.ERROR,
            severity=Severity.INFO,
            confidence=Confidence.LOW,
            title="실행 오류",
            description=message,
            started_at=started_at,
            ended_at=utc_now_iso(),
            errors=[build_tool_error(error_code, message, retryable=retryable)],
        )
