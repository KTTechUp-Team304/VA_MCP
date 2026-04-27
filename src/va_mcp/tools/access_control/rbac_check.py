"""
RBAC (Role-Based Access Control) 테스트 도구.

auth 리스트 순서로 권한 계층을 판단한다.
  auth[0]  = 가장 낮은 권한 (공격자 역할)
  auth[-1] = 가장 높은 권한 (기준 역할)

extra 옵션:
  없음 (현재 버전에서는 extra 미사용)

SKIPPED 조건:
  - request 없음
  - auth 2개 미만
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


class RbacCheckTool(BaseTool):
    tool_id = "rbac_check"
    tool_name = "RBAC Check"

    def run(self, tool_input: ToolInput) -> ToolResult:
        started_at = utc_now_iso()

        if not tool_input.request:
            return self._skipped(started_at, "request가 제공되지 않았습니다.")
        if len(tool_input.auth) < 2:
            return self._skipped(started_at, "auth가 2개 이상 필요합니다 (auth[0]=저권한, auth[-1]=고권한).")

        req = tool_input.request
        base_url = tool_input.target.base_url.rstrip("/")
        url = base_url + req.path
        timeout_s = tool_input.options.timeout / 1000

        high_auth = tool_input.auth[-1]
        low_auth = tool_input.auth[0]

        try:
            high_resp = self._send(url, req.method, req.query, req.body, high_auth, timeout_s)

            if high_resp.status_code not in (200, 201, 204):
                return self._skipped(
                    started_at,
                    f"고권한({high_auth.role}) 요청도 실패({high_resp.status_code}). 엔드포인트가 올바른지 확인하세요.",
                )

            low_resp = self._send(url, req.method, req.query, req.body, low_auth, timeout_s)

        except requests.Timeout:
            return self._error(started_at, ErrorCode.TIMEOUT, "HTTP 요청 타임아웃이 발생했습니다.", retryable=True)
        except requests.RequestException as exc:
            return self._error(started_at, ErrorCode.HTTP_FAILURE, str(exc))

        ended_at = utc_now_iso()

        if low_resp.status_code in (200, 201, 204):
            bodies_match = low_resp.text.strip() == high_resp.text.strip()
            confidence = Confidence.HIGH if bodies_match else Confidence.MEDIUM

            evidence = Evidence(
                request={
                    "method": req.method,
                    "url": url,
                    "headers": mask_sensitive(dict(low_resp.request.headers)),
                    "role": low_auth.role,
                },
                response_status=low_resp.status_code,
                response_headers=dict(low_resp.headers),
                response_body_sample=sanitize_response_sample(low_resp.text),
                note=(
                    f"저권한({low_auth.role})으로 고권한({high_auth.role}) 전용 리소스 접근 성공. "
                    f"응답 body {'일치' if bodies_match else '불일치'}."
                ),
            )

            return ToolResult(
                tool_id=self.tool_id,
                tool_name=self.tool_name,
                status=ToolStatus.VULNERABLE,
                severity=Severity.HIGH,
                confidence=confidence,
                title="역할 기반 접근 제어 우회 가능",
                description=(
                    f"저권한 역할({low_auth.role})로 고권한 역할({high_auth.role}) 전용 엔드포인트에 "
                    f"접근이 허용되었습니다. HTTP {low_resp.status_code} 응답 수신."
                ),
                owasp=["A01 Broken Access Control"],
                cwe=["CWE-285"],
                evidence=[evidence],
                recommendation=(
                    "모든 엔드포인트에 역할 기반 접근 제어 미들웨어를 적용하고, "
                    "서버 측에서 요청자의 권한을 반드시 검증하세요."
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
            title="역할 기반 접근 제어 정상",
            description=(
                f"저권한 역할({low_auth.role})의 접근이 {low_resp.status_code}으로 차단되었습니다."
            ),
            owasp=["A01 Broken Access Control"],
            cwe=["CWE-285"],
            started_at=started_at,
            ended_at=ended_at,
        )

    # ------------------------------------------------------------------
    # helpers
    # ------------------------------------------------------------------

    def _send(
        self,
        url: str,
        method: str,
        query: dict,
        body: dict | None,
        auth: AuthContext,
        timeout_s: float,
    ) -> requests.Response:
        headers = self._auth_headers(auth)
        return requests.request(
            method=method,
            url=url,
            headers=headers,
            params=query or None,
            json=body,
            timeout=timeout_s,
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
