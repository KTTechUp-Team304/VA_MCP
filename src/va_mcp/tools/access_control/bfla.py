"""
BFLA (Broken Function Level Authorization) 테스트 도구.

낮은 권한 사용자가 관리자 전용 기능(엔드포인트)에 접근 가능한지 확인한다.
RBAC가 수평적 접근 제어라면, BFLA는 수직적(기능 레벨) 접근 제어를 테스트한다.

auth 구성:
  auth[0] = 낮은 권한 사용자 (공격자 역할)

request 구성:
  request.path = 관리자 전용 기능 경로 (예: /api/admin/users)

extra 옵션:
  extra["additional_paths"] = ["/api/admin/reports", "/api/admin/settings"]
    → 추가로 테스트할 관리자 경로 목록 (max_requests 제한 적용)

SKIPPED 조건:
  - request 없음
  - auth 없음
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


class BflaTool(BaseTool):
    tool_id = "bfla"
    tool_name = "BFLA Testing"

    def run(self, tool_input: ToolInput) -> ToolResult:
        started_at = utc_now_iso()

        if not tool_input.request:
            return self._skipped(started_at, "request가 제공되지 않았습니다.")
        if not tool_input.auth:
            return self._skipped(started_at, "auth가 최소 1개 필요합니다.")

        req = tool_input.request
        base_url = tool_input.target.base_url.rstrip("/")
        timeout_s = tool_input.options.timeout / 1000
        max_requests = tool_input.options.max_requests
        attacker = tool_input.auth[0]

        additional_paths: list[str] = tool_input.options.extra.get("additional_paths", [])
        all_paths = [req.path] + additional_paths

        vulnerable_evidences: list[Evidence] = []
        request_count = 0

        try:
            for path in all_paths:
                if request_count >= max_requests:
                    break

                url = base_url + path
                resp = self._send(url, req.method, req.query, req.body, attacker, timeout_s)
                request_count += 1

                if resp.status_code in (200, 201, 204):
                    evidence = Evidence(
                        request={
                            "method": req.method,
                            "url": url,
                            "headers": mask_sensitive(dict(resp.request.headers)),
                            "role": attacker.role,
                        },
                        response_status=resp.status_code,
                        response_headers=dict(resp.headers),
                        response_body_sample=sanitize_response_sample(resp.text),
                        note=f"저권한({attacker.role})으로 관리 기능 접근 성공: {path}",
                    )
                    vulnerable_evidences.append(evidence)

        except requests.Timeout:
            return self._error(started_at, ErrorCode.TIMEOUT, "HTTP 요청 타임아웃이 발생했습니다.", retryable=True)
        except requests.RequestException as exc:
            return self._error(started_at, ErrorCode.HTTP_FAILURE, str(exc))

        ended_at = utc_now_iso()

        if vulnerable_evidences:
            vuln_paths = [e.note.split(": ")[-1] for e in vulnerable_evidences]
            return ToolResult(
                tool_id=self.tool_id,
                tool_name=self.tool_name,
                status=ToolStatus.VULNERABLE,
                severity=Severity.HIGH,
                confidence=Confidence.HIGH,
                title="기능 레벨 접근 제어 우회 가능 (BFLA)",
                description=(
                    f"저권한 역할({attacker.role})이 관리자 전용 기능에 접근하는 데 성공했습니다. "
                    f"취약 경로: {', '.join(vuln_paths)}"
                ),
                owasp=["A01 Broken Access Control"],
                cwe=["CWE-285"],
                evidence=vulnerable_evidences,
                recommendation=(
                    "관리자 기능 엔드포인트에 서버 측 권한 검증을 반드시 적용하세요. "
                    "URL 경로를 숨기는 것만으로는 접근 제어가 되지 않습니다."
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
            title="기능 레벨 접근 제어 정상",
            description=(
                f"저권한 역할({attacker.role})의 관리 기능 접근이 모두 차단되었습니다. "
                f"테스트한 경로 수: {request_count}"
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
        return requests.request(
            method=method,
            url=url,
            headers=self._auth_headers(auth),
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
