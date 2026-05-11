"""
IDOR / BOLA (Insecure Direct Object Reference / Broken Object Level Authorization) 테스트 도구.

auth 리스트 구성:
  auth[0] = 공격자 (접근 권한 없는 사용자)
  auth[1] = 소유자 (리소스 정상 소유 사용자)

request.path 는 소유자 기준 리소스 경로로 전달한다.
  예: /api/users/2/profile  (2는 auth[1] 소유자의 리소스 ID)

extra 옵션:
  없음 (현재 버전에서는 extra 미사용)

SKIPPED 조건:
  - request 없음
  - auth 2개 미만
"""

from __future__ import annotations

import requests
from datetime import datetime

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
from va_mcp.core.resolvers.auth_resolver import (
    parse_credentials,
    resolve_auth_headers,
    CredentialResolverError,
)


class IdorBolaTool(BaseTool):
    tool_id = "idor_bola"
    tool_name = "IDOR / BOLA Testing"
    tool_version = "0.1.0"

    def run(self, tool_input: ToolInput) -> ToolResult:
        started_at = utc_now_iso()

        # 1) 요청/인증 검증
        if not tool_input.request:
            return self._skipped(started_at, "request가 제공되지 않았습니다.")
        if len(tool_input.auth) < 2:
            return self._skipped(
                started_at,
                "auth가 2개 필요합니다 (auth[0]=공격자, auth[1]=소유자).",
            )

        # 안전한 extra (planner/orchestrator 매핑용, 사용하지 않더라도 방어)
        extra = (
            tool_input.options.extra
            if tool_input.options and tool_input.options.extra
            else {}
        )

        req = tool_input.request
        base = tool_input.target.base_url.rstrip("/")
        url = f"{base}/{req.path.lstrip('/')}"
        timeout_s = (
            tool_input.options.timeout / 1000
            if tool_input.options and tool_input.options.timeout
            else 5
        )

        attacker: AuthContext = tool_input.auth[0]
        owner: AuthContext    = tool_input.auth[1]

        # 2) AuthContext 파싱 및 헤더 생성 (owner)
        try:
            parse_credentials(owner)
            owner_headers = resolve_auth_headers(owner)
        except CredentialResolverError as e:
            return self._skipped(
                started_at,
                f"Credential 해석 실패 (owner): {e}"
            )

        # 3) 소유자 요청
        try:
            owner_resp = requests.request(
                method=req.method,
                url=url,
                headers={**(req.headers or {}), **owner_headers},
                params=req.query or None,
                json=req.body,
                timeout=timeout_s,
            )
        except requests.Timeout as e:
            return self._error(
                started_at,
                ErrorCode.TIMEOUT,
                "HTTP 요청 타임아웃이 발생했습니다.",
                retryable=True,
            )
        except requests.RequestException as exc:
            return self._error(
                started_at,
                ErrorCode.HTTP_FAILURE,
                str(exc),
            )

        # 4) 소유자 요청 실패 시 SKIPPED
        if owner_resp.status_code not in (200, 201, 204):
            return self._skipped(
                started_at,
                f"소유자({owner.role}) 요청도 실패({owner_resp.status_code}). 경로 또는 소유자 토큰을 확인하세요.",
            )

        # 5) AuthContext 파싱 및 헤더 생성 (attacker)
        try:
            parse_credentials(attacker)
            attacker_headers = resolve_auth_headers(attacker)
        except CredentialResolverError as e:
            return self._skipped(
                started_at,
                f"Credential 해석 실패 (attacker): {e}"
            )

        # 6) 공격자 요청
        try:
            attacker_resp = requests.request(
                method=req.method,
                url=url,
                headers={**(req.headers or {}), **attacker_headers},
                params=req.query or None,
                json=req.body,
                timeout=timeout_s,
            )
        except requests.Timeout as e:
            return self._error(
                started_at,
                ErrorCode.TIMEOUT,
                "HTTP 요청 타임아웃이 발생했습니다.",
                retryable=True,
            )
        except requests.RequestException as exc:
            return self._error(
                started_at,
                ErrorCode.HTTP_FAILURE,
                str(exc),
            )

        ended_at = utc_now_iso()

        # 7) 취약 여부 판단
        if attacker_resp.status_code in (200, 201, 204):
            bodies_match = (
                attacker_resp.text.strip() == owner_resp.text.strip()
            )
            confidence_level = (
                Confidence.HIGH if bodies_match else Confidence.MEDIUM
            )

            evidence = Evidence(
                request={
                    "method": req.method,
                    "url": url,
                    "headers": mask_sensitive(dict(attacker_resp.request.headers)),
                    "attacker_role": attacker.role,
                    "owner_role":    owner.role,
                },
                response_status=attacker_resp.status_code,
                response_headers=dict(attacker_resp.headers),
                response_body_sample=sanitize_response_sample(attacker_resp.text),
                note=(
                    f"공격자({attacker.role})가 소유자({owner.role})의 리소스에 접근 성공. "
                    f"응답 body {'소유자 응답과 일치' if bodies_match else '소유자 응답과 상이'}."
                ),
            )

            return ToolResult(
                tool_id=self.tool_id,
                tool_name=self.tool_name,
                status=ToolStatus.VULNERABLE,
                severity=Severity.HIGH,
                confidence=confidence_level,
                title="타 사용자 리소스 무단 접근 가능 (IDOR/BOLA)",
                description=(
                    f"공격자({attacker.role})가 소유자({owner.role})의 리소스({req.path})에 "
                    f"HTTP {attacker_resp.status_code} 응답으로 접근에 성공했습니다."
                ),
                owasp=["A01:2025 Broken Access Control"],
                cwe=["CWE-639"],
                evidence=[evidence],
                recommendation=(
                    "리소스 접근 시 요청자의 ID와 리소스 소유자 ID를 서버 측에서 반드시 비교 검증하세요. "
                    "클라이언트가 전달하는 ID만 신뢰하지 마세요."
                ),
                started_at=started_at,
                ended_at=ended_at,
                duration_ms=0,
            )

        # 8) 차단 확인
        return ToolResult(
            tool_id=self.tool_id,
            tool_name=self.tool_name,
            status=ToolStatus.PASSED,
            severity=Severity.INFO,
            confidence=Confidence.HIGH,
            title="타 사용자 리소스 접근 차단 확인",
            description=(
                f"공격자({attacker.role})의 접근이 {attacker_resp.status_code}으로 차단되었습니다."
            ),
            owasp=["A01:2025 Broken Access Control"],
            cwe=["CWE-639"],
            started_at=started_at,
            ended_at=ended_at,
            duration_ms=0,
        )

    # ------------------------------------------------------------------
    # helpers
    # ------------------------------------------------------------------

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