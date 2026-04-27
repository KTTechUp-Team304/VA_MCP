"""
CORS 미설정 테스트 도구.

임의의 Origin 헤더를 포함한 요청을 보내고,
서버가 Access-Control-Allow-Origin에 해당 Origin을 허용하는지 확인한다.

auth 구성:
  auth[0] = 테스트에 사용할 인증 컨텍스트 (없으면 비인증 요청)

extra 옵션:
  extra["test_origins"] = ["https://evil.example.com", "null"]
    → 기본 테스트 Origin 목록 대신 이것을 사용

판단 기준:
  ACAO = * + ACAC = true    → VULNERABLE, severity=CRITICAL  (크레덴셜 포함 와일드카드)
  ACAO = 공격자 Origin 반사
    + ACAC = true           → VULNERABLE, severity=CRITICAL  (크레덴셜 포함 Origin 반사)
  ACAO = * (크레덴셜 없음)  → VULNERABLE, severity=HIGH     (와일드카드 허용)
  ACAO = 공격자 Origin 반사
    (크레덴셜 없음)         → VULNERABLE, severity=HIGH     (Origin 반사)
  ACAO = null 허용         → VULNERABLE, severity=MEDIUM   (null origin 허용)
  허용하지 않음            → PASSED,    severity=INFO

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
    utc_now_iso,
)

DEFAULT_TEST_ORIGINS = [
    "https://evil.example.com",
    "https://attacker.com",
    "null",
]

_WILDCARD = "*"


class CorsCheckTool(BaseTool):
    tool_id = "cors_check"
    tool_name = "CORS Misconfiguration Check"

    def run(self, tool_input: ToolInput) -> ToolResult:
        started_at = utc_now_iso()

        base_url = tool_input.target.base_url.rstrip("/")
        path = tool_input.request.path if tool_input.request else "/"
        url = base_url + path
        timeout_s = tool_input.options.timeout / 1000
        auth = tool_input.auth[0] if tool_input.auth else None

        test_origins: list[str] = tool_input.options.extra.get(
            "test_origins", DEFAULT_TEST_ORIGINS
        )

        vulnerable_evidences: list[Evidence] = []
        worst_severity = Severity.INFO

        try:
            for origin in test_origins:
                result = self._test_origin(url, origin, auth, timeout_s)
                if result is None:
                    continue
                evidence, severity = result
                vulnerable_evidences.append(evidence)
                if self._severity_rank(severity) > self._severity_rank(worst_severity):
                    worst_severity = severity

        except requests.Timeout:
            return self._error(started_at, ErrorCode.TIMEOUT, "HTTP 요청 타임아웃이 발생했습니다.", retryable=True)
        except requests.RequestException as exc:
            return self._error(started_at, ErrorCode.HTTP_FAILURE, str(exc))

        ended_at = utc_now_iso()

        if vulnerable_evidences:
            return ToolResult(
                tool_id=self.tool_id,
                tool_name=self.tool_name,
                status=ToolStatus.VULNERABLE,
                severity=worst_severity,
                confidence=Confidence.HIGH,
                title="CORS 정책 미설정 또는 과도한 허용",
                description=(
                    f"서버가 신뢰할 수 없는 Origin의 교차 출처 요청을 허용합니다. "
                    f"취약 케이스 수: {len(vulnerable_evidences)}"
                ),
                owasp=["A01 Broken Access Control"],
                cwe=["CWE-942"],
                evidence=vulnerable_evidences,
                recommendation=(
                    "Access-Control-Allow-Origin에 신뢰할 수 있는 도메인만 명시적으로 허용하세요. "
                    "와일드카드(*)와 Access-Control-Allow-Credentials: true를 동시에 사용하지 마세요. "
                    "null Origin은 허용하지 마세요."
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
            title="CORS 정책 정상",
            description=(
                f"테스트한 {len(test_origins)}개 Origin에 대해 교차 출처 접근이 허용되지 않았습니다."
            ),
            owasp=["A01 Broken Access Control"],
            cwe=["CWE-942"],
            started_at=started_at,
            ended_at=ended_at,
        )

    # ------------------------------------------------------------------
    # helpers
    # ------------------------------------------------------------------

    def _test_origin(
        self,
        url: str,
        origin: str,
        auth: AuthContext | None,
        timeout_s: float,
    ) -> tuple[Evidence, Severity] | None:
        """단일 Origin으로 CORS 테스트를 수행하고, 취약하면 (Evidence, Severity)를 반환한다."""
        headers = self._auth_headers(auth) if auth else {}
        headers["Origin"] = origin

        resp = requests.get(
            url=url,
            headers=headers,
            timeout=timeout_s,
            allow_redirects=False,
        )

        acao = resp.headers.get("Access-Control-Allow-Origin", "")
        acac = resp.headers.get("Access-Control-Allow-Credentials", "").lower() == "true"

        severity = self._evaluate_severity(origin, acao, acac)
        if severity is None:
            return None

        note = self._build_note(origin, acao, acac)
        evidence = Evidence(
            request={
                "method": "GET",
                "url": url,
                "headers": mask_sensitive({**headers}),
            },
            response_status=resp.status_code,
            response_headers={
                "Access-Control-Allow-Origin": acao,
                "Access-Control-Allow-Credentials": resp.headers.get(
                    "Access-Control-Allow-Credentials", ""
                ),
            },
            note=note,
        )
        return evidence, severity

    def _evaluate_severity(
        self, origin: str, acao: str, acac: bool
    ) -> Severity | None:
        """응답 헤더를 분석해서 심각도를 반환한다. 취약하지 않으면 None을 반환한다."""
        if not acao:
            return None

        is_wildcard = acao == _WILDCARD
        # null origin은 "반사"로 분류하지 않고 별도 판단한다
        is_null_allowed = origin == "null" and acao == "null"
        is_reflected = acao == origin and origin not in ("", "null")

        if (is_wildcard or is_reflected) and acac:
            return Severity.CRITICAL

        if is_wildcard or is_reflected:
            return Severity.HIGH

        # null origin + 크레덴셜 허용도 세션 탈취 가능하여 CRITICAL
        if is_null_allowed and acac:
            return Severity.CRITICAL

        if is_null_allowed:
            return Severity.MEDIUM

        return None

    def _build_note(self, origin: str, acao: str, acac: bool) -> str:
        parts = [f"Origin: {origin} → ACAO: {acao}"]
        if acac:
            parts.append("ACAC: true (크레덴셜 포함 허용 — 매우 위험)")
        return ", ".join(parts)

    def _severity_rank(self, severity: Severity) -> int:
        return {
            Severity.INFO: 0,
            Severity.LOW: 1,
            Severity.MEDIUM: 2,
            Severity.HIGH: 3,
            Severity.CRITICAL: 4,
        }.get(severity, 0)

    def _auth_headers(self, auth: AuthContext) -> dict[str, str]:
        headers: dict[str, str] = {}
        if auth.auth_type == "bearer" and auth.token:
            headers["Authorization"] = f"Bearer {auth.token}"
        elif auth.auth_type == "api_key" and auth.token:
            headers["X-API-Key"] = auth.token
        elif auth.auth_type == "cookie" and auth.cookie:
            headers["Cookie"] = auth.cookie
        return headers

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
