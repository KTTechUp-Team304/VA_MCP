"""
HTTP 메서드 변조 테스트 도구.

허용되지 않아야 할 HTTP 메서드가 열려 있는지 확인한다.
원본 메서드(request.method)를 기준으로 나머지 메서드를 테스트한다.

auth 구성:
  auth[0] = 테스트에 사용할 인증 컨텍스트 (없으면 비인증 요청)

safe_mode 기준:
  True  → GET, HEAD, OPTIONS, TRACE 만 테스트
  False → GET, HEAD, OPTIONS, TRACE, POST, PUT, PATCH, DELETE 전체 테스트

extra 옵션:
  extra["test_methods"] = ["DELETE", "PUT"]
    → 이 목록이 있으면 safe_mode 무관하게 해당 메서드만 테스트

판단 기준:
  200/201/204 응답    → VULNERABLE, severity=HIGH
  TRACE 200 응답      → VULNERABLE, severity=MEDIUM (XST 위험)
  OPTIONS 위험 메서드 포함 → PASSED, severity=LOW
  401/403/405 응답    → PASSED, severity=INFO

SKIPPED 조건:
  - request 없음
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

SAFE_METHODS = ["GET", "HEAD", "OPTIONS", "TRACE"]
ALL_METHODS = ["GET", "HEAD", "OPTIONS", "TRACE", "POST", "PUT", "PATCH", "DELETE"]
DANGEROUS_METHODS = {"POST", "PUT", "PATCH", "DELETE"}


class HttpMethodTamperTool(BaseTool):
    tool_id = "http_method_tamper"
    tool_name = "HTTP Method Tampering"

    def run(self, tool_input: ToolInput) -> ToolResult:
        started_at = utc_now_iso()

        if not tool_input.request:
            return self._skipped(started_at, "request가 제공되지 않았습니다.")

        req = tool_input.request
        base_url = tool_input.target.base_url.rstrip("/")
        url = base_url + req.path
        timeout_s = tool_input.options.timeout / 1000
        safe_mode = tool_input.options.safe_mode

        auth = tool_input.auth[0] if tool_input.auth else None

        explicit_methods: list[str] = tool_input.options.extra.get("test_methods", [])
        if explicit_methods:
            candidate_methods = [m.upper() for m in explicit_methods]
        elif safe_mode:
            candidate_methods = SAFE_METHODS
        else:
            candidate_methods = ALL_METHODS

        original_method = req.method.upper()
        test_methods = [m for m in candidate_methods if m != original_method]

        vulnerable_evidences: list[Evidence] = []
        options_warning: str | None = None

        try:
            for method in test_methods:
                resp = self._send(url, method, req.query, req.body, auth, timeout_s)

                if method == "OPTIONS":
                    allow_header = resp.headers.get("Allow", "")
                    exposed = [m for m in DANGEROUS_METHODS if m in allow_header]
                    if exposed:
                        options_warning = f"OPTIONS Allow 헤더에 위험 메서드 노출: {', '.join(exposed)}"
                    continue

                if resp.status_code in (200, 201, 204):
                    severity = Severity.MEDIUM if method == "TRACE" else Severity.HIGH
                    note = (
                        f"TRACE 메서드 허용 (XST 위험)" if method == "TRACE"
                        else f"메서드 {method}로 접근 성공 (원본: {original_method})"
                    )
                    evidence = Evidence(
                        request={
                            "method": method,
                            "url": url,
                            "headers": mask_sensitive(dict(resp.request.headers)),
                        },
                        response_status=resp.status_code,
                        response_headers=dict(resp.headers),
                        response_body_sample=sanitize_response_sample(resp.text),
                        note=note,
                    )
                    vulnerable_evidences.append(evidence)

        except requests.Timeout:
            return self._error(started_at, ErrorCode.TIMEOUT, "HTTP 요청 타임아웃이 발생했습니다.", retryable=True)
        except requests.RequestException as exc:
            return self._error(started_at, ErrorCode.HTTP_FAILURE, str(exc))

        ended_at = utc_now_iso()

        if vulnerable_evidences:
            vuln_methods = [e.request["method"] for e in vulnerable_evidences]  # type: ignore[index]
            return ToolResult(
                tool_id=self.tool_id,
                tool_name=self.tool_name,
                status=ToolStatus.VULNERABLE,
                severity=Severity.HIGH,
                confidence=Confidence.HIGH,
                title="허용되지 않은 HTTP 메서드 접근 가능",
                description=(
                    f"원본 메서드({original_method}) 외 다음 메서드로 접근이 허용되었습니다: "
                    f"{', '.join(vuln_methods)}"
                ),
                owasp=["A01 Broken Access Control"],
                cwe=["CWE-749"],
                evidence=vulnerable_evidences,
                recommendation=(
                    "서버에서 허용할 HTTP 메서드를 명시적으로 제한하세요. "
                    "TRACE 메서드는 운영 환경에서 반드시 비활성화해야 합니다."
                ),
                started_at=started_at,
                ended_at=ended_at,
            )

        if options_warning:
            return ToolResult(
                tool_id=self.tool_id,
                tool_name=self.tool_name,
                status=ToolStatus.PASSED,
                severity=Severity.LOW,
                confidence=Confidence.MEDIUM,
                title="OPTIONS 헤더에 위험 메서드 노출",
                description=options_warning,
                owasp=["A01 Broken Access Control"],
                cwe=["CWE-749"],
                recommendation="Allow 헤더에서 불필요한 HTTP 메서드를 제거하세요.",
                started_at=started_at,
                ended_at=ended_at,
            )

        return ToolResult(
            tool_id=self.tool_id,
            tool_name=self.tool_name,
            status=ToolStatus.PASSED,
            severity=Severity.INFO,
            confidence=Confidence.HIGH,
            title="HTTP 메서드 변조 취약점 미발견",
            description=(
                f"테스트한 메서드({', '.join(test_methods)})가 모두 적절히 차단되었습니다."
            ),
            owasp=["A01 Broken Access Control"],
            cwe=["CWE-749"],
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
        auth: AuthContext | None,
        timeout_s: float,
    ) -> requests.Response:
        headers = self._auth_headers(auth) if auth else {}
        return requests.request(
            method=method,
            url=url,
            headers=headers,
            params=query or None,
            json=body if method not in ("GET", "HEAD", "OPTIONS", "TRACE") else None,
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
