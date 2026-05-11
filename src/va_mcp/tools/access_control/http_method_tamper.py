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
import time
from typing import Any, List, Dict

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

SAFE_METHODS = ["GET", "HEAD", "OPTIONS", "TRACE"]
ALL_METHODS = ["GET", "HEAD", "OPTIONS", "TRACE", "POST", "PUT", "PATCH", "DELETE"]
DANGEROUS_METHODS = {"POST", "PUT", "PATCH", "DELETE"}


class HttpMethodTamperTool(BaseTool):
    tool_id = "http_method_tamper"
    tool_name = "HTTP Method Tampering"
    tool_version = "0.1.0"

    def run(self, tool_input: ToolInput) -> ToolResult:
        start_ts = time.time()
        started_at = utc_now_iso()

        # 1) request 방어
        if not tool_input.request:
            return self._skipped(started_at, "request가 제공되지 않았습니다.")

        req = tool_input.request
        # 2) URL 안전 조합
        base = tool_input.target.base_url.rstrip("/")
        url = f"{base}/{req.path.lstrip('/')}"
        # 3) timeout 방어
        timeout_s = (
            tool_input.options.timeout / 1000
            if tool_input.options and tool_input.options.timeout
            else 5
        )
        # 4) safe_mode
        safe_mode = tool_input.options.safe_mode if tool_input.options else False

        # 5) extra 방어 및 test_methods 추출
        extra: Dict[str, Any] = (
            tool_input.options.extra
            if tool_input.options and tool_input.options.extra
            else {}
        )
        explicit_methods: List[str] = extra.get("test_methods", [])
        if explicit_methods:
            candidate_methods = [m.upper() for m in explicit_methods]
        elif safe_mode:
            candidate_methods = SAFE_METHODS
        else:
            candidate_methods = ALL_METHODS

        original_method = req.method.upper()
        test_methods = [m for m in candidate_methods if m != original_method]

        # 6) auth 및 resolver
        auth_ctx: AuthContext | None = tool_input.auth[0] if tool_input.auth else None
        if auth_ctx:
            try:
                parse_credentials(auth_ctx)
                auth_headers = resolve_auth_headers(auth_ctx)
            except CredentialResolverError as e:
                ended_at = utc_now_iso()
                return ToolResult(
                    tool_id=self.tool_id,
                    tool_name=self.tool_name,
                    status=ToolStatus.SKIPPED.value,
                    severity=Severity.INFO.value,
                    confidence=Confidence.LOW.value,
                    title="Credential 해석 실패",
                    description=str(e),
                    evidence=[],
                    owasp=[],
                    cwe=[],
                    recommendation="AuthContext를 검토하세요.",
                    started_at=started_at,
                    ended_at=ended_at,
                    duration_ms=int((time.time() - start_ts) * 1000),
                )
        else:
            auth_headers = {}

        vulnerable_evidences: List[Evidence] = []
        options_warning: str | None = None

        try:
            # 7) 각 메서드 테스트
            for method in test_methods:
                resp = self._send(
                    url=url,
                    method=method,
                    query=req.query,
                    body=req.body,
                    auth_headers=auth_headers,
                    timeout_s=timeout_s,
                )

                if method == "OPTIONS":
                    allow_header = resp.headers.get("Allow", "")
                    exposed = [m for m in DANGEROUS_METHODS if m in allow_header]
                    if exposed:
                        options_warning = (
                            f"OPTIONS Allow 헤더에 위험 메서드 노출: {', '.join(exposed)}"
                        )
                    continue

                if resp.status_code in (200, 201, 204):
                    severity = Severity.MEDIUM if method == "TRACE" else Severity.HIGH
                    note = (
                        "TRACE 메서드 허용 (XST 위험)"
                        if method == "TRACE"
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

        # 8) 취약 결과
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
                owasp=["A01:2025 Broken Access Control"],
                cwe=["CWE-749"],
                evidence=vulnerable_evidences,
                recommendation=(
                    "서버에서 허용할 HTTP 메서드를 명시적으로 제한하세요. "
                    "TRACE 메서드는 운영 환경에서 반드시 비활성화해야 합니다."
                ),
                started_at=started_at,
                ended_at=ended_at,
                duration_ms=int((time.time() - start_ts) * 1000),
            )

        # 9) OPTIONS 헤더 경고
        if options_warning:
            return ToolResult(
                tool_id=self.tool_id,
                tool_name=self.tool_name,
                status=ToolStatus.PASSED,
                severity=Severity.LOW,
                confidence=Confidence.MEDIUM,
                title="OPTIONS 헤더에 위험 메서드 노출",
                description=options_warning,
                owasp=["A01:2025 Broken Access Control"],
                cwe=["CWE-749"],
                recommendation="Allow 헤더에서 불필요한 HTTP 메서드를 제거하세요.",
                started_at=started_at,
                ended_at=ended_at,
                duration_ms=int((time.time() - start_ts) * 1000),
            )

        # 10) 정상
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
            owasp=["A01:2025 Broken Access Control"],
            cwe=["CWE-749"],
            started_at=started_at,
            ended_at=ended_at,
            duration_ms=int((time.time() - start_ts) * 1000),
        )

    # ------------------------------------------------------------------
    # helper
    # ------------------------------------------------------------------

    def _send(
        self,
        url: str,
        method: str,
        query: dict[str, Any] | None,
        body: dict[str, Any] | None,
        auth_headers: dict[str, str],
        timeout_s: float,
    ) -> requests.Response:
        return requests.request(
            method=method,
            url=url,
            headers=auth_headers,
            params=query or None,
            json=body
            if method not in ("GET", "HEAD", "OPTIONS", "TRACE")
            else None,
            timeout=timeout_s,
            allow_redirects=False,
        )

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