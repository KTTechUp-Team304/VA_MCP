from __future__ import annotations

# extra 옵션 키:
#   "test_origins": list[str] — 테스트에 사용할 Origin 값 목록
#                               (기본값: ["https://evil.example.com", "null"])

import requests
import time
from typing import Any, Dict, List

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

DEFAULT_TEST_ORIGINS = [
    "https://evil.example.com",
    "null",
]


class CorsMisconfigurationTool(BaseTool):
    """
    대상 엔드포인트의 CORS 정책 오설정 여부를 점검하는 도구.
    임의의 Origin 헤더를 전송하여 서버가 이를 무분별하게 허용하는지 확인하며,
    자격 증명(Credentials) 허용 여부에 따라 위험도를 구분하여 판정한다.
    """

    tool_id = "cors_misconfiguration"
    tool_name = "CORS Misconfiguration Testing"
    tool_version = "0.1.0"

    def run(self, tool_input: ToolInput) -> ToolResult:
        start_ts = time.time()
        started_at = utc_now_iso()

        # 1) request 방어
        req = tool_input.request
        if not req:
            ended_at = utc_now_iso()
            return ToolResult(
                tool_id=self.tool_id,
                tool_name=self.tool_name,
                status=ToolStatus.SKIPPED.value,
                severity=Severity.INFO.value,
                confidence=Confidence.LOW.value,
                title="요청 정보 없음",
                description="request가 제공되지 않아 점검을 건너뜁니다.",
                evidence=[],
                started_at=started_at,
                ended_at=ended_at,
                duration_ms=0,
                tool_version=self.tool_version,
            )

        # 2) options/extra 방어
        opts = tool_input.options
        extra: Dict[str, Any] = opts.extra if opts and opts.extra else {}
        timeout_s = (opts.timeout / 1000.0) if opts and opts.timeout else 5
        test_origins: List[str] = extra.get("test_origins", DEFAULT_TEST_ORIGINS)
        max_req = opts.max_requests if opts and opts.max_requests is not None else len(test_origins)

        # 3) URL 안전 조합
        base = tool_input.target.base_url.rstrip("/")
        url = f"{base}/{req.path.lstrip('/')}"
        method = req.method.upper()

        # 4) auth_resolver로 auth header 생성
        auth_ctx = tool_input.auth[0] if tool_input.auth else None
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
                    started_at=started_at,
                    ended_at=ended_at,
                    duration_ms=int((time.time() - start_ts) * 1000),
                    tool_version=self.tool_version,
                )
        else:
            auth_headers = {}

        vulnerable_evidence: List[Evidence] = []
        result_severity = Severity.INFO
        result_confidence = Confidence.LOW

        try:
            # 5) Origin별 테스트
            for origin in test_origins[:max_req]:
                headers = {
                    **(req.headers or {}),
                    **auth_headers,
                    "Origin": origin,
                }

                resp = requests.request(
                    method=method,
                    url=url,
                    headers=headers,
                    params=req.query or None,
                    timeout=timeout_s,
                    verify=False,
                )

                acao = resp.headers.get("Access-Control-Allow-Origin", "")
                acac = resp.headers.get("Access-Control-Allow-Credentials", "").lower() == "true"
                is_reflected = acao == origin
                is_wildcard = acao == "*"

                # 5-1) 반사 + 크레덴셜 허용 → 치명적
                if is_reflected and acac:
                    result_severity = Severity.HIGH
                    result_confidence = Confidence.HIGH
                    note = f"Origin '{origin}' 반사 및 자격 증명 허용 확인. ACAO: {acao}, ACAC: true"
                    vulnerable_evidence.append(
                        Evidence(
                            request={
                                "method": method,
                                "url": url,
                                "headers": mask_sensitive(headers),
                            },
                            response_status=resp.status_code,
                            response_headers=dict(resp.headers),
                            response_body_sample=sanitize_response_sample(resp.text),
                            note=note,
                        )
                    )
                    break

                # 5-2) 와일드카드 + 크레덴셜 허용 → 중간 위험
                if is_wildcard and acac:
                    if result_severity.value < Severity.MEDIUM.value:
                        result_severity = Severity.MEDIUM
                        result_confidence = Confidence.HIGH
                    note = f"와일드카드(*)와 자격 증명 허용이 동시에 설정됨. ACAO: {acao}, ACAC: true"
                    vulnerable_evidence.append(
                        Evidence(
                            request={
                                "method": method,
                                "url": url,
                                "headers": mask_sensitive(headers),
                            },
                            response_status=resp.status_code,
                            response_headers=dict(resp.headers),
                            response_body_sample=sanitize_response_sample(resp.text),
                            note=note,
                        )
                    )
                    continue

                # 5-3) 반사만 → 낮은 위험
                if is_reflected and not acac:
                    if result_severity.value < Severity.LOW.value:
                        result_severity = Severity.LOW
                        result_confidence = Confidence.MEDIUM
                    note = f"Origin '{origin}' 반사 확인 (자격 증명 미허용). ACAO: {acao}"
                    vulnerable_evidence.append(
                        Evidence(
                            request={
                                "method": method,
                                "url": url,
                                "headers": mask_sensitive(headers),
                            },
                            response_status=resp.status_code,
                            response_headers=dict(resp.headers),
                            response_body_sample=sanitize_response_sample(resp.text),
                            note=note,
                        )
                    )

        except requests.Timeout as e:
            ended_at = utc_now_iso()
            return ToolResult(
                tool_id=self.tool_id,
                tool_name=self.tool_name,
                status=ToolStatus.ERROR.value,
                severity=Severity.INFO.value,
                confidence=Confidence.LOW.value,
                title="요청 타임아웃",
                description=str(e),
                evidence=[],
                errors=[build_tool_error(ErrorCode.TIMEOUT.value, str(e), retryable=True)],
                started_at=started_at,
                ended_at=ended_at,
                duration_ms=int((time.time() - start_ts) * 1000),
                tool_version=self.tool_version,
            )
        except requests.RequestException as e:
            ended_at = utc_now_iso()
            return ToolResult(
                tool_id=self.tool_id,
                tool_name=self.tool_name,
                status=ToolStatus.ERROR.value,
                severity=Severity.INFO.value,
                confidence=Confidence.LOW.value,
                title="HTTP 요청 실패",
                description=str(e),
                evidence=[],
                errors=[build_tool_error(ErrorCode.HTTP_FAILURE.value, str(e), retryable=True)],
                started_at=started_at,
                ended_at=ended_at,
                duration_ms=int((time.time() - start_ts) * 1000),
                tool_version=self.tool_version,
            )

        ended_at = utc_now_iso()
        duration_ms = int((time.time() - start_ts) * 1000)

        # 6) 취약 여부 반환
        if vulnerable_evidence:
            return ToolResult(
                tool_id=self.tool_id,
                tool_name=self.tool_name,
                status=ToolStatus.VULNERABLE.value,
                severity=result_severity.value,
                confidence=result_confidence.value,
                title="CORS 오설정 발견",
                description="대상 엔드포인트에서 CORS 정책 오설정이 발견되었습니다.",
                owasp=["A02:2025 Security Misconfiguration"],
                cwe=["CWE-942"],
                evidence=vulnerable_evidence,
                recommendation=(
                    "허용할 Origin을 명시적인 화이트리스트로 관리하세요. "
                    "Access-Control-Allow-Credentials: true 사용 시 와일드카드(*) 및 임의 Origin 반사를 금지하세요."
                ),
                started_at=started_at,
                ended_at=ended_at,
                duration_ms=duration_ms,
                tool_version=self.tool_version,
            )

        # 7) 정상
        return ToolResult(
            tool_id=self.tool_id,
            tool_name=self.tool_name,
            status=ToolStatus.PASSED.value,
            severity=Severity.INFO.value,
            confidence=Confidence.HIGH.value,
            title="CORS 정책 정상",
            description="임의 Origin에 대한 무분별한 허용이 확인되지 않았습니다.",
            owasp=["A02:2025 Security Misconfiguration"],
            cwe=["CWE-942"],
            started_at=started_at,
            ended_at=ended_at,
            duration_ms=duration_ms,
            tool_version=self.tool_version,
        )