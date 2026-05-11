from __future__ import annotations

# extra 옵션 키:
#   "debug_paths": list[str] — 점검할 디버그 엔드포인트 경로 목록
#                              (기본값: DEFAULT_DEBUG_PATHS)

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

DEFAULT_DEBUG_PATHS = [
    "/debug",
    "/__debug__",
    "/console",
    "/profiler",
    "/actuator",
    "/actuator/env",
    "/actuator/beans",
    "/actuator/metrics",
    "/actuator/loggers",
    "/actuator/threaddump",
    "/swagger-ui",
    "/swagger-ui.html",
    "/api-docs",
    "/v2/api-docs",
    "/v3/api-docs",
    "/graphiql",
    "/metrics",
    "/__admin__",
]

# 접근 가능(200) 판정 상태 코드
_ACCESSIBLE_STATUS = {200}
# 존재하지만 차단(401/403) 판정 상태 코드
_EXISTS_STATUS = {401, 403}


class DebugEndpointTool(BaseTool):
    tool_id = "debug_endpoint"
    tool_name = "Debug Endpoint Detection"
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
        max_req = opts.max_requests if opts and opts.max_requests is not None else len(DEFAULT_DEBUG_PATHS)
        debug_paths: List[str] = extra.get("debug_paths", DEFAULT_DEBUG_PATHS)

        # 3) URL 기본 준비
        base = tool_input.target.base_url.rstrip("/")
        req_headers = req.headers or {}

        # 4) auth_resolver로 auth header 생성
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
                    started_at=started_at,
                    ended_at=ended_at,
                    duration_ms=int((time.time() - start_ts) * 1000),
                    tool_version=self.tool_version,
                )
        else:
            auth_headers = {}

        vulnerable_evidence: List[Evidence] = []

        try:
            # 5) debug_paths 순회
            for path in debug_paths[:max_req]:
                url = f"{base}/{path.lstrip('/')}"
                headers = {**req_headers, **auth_headers}

                resp = requests.get(
                    url=url,
                    headers=headers,
                    timeout=timeout_s,
                    allow_redirects=False,
                    verify=False,
                )

                status = resp.status_code
                note: str

                if status in _ACCESSIBLE_STATUS:
                    note = f"디버그 엔드포인트 '{path}' 직접 접근 가능 (HTTP {status})"
                elif status in _EXISTS_STATUS:
                    note = f"디버그 엔드포인트 '{path}' 존재 확인 (HTTP {status} - 접근 차단됨)"
                else:
                    continue

                vulnerable_evidence.append(
                    Evidence(
                        request={
                            "method": "GET",
                            "url": url,
                            "headers": mask_sensitive(headers),
                        },
                        response_status=status,
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

        # 6) 결과 반환
        if vulnerable_evidence:
            has_access = any(e.response_status in _ACCESSIBLE_STATUS for e in vulnerable_evidence)
            severity = Severity.HIGH if has_access else Severity.MEDIUM
            confidence = Confidence.HIGH if has_access else Confidence.MEDIUM

            return ToolResult(
                tool_id=self.tool_id,
                tool_name=self.tool_name,
                status=ToolStatus.VULNERABLE.value,
                severity=severity.value,
                confidence=confidence.value,
                title="디버그 엔드포인트 노출 발견",
                description=f"{len(vulnerable_evidence)}개의 디버그 엔드포인트가 탐지되었습니다.",
                owasp=["A02:2025 Security Misconfiguration"],
                cwe=["CWE-215"],
                evidence=vulnerable_evidence,
                recommendation=(
                    "운영 환경에서는 디버그 및 관리용 엔드포인트를 비활성화하거나 "
                    "IP 화이트리스트 등으로 접근을 엄격히 제한하세요."
                ),
                started_at=started_at,
                ended_at=ended_at,
                duration_ms=duration_ms,
                tool_version=self.tool_version,
            )

        # PASSED
        return ToolResult(
            tool_id=self.tool_id,
            tool_name=self.tool_name,
            status=ToolStatus.PASSED.value,
            severity=Severity.INFO.value,
            confidence=Confidence.HIGH.value,
            title="디버그 엔드포인트 미노출",
            description="점검한 경로에서 노출된 디버그 엔드포인트가 발견되지 않았습니다.",
            evidence=[],
            started_at=started_at,
            ended_at=ended_at,
            duration_ms=duration_ms,
            tool_version=self.tool_version,
        )