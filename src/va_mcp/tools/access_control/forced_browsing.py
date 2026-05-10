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

import time
import requests
from typing import List, Dict, Any

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
    tool_version = "0.1.0"

    def run(self, tool_input: ToolInput) -> ToolResult:
        start_ts = time.time()
        started_at = utc_now_iso()

        # 1) 안전하게 extra 및 mapping 가져오기
        extra: Dict[str, Any] = (
            tool_input.options.extra
            if tool_input.options and tool_input.options.extra
            else {}
        )
        mapping: Dict[str, Any] = extra.get("field_mapping", {})

        # 2) 요청 및 타임아웃/한도 방어
        req = tool_input.request
        if not req:
            return ToolResult(
                tool_id=self.tool_id,
                tool_name=self.tool_name,
                status=ToolStatus.SKIPPED.value,
                severity=Severity.INFO.value,
                confidence=Confidence.LOW.value,
                title="입력 부족",
                description="request 정보가 없습니다.",
                evidence=[],
                started_at=started_at,
                ended_at=started_at,
                duration_ms=0,
            )

        base = tool_input.target.base_url.rstrip("/")
        timeout_s = (
            tool_input.options.timeout / 1000
            if tool_input.options and tool_input.options.timeout
            else 5
        )
        max_requests = (
            tool_input.options.max_requests
            if tool_input.options and tool_input.options.max_requests is not None
            else 1
        )

        # 3) paths 매핑: planner/orchestrator 제공
        extra_paths = mapping.get("paths", [])
        all_paths = DEFAULT_PATHS + (extra_paths if isinstance(extra_paths, list) else [])

        # 4) auth 처리: optional
        auth_ctx: AuthContext | None = tool_input.auth[0] if tool_input.auth else None
        if auth_ctx:
            try:
                _ = parse_credentials(auth_ctx)
                auth_headers = resolve_auth_headers(auth_ctx)
            except CredentialResolverError:
                # auth 파싱 실패 시 skip
                ended_at = utc_now_iso()
                return ToolResult(
                    tool_id=self.tool_id,
                    tool_name=self.tool_name,
                    status=ToolStatus.SKIPPED.value,
                    severity=Severity.INFO.value,
                    confidence=Confidence.LOW.value,
                    title="Credential 해석 실패",
                    description="AuthContext를 검토하세요.",
                    evidence=[],
                    started_at=started_at,
                    ended_at=ended_at,
                    duration_ms=int((time.time() - start_ts) * 1000),
                )
        else:
            auth_headers = {}

        vulnerable_evidences: List[Evidence] = []
        request_count = 0

        try:
            # 5) 경로별 요청
            for path in all_paths:
                if request_count >= max_requests:
                    break

                url = f"{base}/{path.lstrip('/')}"
                resp = requests.get(
                    url=url,
                    headers={**(req.headers or {}), **auth_headers},
                    timeout=timeout_s,
                    allow_redirects=False,
                )
                request_count += 1

                # 6) 200 응답은 취약으로 간주
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
            return ToolResult(
                tool_id=self.tool_id,
                tool_name=self.tool_name,
                status=ToolStatus.ERROR.value,
                severity=Severity.INFO.value,
                confidence=Confidence.LOW.value,
                title="실행 오류",
                description="HTTP 요청 타임아웃이 발생했습니다.",
                errors=[build_tool_error(ErrorCode.TIMEOUT.value, "HTTP 요청 타임아웃이 발생했습니다.", retryable=True)],
                started_at=started_at,
                ended_at=utc_now_iso(),
                duration_ms=0,
            )
        except requests.RequestException as exc:
            return ToolResult(
                tool_id=self.tool_id,
                tool_name=self.tool_name,
                status=ToolStatus.ERROR.value,
                severity=Severity.INFO.value,
                confidence=Confidence.LOW.value,
                title="실행 오류",
                description=str(exc),
                errors=[build_tool_error(ErrorCode.HTTP_FAILURE.value, str(exc), retryable=True)],
                started_at=started_at,
                ended_at=utc_now_iso(),
                duration_ms=0,
            )

        ended_at = utc_now_iso()

        # 7) 결과 반환
        if vulnerable_evidences:
            exposed = [e.note.split(": ")[-1] for e in vulnerable_evidences]
            return ToolResult(
                tool_id=self.tool_id,
                tool_name=self.tool_name,
                status=ToolStatus.VULNERABLE.value,
                severity=Severity.HIGH.value,
                confidence=Confidence.HIGH.value,
                title="숨겨진 경로 노출 확인 (강제 브라우징)",
                description=(
                    f"인증 없이 접근 가능한 숨겨진 경로가 발견되었습니다. "
                    f"노출 경로: {', '.join(exposed)}"
                ),
                owasp=["A01:2025 Broken Access Control"],
                cwe=["CWE-425"],
                evidence=vulnerable_evidences,
                recommendation=(
                    "민감한 경로에 인증 및 권한 검증을 적용하세요. "
                    "불필요한 관리 인터페이스와 설정 파일은 외부에서 접근 불가능하도록 제한하세요."
                ),
                started_at=started_at,
                ended_at=ended_at,
                duration_ms=int((time.time() - start_ts) * 1000),
                tool_version=self.tool_version,
            )

        return ToolResult(
            tool_id=self.tool_id,
            tool_name=self.tool_name,
            status=ToolStatus.PASSED.value,
            severity=Severity.INFO.value,
            confidence=Confidence.MEDIUM.value,
            title="강제 브라우징 취약 경로 미발견",
            description=(
                f"테스트한 {request_count}개 경로에서 무단 접근 가능한 경로가 발견되지 않았습니다."
            ),
            owasp=["A01:2025 Broken Access Control"],
            cwe=["CWE-425"],
            started_at=started_at,
            ended_at=ended_at,
            duration_ms=int((time.time() - start_ts) * 1000),
            tool_version=self.tool_version,
        )