from __future__ import annotations

# extra 옵션 키:
#   "sensitive_paths": list[str] — 점검할 민감 경로 목록
#                                  (기본값: DEFAULT_SENSITIVE_PATHS)

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

DEFAULT_SENSITIVE_PATHS = [
    "/.env",
    "/.git/config",
    "/.git/HEAD",
    "/backup",
    "/backup.zip",
    "/backup.sql",
    "/config.php",
    "/wp-config.php",
    "/.DS_Store",
    "/database.yml",
    "/config.yml",
    "/config.json",
    "/.htaccess",
    "/web.config",
    "/phpinfo.php",
    "/server-status",
]


class SensitivePathTool(BaseTool):
    """
    서버에 노출된 민감한 경로(설정 파일, 백업, 버전 관리 등)를 탐지하는 도구.
    .env, .git/config, backup.zip 등 주요 경로에 직접 요청을 보내며,
    HTTP 200 응답 시 HIGH, HTTP 403 응답 시 경로 존재 가능성으로 MEDIUM을 판정한다.
    """

    tool_id = "sensitive_path"
    tool_name = "Sensitive Path Detection"
    tool_version = "0.1.0"

    def run(self, tool_input: ToolInput) -> ToolResult:
        start_ts   = time.time()
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

        # 2) options/extra 안전 처리
        opts: Any = tool_input.options
        extra: Dict[str, Any] = opts.extra if opts and opts.extra else {}
        timeout_s = (opts.timeout / 1000.0) if opts and opts.timeout else 5
        max_req   = opts.max_requests if opts and opts.max_requests is not None else len(DEFAULT_SENSITIVE_PATHS)
        sensitive_paths: List[str] = extra.get("sensitive_paths", DEFAULT_SENSITIVE_PATHS)

        # 3) URL 베이스 및 headers 준비
        base = tool_input.target.base_url.rstrip("/")
        orig_headers = req.headers or {}

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
            # 5) 민감 경로별 요청
            for path in sensitive_paths[:max_req]:
                url = f"{base}/{path.lstrip('/')}"
                headers = {**orig_headers, **auth_headers}

                resp = requests.get(
                    url=url,
                    headers=headers,
                    timeout=timeout_s,
                    allow_redirects=False,
                )

                status = resp.status_code
                if status == 200:
                    note = f"민감 경로 '{path}' 직접 접근 가능 (HTTP 200)"
                elif status == 403:
                    note = f"민감 경로 '{path}' 존재 확인 (HTTP 403 - 접근 차단됨)"
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
                duration_ms=0,
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
                duration_ms=0,
                tool_version=self.tool_version,
            )

        ended_at   = utc_now_iso()
        duration_ms = int((time.time() - start_ts) * 1000)

        # 6) 결과 반환
        if vulnerable_evidence:
            has_access = any(e.response_status == 200 for e in vulnerable_evidence)
            severity   = Severity.HIGH if has_access else Severity.MEDIUM
            confidence = Confidence.HIGH if has_access else Confidence.MEDIUM

            return ToolResult(
                tool_id=self.tool_id,
                tool_name=self.tool_name,
                status=ToolStatus.VULNERABLE.value,
                severity=severity.value,
                confidence=confidence.value,
                title="민감 경로 노출 발견",
                description=f"{len(vulnerable_evidence)}개의 민감 경로가 탐지되었습니다.",
                owasp=["A02:2025 Security Misconfiguration"],
                cwe=["CWE-538"],
                evidence=vulnerable_evidence,
                recommendation=(
                    "민감한 파일과 디렉터리는 웹 루트 외부로 이동하거나 접근을 차단하세요. "
                    "웹 서버 설정에서 .env, .git 등 숨김 파일 및 백업 파일 접근을 금지하세요."
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
            title="민감 경로 미노출",
            description="점검한 민감 경로에서 외부 접근 가능한 경로가 발견되지 않았습니다.",
            evidence=[],
            started_at=started_at,
            ended_at=ended_at,
            duration_ms=duration_ms,
            tool_version=self.tool_version,
        )