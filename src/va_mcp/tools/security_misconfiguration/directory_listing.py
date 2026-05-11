from __future__ import annotations

# extra 옵션 키:
#   "check_paths": list[str] — 디렉터리 목록 노출 여부를 점검할 경로 목록
#                              (기본값: DEFAULT_DIRECTORY_PATHS)

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

DEFAULT_DIRECTORY_PATHS = [
    "/",
    "/static/",
    "/assets/",
    "/uploads/",
    "/files/",
    "/images/",
    "/backup/",
    "/public/",
    "/resources/",
    "/media/",
]

DIRECTORY_LISTING_KEYWORDS = [
    "Index of /",
    "Directory listing for",
    "[PARENTDIR]",
    "[DIR]",
    "<title>Index of",
    "Parent Directory",
    "Directory: /",
]


class DirectoryListingTool(BaseTool):
    """
    웹 서버에서 디렉터리 목록이 외부에 노출되는지 탐지하는 도구.
    주요 디렉터리 경로에 GET 요청을 보내 HTTP 200 응답 바디에서
    디렉터리 목록 전형 키워드를 탐지하며, 발견 시 HIGH로 판정한다.
    """

    tool_id = "directory_listing"
    tool_name = "Directory Listing Detection"
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
        max_req = opts.max_requests if opts and opts.max_requests is not None else len(DEFAULT_DIRECTORY_PATHS)
        check_paths: List[str] = extra.get("check_paths", DEFAULT_DIRECTORY_PATHS)

        # 3) URL 베이스 및 headers 준비
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
            # 5) 경로별 디렉터리 노출 검사
            for path in check_paths[:max_req]:
                url = f"{base}/{path.lstrip('/')}"
                headers = {**req_headers, **auth_headers}

                resp = requests.get(
                    url=url,
                    headers=headers,
                    timeout=timeout_s,
                    allow_redirects=False,
                )

                if resp.status_code != 200:
                    continue

                body = resp.text or ""
                found = [
                    kw for kw in DIRECTORY_LISTING_KEYWORDS
                    if kw.lower() in body.lower()
                ]
                if not found:
                    continue

                note = (
                    f"경로 '{path}'에서 디렉터리 목록 노출 확인. "
                    f"탐지 키워드: {', '.join(found)}"
                )
                vulnerable_evidence.append(
                    Evidence(
                        request={
                            "method": "GET",
                            "url": url,
                            "headers": mask_sensitive(headers),
                        },
                        response_status=resp.status_code,
                        response_headers=dict(resp.headers),
                        response_body_sample=sanitize_response_sample(body),
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

        ended_at = utc_now_iso()
        duration_ms = int((time.time() - start_ts) * 1000)

        # 6) 결과 반환
        if vulnerable_evidence:
            return ToolResult(
                tool_id=self.tool_id,
                tool_name=self.tool_name,
                status=ToolStatus.VULNERABLE.value,
                severity=Severity.HIGH.value,
                confidence=Confidence.HIGH.value,
                title="디렉터리 목록 노출 발견",
                description=f"{len(vulnerable_evidence)}개의 경로에서 디렉터리 목록이 노출되었습니다.",
                owasp=["A02:2025 Security Misconfiguration"],
                cwe=["CWE-548"],
                evidence=vulnerable_evidence,
                recommendation=(
                    "웹 서버 설정에서 디렉터리 목록 기능을 비활성화하세요. "
                    "Apache는 Options -Indexes, Nginx는 autoindex off 설정을 적용하세요."
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
            title="디렉터리 목록 미노출",
            description="점검한 경로에서 디렉터리 목록 노출이 확인되지 않았습니다.",
            evidence=[],
            started_at=started_at,
            ended_at=ended_at,
            duration_ms=duration_ms,
            tool_version=self.tool_version,
        )