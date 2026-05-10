from __future__ import annotations

# extra 옵션 키:
#   "payloads": list[str] — 비정상 입력으로 사용할 페이로드 목록
#                           (기본값: DEFAULT_PAYLOADS)

import requests
import time
from typing import Any, Dict, List

from va_mcp.core import (
    BaseTool,
    ToolInput,
    ToolResult,
    Evidence,
    ToolStatus,
    Severity,
    Confidence,
    ErrorCode,
)
from va_mcp.core.utils import (
    build_tool_error,
    mask_sensitive,
    sanitize_request_body,
    sanitize_response_sample,
    utc_now_iso,
)
from va_mcp.core.resolvers.auth_resolver import (
    parse_credentials,
    resolve_auth_headers,
    CredentialResolverError,
)

DEFAULT_PAYLOADS = [
    "{malformed: json}",
    "A" * 5000,
    "null",
    "<xml>",
]


class MalformedInputTool(BaseTool):
    tool_id = "malformed_input"
    tool_name = "Malformed Input Testing"
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
        opts: Any = tool_input.options
        extra: Dict[str, Any] = opts.extra if opts and opts.extra else {}
        timeout_s = (opts.timeout / 1000.0) if opts and opts.timeout else 5
        max_req = (
            opts.max_requests if opts and opts.max_requests is not None
            else len(DEFAULT_PAYLOADS)
        )
        payloads: List[str] = extra.get("payloads", DEFAULT_PAYLOADS)

        # 3) payloads 유효성
        if not payloads:
            ended_at = utc_now_iso()
            return ToolResult(
                tool_id=self.tool_id,
                tool_name=self.tool_name,
                status=ToolStatus.ERROR.value,
                severity=Severity.INFO.value,
                confidence=Confidence.LOW.value,
                title="입력 오류",
                description="테스트할 payloads 리스트가 비어있습니다.",
                evidence=[],
                errors=[
                    build_tool_error(
                        ErrorCode.INVALID_INPUT.value,
                        "Empty payloads list",
                        retryable=False,
                    )
                ],
                started_at=started_at,
                ended_at=ended_at,
                duration_ms=0,
                tool_version=self.tool_version,
            )

        # 4) URL 안전 조합
        base = tool_input.target.base_url.rstrip("/")
        url = f"{base}/{req.path.lstrip('/')}"
        method = req.method.upper()

        # 5) headers 방어 및 auth_resolver 적용
        orig_headers = req.headers.copy() if req.headers else {}
        orig_headers.setdefault("Content-Type", "application/json")

        auth_ctx = tool_input.auth[0] if tool_input.auth else None
        if auth_ctx:
            try:
                parse_credentials(auth_ctx)
                auth_headers = resolve_auth_headers(auth_ctx)
                headers = {**orig_headers, **auth_headers}
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
            headers = orig_headers

        vulnerable_evidence: List[Evidence] = []

        try:
            # 6) malformed 페이로드 테스트
            for payload in payloads[:max_req]:
                resp = requests.request(
                    method=method,
                    url=url,
                    headers=headers,
                    data=payload,
                    timeout=timeout_s,
                    allow_redirects=False,
                )
                if resp.status_code >= 500:
                    vulnerable_evidence.append(
                        Evidence(
                            request={
                                "method": method,
                                "url": url,
                                "headers": mask_sensitive(headers),
                                "body": sanitize_request_body(payload),
                            },
                            response_status=resp.status_code,
                            response_headers=dict(resp.headers),
                            response_body_sample=sanitize_response_sample(resp.text),
                            note=(
                                "형식에 맞지 않는 입력에 대해 "
                                "5xx 에러(예외 처리 실패)를 반환함"
                            ),
                        )
                    )
                    break

            ended_at = utc_now_iso()
            duration_ms = int((time.time() - start_ts) * 1000)

            # 7) 결과 반환
            if vulnerable_evidence:
                return ToolResult(
                    tool_id=self.tool_id,
                    tool_name=self.tool_name,
                    status=ToolStatus.VULNERABLE.value,
                    severity=Severity.MEDIUM.value,
                    confidence=Confidence.HIGH.value,
                    title="비정상 입력 처리 취약점 발견",
                    description=(
                        "형식에 맞지 않는 입력값을 안전하게 거부(400)하지 못하고 "
                        "내부 에러가 발생합니다."
                    ),
                    owasp=["A10:2025 Mishandling of Exceptional Conditions"],
                    cwe=["CWE-20"],
                    evidence=vulnerable_evidence,
                    recommendation=(
                        "강력한 입력값 검증(Input Validation)을 구현하여 "
                        "400 Bad Request를 반환하도록 처리하세요."
                    ),
                    started_at=started_at,
                    ended_at=ended_at,
                    duration_ms=duration_ms,
                    tool_version=self.tool_version,
                )

            return ToolResult(
                tool_id=self.tool_id,
                tool_name=self.tool_name,
                status=ToolStatus.PASSED.value,
                severity=Severity.INFO.value,
                confidence=Confidence.HIGH.value,
                title="비정상 입력 방어 확인",
                description="서버가 비정상적인 입력값을 올바르게 식별하고 처리합니다.",
                evidence=[],
                started_at=started_at,
                ended_at=ended_at,
                duration_ms=duration_ms,
                tool_version=self.tool_version,
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

        except Exception as e:
            ended_at = utc_now_iso()
            return ToolResult(
                tool_id=self.tool_id,
                tool_name=self.tool_name,
                status=ToolStatus.ERROR.value,
                severity=Severity.INFO.value,
                confidence=Confidence.LOW.value,
                title="도구 실행 오류",
                description=str(e),
                evidence=[],
                errors=[build_tool_error(ErrorCode.INTERNAL_ERROR.value, str(e), retryable=False)],
                started_at=started_at,
                ended_at=ended_at,
                duration_ms=0,
                tool_version=self.tool_version,
            )