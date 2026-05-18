"""
Business Logic Check Tool

지정 필드에 비정상 값(음수, 0, 극단값 등)을 전송하여
서버가 비즈니스 로직 수준의 값 검증을 수행하는지 확인한다.

OWASP: A06 Insecure Design
CWE:   CWE-840 (Business Logic Errors)

extra 옵션:
    extra["test_field"]     : str       - 비정상 값을 주입할 필드명 (기본값: "amount")
    extra["invalid_values"] : list[int|float] - 테스트할 비정상 값 목록
                                               (기본값: [-1, 0, -9999])
"""

from __future__ import annotations

import requests
import time
from typing import Any, Dict, List

from va_mcp.core.base import BaseTool
from va_mcp.core.schemas import ToolInput, ToolResult, Evidence, AuthContext
from va_mcp.core.constants import ToolStatus, Severity, Confidence, ErrorCode
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


class BusinessLogicCheckTool(BaseTool):
    """
    비정상 값을 전송하여 서버의 비즈니스 로직 값 검증 여부를 확인한다.

    - 모든 비정상 값에 400/422 응답: PASSED (값 검증 존재)
    - 비정상 값이 200으로 수락됨:    VULNERABLE (값 검증 미존재)
    """
    tool_id = "business_logic_check"
    tool_name = "Business Logic Check"
    tool_version = "0.1.0"

    def run(self, tool_input: ToolInput) -> ToolResult:
        start_ts   = time.time()
        started_at = utc_now_iso()

        # 1) request 방어
        req = tool_input.request
        if not req:
            ended_at   = utc_now_iso()
            duration_ms = int((time.time() - start_ts) * 1000)
            return ToolResult(
                tool_id=self.tool_id,
                tool_name=self.tool_name,
                status=ToolStatus.SKIPPED.value,
                severity=Severity.INFO.value,
                confidence=Confidence.LOW.value,
                title="요청 정보 없음",
                description="request가 제공되지 않아 검사를 수행할 수 없습니다.",
                evidence=[],
                started_at=started_at,
                ended_at=ended_at,
                duration_ms=duration_ms,
                tool_version=self.tool_version,
            )

        # 2) method 방어
        method = req.method.upper()
        if method not in ("POST", "PUT", "PATCH"):
            ended_at   = utc_now_iso()
            duration_ms = int((time.time() - start_ts) * 1000)
            return ToolResult(
                tool_id=self.tool_id,
                tool_name=self.tool_name,
                status=ToolStatus.SKIPPED.value,
                severity=Severity.INFO.value,
                confidence=Confidence.LOW.value,
                title="검사 대상 아님",
                description="Business Logic Check는 POST, PUT, PATCH 메서드에만 적용됩니다.",
                evidence=[],
                started_at=started_at,
                ended_at=ended_at,
                duration_ms=duration_ms,
                tool_version=self.tool_version,
            )

        # 3) safe_mode 방어
        opts: Any = tool_input.options
        safe_mode = getattr(opts, "safe_mode", False)
        if safe_mode:
            ended_at   = utc_now_iso()
            duration_ms = int((time.time() - start_ts) * 1000)
            return ToolResult(
                tool_id=self.tool_id,
                tool_name=self.tool_name,
                status=ToolStatus.SKIPPED.value,
                severity=Severity.INFO.value,
                confidence=Confidence.LOW.value,
                title="Safe Mode 활성화",
                description="safe_mode=True 상태에서는 비정상 값 전송을 수행하지 않습니다.",
                evidence=[],
                started_at=started_at,
                ended_at=ended_at,
                duration_ms=duration_ms,
                tool_version=self.tool_version,
            )

        # 4) options/extra 방어
        extra: Dict[str, Any] = opts.extra if opts and opts.extra else {}
        timeout_s = (opts.timeout / 1000.0) if opts and opts.timeout else 5

        test_field = extra.get("test_field", "amount")
        invalid_values = extra.get("invalid_values", [-1, 0, -9999])

        # 5) invalid_values 검증
        if not isinstance(invalid_values, list) or not invalid_values:
            ended_at   = utc_now_iso()
            duration_ms = int((time.time() - start_ts) * 1000)
            return ToolResult(
                tool_id=self.tool_id,
                tool_name=self.tool_name,
                status=ToolStatus.ERROR.value,
                severity=Severity.INFO.value,
                confidence=Confidence.LOW.value,
                title="입력값 오류",
                description="invalid_values는 1개 이상의 값을 포함하는 리스트여야 합니다.",
                evidence=[],
                errors=[build_tool_error(
                    ErrorCode.INVALID_INPUT.value,
                    f"invalid_values 값이 유효하지 않습니다: {invalid_values!r}",
                    retryable=False,
                )],
                started_at=started_at,
                ended_at=ended_at,
                duration_ms=duration_ms,
                tool_version=self.tool_version,
            )

        # 6) test_field 검증
        if not isinstance(test_field, str) or not test_field.strip():
            ended_at   = utc_now_iso()
            duration_ms = int((time.time() - start_ts) * 1000)
            return ToolResult(
                tool_id=self.tool_id,
                tool_name=self.tool_name,
                status=ToolStatus.ERROR.value,
                severity=Severity.INFO.value,
                confidence=Confidence.LOW.value,
                title="입력값 오류",
                description="test_field는 비어 있지 않은 문자열이어야 합니다.",
                evidence=[],
                errors=[build_tool_error(
                    ErrorCode.INVALID_INPUT.value,
                    f"test_field 값이 유효하지 않습니다: {test_field!r}",
                    retryable=False,
                )],
                started_at=started_at,
                ended_at=ended_at,
                duration_ms=duration_ms,
                tool_version=self.tool_version,
            )

        # 7) URL 안전 조합
        base = tool_input.target.base_url.rstrip("/")
        path = req.path.lstrip("/")
        url  = f"{base}/{path}"

        headers = req.headers.copy() if req.headers else {}

        # 8) auth_resolver로 인증 헤더 처리
        auth_ctx: AuthContext | None = tool_input.auth[0] if tool_input.auth else None
        if auth_ctx:
            try:
                parse_credentials(auth_ctx)
                auth_headers = resolve_auth_headers(auth_ctx)
                headers = {**headers, **auth_headers}
            except CredentialResolverError as e:
                ended_at   = utc_now_iso()
                duration_ms = int((time.time() - start_ts) * 1000)
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
                    duration_ms=duration_ms,
                    tool_version=self.tool_version,
                )

        # 9) 원본 body 복사
        orig_body = req.body.copy() if req.body else {}

        accepted: List[Evidence] = []
        rejected: List[Evidence] = []

        try:
            # 10) 원본 요청 전송 (비교 기준)
            orig_resp = requests.request(
                req.method.upper(),
                url,
                headers=headers,
                json=orig_body,
                timeout=timeout_s,
                allow_redirects=False,
            )
            orig_text = orig_resp.text.strip()

            # 11) 비정상 값 순차 전송
            for invalid in invalid_values:
                if req.method.upper() in ("POST", "PUT", "PATCH"):
                    test_body = {**orig_body, test_field: invalid}
                    resp = requests.request(
                        req.method.upper(),
                        url,
                        headers=headers,
                        json=test_body,
                        timeout=timeout_s,
                        allow_redirects=False,
                    )
                    req_info = {
                        "method": req.method.upper(),
                        "url": url,
                        "headers": mask_sensitive(headers),
                        "body": sanitize_request_body(test_body),
                    }
                else:
                    # GET 등은 비정상 body 검사 대상 아님
                    break

                # 주입 후 응답이 원본과 달라졌을 때만 수락으로 판정
                response_changed = resp.text.strip() != orig_text

                evidence = Evidence(
                    request=req_info,
                    response_status=resp.status_code,
                    response_headers=dict(resp.headers),
                    response_body_sample=sanitize_response_sample(resp.text),
                    note=(
                        f"필드 '{test_field}'에 비정상 값 {invalid!r} 전송 → "
                        f"응답 코드: {resp.status_code}, "
                        f"응답 변화: {'있음' if response_changed else '없음'}"
                    ),
                )

                if 200 <= resp.status_code < 300 and response_changed:
                    accepted.append(evidence)
                else:
                    rejected.append(evidence)

            ended_at   = utc_now_iso()
            duration_ms = int((time.time() - start_ts) * 1000)

            # 11) 결과 판정
            if accepted:
                return ToolResult(
                    tool_id=self.tool_id,
                    tool_name=self.tool_name,
                    status=ToolStatus.VULNERABLE.value,
                    severity=Severity.HIGH.value,
                    confidence=Confidence.HIGH.value,
                    title="비즈니스 로직 값 검증 미흡",
                    description=(
                        f"필드 '{test_field}'에 비정상 값을 전송하였으나 "
                        f"{len(accepted)}/{len(invalid_values)}건이 수락되었습니다."
                    ),
                    owasp=["A06 Insecure Design"],
                    cwe=["CWE-840"],
                    evidence=accepted,
                    recommendation=(
                        f"'{test_field}' 필드에 대한 서버 측 비즈니스 로직 유효성 검사를 강화하세요."
                    ),
                    started_at=started_at,
                    ended_at=ended_at,
                    duration_ms=duration_ms,
                    tool_version=self.tool_version,
                )

            # PASSED: 모두 거부
            return ToolResult(
                tool_id=self.tool_id,
                tool_name=self.tool_name,
                status=ToolStatus.PASSED.value,
                severity=Severity.INFO.value,
                confidence=Confidence.HIGH.value,
                title="비즈니스 로직 값 검증 적용됨",
                description=(
                    f"필드 '{test_field}'에 전송된 모든 비정상 값 "
                    f"({len(invalid_values)}건)이 2xx 외 응답으로 거부되었습니다."
                ),
                owasp=["A06 Insecure Design"],
                cwe=["CWE-840"],
                evidence=rejected,
                started_at=started_at,
                ended_at=ended_at,
                duration_ms=duration_ms,
                tool_version=self.tool_version,
            )

        except requests.Timeout as exc:
            ended_at = utc_now_iso()
            return ToolResult(
                tool_id=self.tool_id,
                tool_name=self.tool_name,
                status=ToolStatus.ERROR.value,
                severity=Severity.INFO.value,
                confidence=Confidence.LOW.value,
                title="요청 시간 초과",
                description=str(exc),
                evidence=[],
                errors=[build_tool_error(
                    ErrorCode.TIMEOUT.value, str(exc), retryable=True
                )],
                started_at=started_at,
                ended_at=ended_at,
                duration_ms=0,
                tool_version=self.tool_version,
            )
        except requests.RequestException as exc:
            ended_at = utc_now_iso()
            return ToolResult(
                tool_id=self.tool_id,
                tool_name=self.tool_name,
                status=ToolStatus.ERROR.value,
                severity=Severity.INFO.value,
                confidence=Confidence.LOW.value,
                title="HTTP 요청 실패",
                description=str(exc),
                evidence=[],
                errors=[build_tool_error(
                    ErrorCode.HTTP_FAILURE.value, str(exc), retryable=True
                )],
                started_at=started_at,
                ended_at=ended_at,
                duration_ms=0,
                tool_version=self.tool_version,
            )
        except Exception as exc:
            ended_at = utc_now_iso()
            return ToolResult(
                tool_id=self.tool_id,
                tool_name=self.tool_name,
                status=ToolStatus.ERROR.value,
                severity=Severity.INFO.value,
                confidence=Confidence.LOW.value,
                title="실행 오류",
                description=str(exc),
                evidence=[],
                errors=[build_tool_error(
                    ErrorCode.INTERNAL_ERROR.value, str(exc), retryable=False
                )],
                started_at=started_at,
                ended_at=ended_at,
                duration_ms=0,
                tool_version=self.tool_version,
            )