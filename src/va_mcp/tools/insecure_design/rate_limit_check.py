"""
Rate Limit Check Tool

대상 엔드포인트에 동일 요청을 반복 전송하여
API Rate Limit(요청 제한) 존재 여부를 확인한다.

OWASP: A06 Insecure Design
CWE:   CWE-770 (Allocation of Resources Without Limits or Throttling)

extra 옵션:
    extra["repeat_count"]  : int  - 반복 요청 횟수 (기본값: 10)
    extra["interval_ms"]   : int  - 요청 간 대기 시간 밀리초 (기본값: 0)
"""

from __future__ import annotations

import time

from va_mcp.core import (
    BaseTool,
    Confidence,
    ErrorCode,
    Evidence,
    Severity,
    ToolInput,
    ToolResult,
    ToolStatus,
)
import requests

from va_mcp.core.utils import (
    build_tool_error,
    mask_sensitive,
    sanitize_request_body,
    sanitize_response_sample,
    utc_now_iso,
)


class RateLimitCheckTool(BaseTool):
    """
    동일 요청을 반복 전송하여 429 응답 여부로 Rate Limit 존재를 판단한다.

    - 429 응답이 오면: PASSED (Rate Limit 존재)
    - 모두 200이면: VULNERABLE (Rate Limit 미존재)
    """

    tool_id = "rate_limit_check"
    tool_name = "API Rate Limit Check"

    def run(self, tool_input: ToolInput) -> ToolResult:
        started_at = utc_now_iso()

        try:
            # ── 입력 검증 ──
            if tool_input.request is None:
                ended_at = utc_now_iso()
                return ToolResult(
                    tool_id=self.tool_id,
                    tool_name=self.tool_name,
                    status=ToolStatus.SKIPPED,
                    severity=Severity.INFO,
                    confidence=Confidence.LOW,
                    title="요청 정보 없음",
                    description="request가 제공되지 않아 검사를 수행할 수 없습니다.",
                    started_at=started_at,
                    ended_at=ended_at,
                )

            # ── extra 옵션 추출 ──
            repeat_count = tool_input.options.extra.get("repeat_count", 10)
            interval_ms = tool_input.options.extra.get("interval_ms", 0)

            # repeat_count 유효성 검증
            if not isinstance(repeat_count, int) or repeat_count < 1:
                ended_at = utc_now_iso()
                return ToolResult(
                    tool_id=self.tool_id,
                    tool_name=self.tool_name,
                    status=ToolStatus.ERROR,
                    severity=Severity.INFO,
                    confidence=Confidence.LOW,
                    title="입력값 오류",
                    description="repeat_count는 1 이상의 정수여야 합니다.",
                    started_at=started_at,
                    ended_at=ended_at,
                    errors=[
                        build_tool_error(
                            error_code=ErrorCode.INVALID_INPUT,
                            error_message=f"repeat_count 값이 유효하지 않습니다: {repeat_count}",
                            retryable=False,
                        )
                    ],
                )

            # max_requests 제한 적용
            actual_count = min(repeat_count, tool_input.options.max_requests)

            if actual_count < 1:
                ended_at = utc_now_iso()
                return ToolResult(
                    tool_id=self.tool_id,
                    tool_name=self.tool_name,
                    status=ToolStatus.ERROR,
                    severity=Severity.INFO,
                    confidence=Confidence.LOW,
                    title="입력값 오류",
                    description="max_requests 또는 repeat_count가 1 미만이어서 검사를 수행할 수 없습니다.",
                    started_at=started_at,
                    ended_at=ended_at,
                    errors=[
                        build_tool_error(
                            error_code=ErrorCode.INVALID_INPUT,
                            error_message=f"actual_count가 0 이하입니다: repeat_count={repeat_count}, max_requests={tool_input.options.max_requests}",
                            retryable=False,
                        )
                    ],
                )

            # ── URL 조립 ──
            base_url = tool_input.target.base_url.rstrip("/")
            path = tool_input.request.path
            url = f"{base_url}{path}"

            method = tool_input.request.method.upper()
            headers = dict(tool_input.request.headers)
            query = dict(tool_input.request.query)
            body = tool_input.request.body
            timeout_sec = tool_input.options.timeout / 1000

            # ── 인증 헤더 주입 ──
            if tool_input.auth:
                auth_ctx = tool_input.auth[0]
                if auth_ctx.auth_type == "bearer" and auth_ctx.token:
                    headers["Authorization"] = f"Bearer {auth_ctx.token}"
                elif auth_ctx.auth_type == "cookie" and auth_ctx.cookie:
                    headers["Cookie"] = auth_ctx.cookie

            # ── 반복 요청 전송 ──
            status_codes: list[int] = []
            rate_limited = False
            rate_limit_evidence: Evidence | None = None

            for i in range(actual_count):
                resp = requests.request(
                    method=method,
                    url=url,
                    headers=headers,
                    params=query,
                    json=body if method in ("POST", "PUT", "PATCH") else None,
                    timeout=timeout_sec,
                )

                status_codes.append(resp.status_code)

                if resp.status_code == 429:
                    rate_limited = True
                    rate_limit_evidence = Evidence(
                        request={
                            "method": method,
                            "url": url,
                            "headers": mask_sensitive(headers),
                            "body": sanitize_request_body(body),
                        },
                        response_status=resp.status_code,
                        response_headers=dict(resp.headers),
                        response_body_sample=sanitize_response_sample(resp.text),
                        note=f"{i + 1}번째 요청에서 429 Too Many Requests 응답 수신",
                    )
                    break

                if interval_ms > 0:
                    time.sleep(interval_ms / 1000)

            # ── 결과 판정 ──
            if rate_limited and rate_limit_evidence is not None:
                ended_at = utc_now_iso()
                return ToolResult(
                    tool_id=self.tool_id,
                    tool_name=self.tool_name,
                    status=ToolStatus.PASSED,
                    severity=Severity.INFO,
                    confidence=Confidence.HIGH,
                    title="Rate Limit 적용됨",
                    description=(
                        f"{len(status_codes)}번째 요청에서 429 응답을 수신하였습니다. "
                        f"API에 Rate Limit이 적용되어 있습니다."
                    ),
                    owasp=["A06 Insecure Design"],
                    cwe=["CWE-770"],
                    evidence=[rate_limit_evidence],
                    recommendation="현재 Rate Limit이 적용되어 있습니다. 주기적으로 임계값의 적절성을 검토하세요.",
                    started_at=started_at,
                    ended_at=ended_at,
                )

            # Rate Limit 미존재 → 취약
            last_resp_evidence = Evidence(
                request={
                    "method": method,
                    "url": url,
                    "headers": mask_sensitive(headers),
                    "body": sanitize_request_body(body),
                },
                response_status=resp.status_code,
                response_headers=dict(resp.headers),
                response_body_sample=sanitize_response_sample(resp.text),
                note=(
                    f"{actual_count}회 반복 요청 후에도 429 응답 없음. "
                    f"응답 코드 분포: {dict(_count_codes(status_codes))}"
                ),
            )

            ended_at = utc_now_iso()
            return ToolResult(
                tool_id=self.tool_id,
                tool_name=self.tool_name,
                status=ToolStatus.VULNERABLE,
                severity=Severity.MEDIUM,
                confidence=Confidence.MEDIUM,
                title="Rate Limit 미적용",
                description=(
                    f"{actual_count}회 동일 요청을 반복했으나 429 응답이 발생하지 않았습니다. "
                    f"API에 Rate Limit이 설정되지 않았을 가능성이 있습니다."
                ),
                owasp=["A06 Insecure Design"],
                cwe=["CWE-770"],
                evidence=[last_resp_evidence],
                recommendation=(
                    "API 엔드포인트에 Rate Limit을 적용하세요. "
                    "예: 분당 최대 요청 수 제한, 429 Too Many Requests 응답 반환."
                ),
                started_at=started_at,
                ended_at=ended_at,
            )

        except requests.exceptions.Timeout as exc:
            ended_at = utc_now_iso()
            return ToolResult(
                tool_id=self.tool_id,
                tool_name=self.tool_name,
                status=ToolStatus.ERROR,
                severity=Severity.INFO,
                confidence=Confidence.LOW,
                title="요청 시간 초과",
                description="대상 서버로의 요청이 시간 초과되었습니다.",
                started_at=started_at,
                ended_at=ended_at,
                errors=[
                    build_tool_error(
                        error_code=ErrorCode.TIMEOUT,
                        error_message=str(exc),
                        retryable=True,
                    )
                ],
            )

        except requests.exceptions.RequestException as exc:
            ended_at = utc_now_iso()
            return ToolResult(
                tool_id=self.tool_id,
                tool_name=self.tool_name,
                status=ToolStatus.ERROR,
                severity=Severity.INFO,
                confidence=Confidence.LOW,
                title="HTTP 요청 실패",
                description="대상 서버로의 HTTP 요청이 실패했습니다.",
                started_at=started_at,
                ended_at=ended_at,
                errors=[
                    build_tool_error(
                        error_code=ErrorCode.HTTP_FAILURE,
                        error_message=str(exc),
                        retryable=True,
                    )
                ],
            )

        except Exception as exc:
            ended_at = utc_now_iso()
            return ToolResult(
                tool_id=self.tool_id,
                tool_name=self.tool_name,
                status=ToolStatus.ERROR,
                severity=Severity.INFO,
                confidence=Confidence.LOW,
                title="실행 오류",
                description="예상치 못한 오류가 발생했습니다.",
                started_at=started_at,
                ended_at=ended_at,
                errors=[
                    build_tool_error(
                        error_code=ErrorCode.INTERNAL_ERROR,
                        error_message=str(exc),
                        retryable=False,
                    )
                ],
            )


def _count_codes(codes: list[int]) -> list[tuple[int, int]]:
    """상태 코드별 등장 횟수를 반환한다."""
    counter: dict[int, int] = {}
    for code in codes:
        counter[code] = counter.get(code, 0) + 1
    return sorted(counter.items())
