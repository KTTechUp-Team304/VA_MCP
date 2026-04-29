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


class BusinessLogicCheckTool(BaseTool):
    """
    비정상 값을 전송하여 서버의 비즈니스 로직 값 검증 여부를 확인한다.

    - 모든 비정상 값에 400/422 응답: PASSED (값 검증 존재)
    - 비정상 값이 200으로 수락됨:    VULNERABLE (값 검증 미존재)
    """

    tool_id = "business_logic_check"
    tool_name = "Business Logic Check"

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

            if tool_input.request.method.upper() not in ("POST", "PUT", "PATCH"):
                ended_at = utc_now_iso()
                return ToolResult(
                    tool_id=self.tool_id,
                    tool_name=self.tool_name,
                    status=ToolStatus.SKIPPED,
                    severity=Severity.INFO,
                    confidence=Confidence.LOW,
                    title="검사 대상 아님",
                    description="Business Logic Check는 POST, PUT, PATCH 메서드에만 적용됩니다.",
                    started_at=started_at,
                    ended_at=ended_at,
                )

            # ── extra 옵션 추출 ──
            test_field = tool_input.options.extra.get("test_field", "amount")
            invalid_values = tool_input.options.extra.get("invalid_values", [-1, 0, -9999])

            if not isinstance(invalid_values, list) or len(invalid_values) == 0:
                ended_at = utc_now_iso()
                return ToolResult(
                    tool_id=self.tool_id,
                    tool_name=self.tool_name,
                    status=ToolStatus.ERROR,
                    severity=Severity.INFO,
                    confidence=Confidence.LOW,
                    title="입력값 오류",
                    description="invalid_values는 1개 이상의 값을 포함하는 리스트여야 합니다.",
                    started_at=started_at,
                    ended_at=ended_at,
                    errors=[
                        build_tool_error(
                            error_code=ErrorCode.INVALID_INPUT,
                            error_message=f"invalid_values 값이 유효하지 않습니다: {invalid_values}",
                            retryable=False,
                        )
                    ],
                )

            if not isinstance(test_field, str) or not test_field.strip():
                ended_at = utc_now_iso()
                return ToolResult(
                    tool_id=self.tool_id,
                    tool_name=self.tool_name,
                    status=ToolStatus.ERROR,
                    severity=Severity.INFO,
                    confidence=Confidence.LOW,
                    title="입력값 오류",
                    description="test_field는 비어 있지 않은 문자열이어야 합니다.",
                    started_at=started_at,
                    ended_at=ended_at,
                    errors=[
                        build_tool_error(
                            error_code=ErrorCode.INVALID_INPUT,
                            error_message=f"test_field 값이 유효하지 않습니다: {test_field!r}",
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
            timeout_sec = tool_input.options.timeout / 1000

            # ── 인증 헤더 주입 ──
            if tool_input.auth:
                auth_ctx = tool_input.auth[0]
                if auth_ctx.auth_type == "bearer" and auth_ctx.token:
                    headers["Authorization"] = f"Bearer {auth_ctx.token}"
                elif auth_ctx.auth_type == "cookie" and auth_ctx.cookie:
                    headers["Cookie"] = auth_ctx.cookie

            original_body = dict(tool_input.request.body) if tool_input.request.body else {}

            # ── 비정상 값 순차 전송 ──
            accepted_evidences: list[Evidence] = []
            rejected_evidences: list[Evidence] = []

            for invalid_val in invalid_values:
                test_body = {**original_body, test_field: invalid_val}

                resp = requests.request(
                    method=method,
                    url=url,
                    headers=headers,
                    json=test_body,
                    timeout=timeout_sec,
                )

                evidence = Evidence(
                    request={
                        "method": method,
                        "url": url,
                        "headers": mask_sensitive(headers),
                        "body": sanitize_request_body(test_body),
                    },
                    response_status=resp.status_code,
                    response_headers=dict(resp.headers),
                    response_body_sample=sanitize_response_sample(resp.text),
                    note=(
                        f"필드 '{test_field}'에 비정상 값 {invalid_val!r} 전송 → "
                        f"응답 코드: {resp.status_code}"
                    ),
                )

                if resp.status_code in (400, 422):
                    rejected_evidences.append(evidence)
                else:
                    accepted_evidences.append(evidence)

            # ── 결과 판정 ──
            if accepted_evidences:
                ended_at = utc_now_iso()
                return ToolResult(
                    tool_id=self.tool_id,
                    tool_name=self.tool_name,
                    status=ToolStatus.VULNERABLE,
                    severity=Severity.HIGH,
                    confidence=Confidence.HIGH,
                    title="비즈니스 로직 값 검증 미흡",
                    description=(
                        f"필드 '{test_field}'에 비정상 값을 전송하였으나 서버가 이를 수락하였습니다. "
                        f"({len(accepted_evidences)}/{len(invalid_values)}건 수락) "
                        f"비즈니스 로직 수준의 값 검증이 부재하거나 불완전합니다."
                    ),
                    owasp=["A06 Insecure Design"],
                    cwe=["CWE-840"],
                    evidence=accepted_evidences,
                    recommendation=(
                        f"'{test_field}' 필드에 대해 서버 측 비즈니스 로직 유효성 검사를 추가하세요. "
                        "예: 음수 불가, 최소/최대 범위 제한 등. "
                        "클라이언트 측 검증만으로는 충분하지 않습니다."
                    ),
                    started_at=started_at,
                    ended_at=ended_at,
                )

            ended_at = utc_now_iso()
            return ToolResult(
                tool_id=self.tool_id,
                tool_name=self.tool_name,
                status=ToolStatus.PASSED,
                severity=Severity.INFO,
                confidence=Confidence.HIGH,
                title="비즈니스 로직 값 검증 적용됨",
                description=(
                    f"필드 '{test_field}'에 비정상 값을 전송하였으며, "
                    f"모든 요청({len(invalid_values)}건)이 400/422로 거부되었습니다. "
                    f"서버에 비즈니스 로직 값 검증이 적용되어 있습니다."
                ),
                owasp=["A06 Insecure Design"],
                cwe=["CWE-840"],
                evidence=rejected_evidences,
                recommendation="현재 값 검증이 적용되어 있습니다. 검증 범위와 오류 메시지 노출 수준을 주기적으로 검토하세요.",
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
