"""
Resource Exhaustion Check Tool

비정상적으로 큰 입력값을 전송하여
서버가 요청 크기를 제한하고 있는지 확인한다.

OWASP: A04 Insecure Design
CWE:   CWE-400 (Uncontrolled Resource Consumption)

extra 옵션:
    extra["payload_size"]   : int  - 페이로드 문자열 크기 (기본값: 100000)
    extra["test_field"]     : str  - 큰 값을 넣을 필드명 (기본값: "data")
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


class ResourceExhaustionTool(BaseTool):
    """
    비정상적으로 큰 페이로드를 전송하여 서버의 요청 크기 제한 여부를 확인한다.

    - 413 응답이 오면: PASSED (크기 제한 존재)
    - 200 응답이면: VULNERABLE (크기 제한 미존재)
    - 500 또는 타임아웃이면: VULNERABLE (서버 과부하 가능성)
    """

    tool_id = "resource_exhaustion"
    tool_name = "Resource Exhaustion Check"

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
                    description="Resource Exhaustion 검사는 POST, PUT, PATCH 메서드에만 적용됩니다.",
                    started_at=started_at,
                    ended_at=ended_at,
                )

            # ── extra 옵션 추출 ──
            payload_size = tool_input.options.extra.get("payload_size", 100000)
            test_field = tool_input.options.extra.get("test_field", "data")

            if not isinstance(payload_size, int) or payload_size < 1:
                ended_at = utc_now_iso()
                return ToolResult(
                    tool_id=self.tool_id,
                    tool_name=self.tool_name,
                    status=ToolStatus.ERROR,
                    severity=Severity.INFO,
                    confidence=Confidence.LOW,
                    title="입력값 오류",
                    description="payload_size는 1 이상의 정수여야 합니다.",
                    started_at=started_at,
                    ended_at=ended_at,
                    errors=[
                        build_tool_error(
                            error_code=ErrorCode.INVALID_INPUT,
                            error_message=f"payload_size 값이 유효하지 않습니다: {payload_size}",
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

            # ── 대형 페이로드 생성 ──
            original_body = dict(tool_input.request.body) if tool_input.request.body else {}
            large_body = {**original_body, test_field: "A" * payload_size}

            # ── 요청 전송 ──
            resp = requests.request(
                method=method,
                url=url,
                headers=headers,
                json=large_body,
                timeout=timeout_sec,
            )

            # ── 결과 판정 ──
            evidence = Evidence(
                request={
                    "method": method,
                    "url": url,
                    "headers": mask_sensitive(headers),
                    "body": sanitize_request_body(
                        {**original_body, test_field: f"'A' * {payload_size} ({payload_size} chars)"}
                    ),
                },
                response_status=resp.status_code,
                response_headers=dict(resp.headers),
                response_body_sample=sanitize_response_sample(resp.text),
                note="",
            )

            if resp.status_code == 413:
                evidence.note = "413 Payload Too Large 응답 수신. 서버가 요청 크기를 제한하고 있음."
                ended_at = utc_now_iso()
                return ToolResult(
                    tool_id=self.tool_id,
                    tool_name=self.tool_name,
                    status=ToolStatus.PASSED,
                    severity=Severity.INFO,
                    confidence=Confidence.HIGH,
                    title="요청 크기 제한 적용됨",
                    description=(
                        f"{payload_size}자 크기의 페이로드 전송 시 413 응답을 수신하였습니다. "
                        f"서버에 요청 크기 제한이 적용되어 있습니다."
                    ),
                    owasp=["A04 Insecure Design"],
                    cwe=["CWE-400"],
                    evidence=[evidence],
                    recommendation="현재 요청 크기 제한이 적용되어 있습니다. 주기적으로 임계값의 적절성을 검토하세요.",
                    started_at=started_at,
                    ended_at=ended_at,
                )

            if resp.status_code >= 500:
                evidence.note = (
                    f"{resp.status_code} 서버 오류 응답. "
                    f"대형 페이로드로 인해 서버 과부하가 발생했을 가능성이 있음."
                )
                ended_at = utc_now_iso()
                return ToolResult(
                    tool_id=self.tool_id,
                    tool_name=self.tool_name,
                    status=ToolStatus.VULNERABLE,
                    severity=Severity.HIGH,
                    confidence=Confidence.MEDIUM,
                    title="대형 페이로드로 서버 오류 발생",
                    description=(
                        f"{payload_size}자 크기의 페이로드 전송 시 {resp.status_code} 오류가 발생했습니다. "
                        f"서버가 대형 요청을 적절히 처리하지 못하고 있습니다."
                    ),
                    owasp=["A04 Insecure Design"],
                    cwe=["CWE-400"],
                    evidence=[evidence],
                    recommendation=(
                        "서버에 요청 크기 제한을 적용하세요. "
                        "예: Nginx client_max_body_size, Express body-parser limit 설정."
                    ),
                    started_at=started_at,
                    ended_at=ended_at,
                )

            # 200 등 정상 응답 → 크기 제한 없음
            evidence.note = (
                f"{payload_size}자 페이로드가 {resp.status_code} 응답으로 정상 처리됨. "
                f"요청 크기 제한이 설정되지 않았을 가능성이 있음."
            )
            ended_at = utc_now_iso()
            return ToolResult(
                tool_id=self.tool_id,
                tool_name=self.tool_name,
                status=ToolStatus.VULNERABLE,
                severity=Severity.MEDIUM,
                confidence=Confidence.MEDIUM,
                title="요청 크기 제한 미적용",
                description=(
                    f"{payload_size}자 크기의 대형 페이로드가 거부되지 않고 처리되었습니다. "
                    f"서버에 요청 크기 제한이 설정되지 않았을 가능성이 있습니다."
                ),
                owasp=["A04 Insecure Design"],
                cwe=["CWE-400"],
                evidence=[evidence],
                recommendation=(
                    "서버에 요청 크기 제한을 적용하세요. "
                    "예: Nginx client_max_body_size, Express body-parser limit 설정."
                ),
                started_at=started_at,
                ended_at=ended_at,
            )

        except requests.exceptions.Timeout as exc:
            ended_at = utc_now_iso()
            return ToolResult(
                tool_id=self.tool_id,
                tool_name=self.tool_name,
                status=ToolStatus.VULNERABLE,
                severity=Severity.MEDIUM,
                confidence=Confidence.MEDIUM,
                title="대형 페이로드로 타임아웃 발생",
                description=(
                    "대형 페이로드 전송 시 서버가 시간 내에 응답하지 못했습니다. "
                    "리소스 고갈 공격에 취약할 가능성이 있습니다."
                ),
                owasp=["A04 Insecure Design"],
                cwe=["CWE-400"],
                evidence=[
                    Evidence(
                        request={
                            "method": method,
                            "url": url,
                            "headers": mask_sensitive(headers),
                            "body": sanitize_request_body(
                                {test_field: f"'A' * {payload_size} ({payload_size} chars)"}
                            ),
                        },
                        response_status=0,
                        response_headers={},
                        response_body_sample="",
                        note=f"타임아웃 발생: {exc}",
                    )
                ],
                recommendation=(
                    "서버에 요청 크기 제한과 처리 시간 제한을 적용하세요."
                ),
                started_at=started_at,
                ended_at=ended_at,
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
