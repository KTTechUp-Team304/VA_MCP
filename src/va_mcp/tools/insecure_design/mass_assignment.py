"""
Mass Assignment Check Tool

요청 바디에 권한 관련 필드(role, is_admin 등)를 추가하여
서버가 의도하지 않은 필드까지 반영하는지 확인한다.

OWASP: A04 Insecure Design
CWE:   CWE-915 (Improperly Controlled Modification of Dynamically-Determined Object Attributes)

extra 옵션:
    extra["inject_fields"]  : dict  - 주입할 필드 (기본값: {"role": "admin", "is_admin": True})
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

# 주입 필드가 반영되었는지 확인할 기본 키 목록
DEFAULT_INJECT_FIELDS: dict[str, object] = {
    "role": "admin",
    "is_admin": True,
    "isAdmin": True,
    "admin": True,
    "permissions": "all",
}


class MassAssignmentTool(BaseTool):
    """
    요청에 권한 필드를 추가 전송하여 서버가 이를 반영하는지 확인한다.

    1단계: 원본 요청 전송 → 정상 응답 확보
    2단계: 권한 필드 추가 요청 전송
    3단계: 응답 비교 → 추가 필드가 반영되었으면 VULNERABLE
    """

    tool_id = "mass_assignment"
    tool_name = "Mass Assignment Check"

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
                    description="Mass Assignment 검사는 POST, PUT, PATCH 메서드에만 적용됩니다.",
                    started_at=started_at,
                    ended_at=ended_at,
                )

            # ── extra 옵션 추출 ──
            inject_fields = tool_input.options.extra.get(
                "inject_fields", DEFAULT_INJECT_FIELDS
            )

            if not isinstance(inject_fields, dict) or len(inject_fields) == 0:
                ended_at = utc_now_iso()
                return ToolResult(
                    tool_id=self.tool_id,
                    tool_name=self.tool_name,
                    status=ToolStatus.ERROR,
                    severity=Severity.INFO,
                    confidence=Confidence.LOW,
                    title="입력값 오류",
                    description="inject_fields는 1개 이상의 키를 가진 dict여야 합니다.",
                    started_at=started_at,
                    ended_at=ended_at,
                    errors=[
                        build_tool_error(
                            error_code=ErrorCode.INVALID_INPUT,
                            error_message=f"inject_fields 값이 유효하지 않습니다: {type(inject_fields).__name__}",
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
            original_body = dict(tool_input.request.body) if tool_input.request.body else {}
            timeout_sec = tool_input.options.timeout / 1000

            # ── 인증 헤더 주입 ──
            if tool_input.auth:
                auth_ctx = tool_input.auth[0]
                if auth_ctx.auth_type == "bearer" and auth_ctx.token:
                    headers["Authorization"] = f"Bearer {auth_ctx.token}"
                elif auth_ctx.auth_type == "cookie" and auth_ctx.cookie:
                    headers["Cookie"] = auth_ctx.cookie

            # ── 1단계: 원본 요청 ──
            original_resp = requests.request(
                method=method,
                url=url,
                headers=headers,
                json=original_body,
                timeout=timeout_sec,
            )

            # ── 2단계: 권한 필드 추가 요청 ──
            injected_body = {**original_body, **inject_fields}

            injected_resp = requests.request(
                method=method,
                url=url,
                headers=headers,
                json=injected_body,
                timeout=timeout_sec,
            )

            # ── 3단계: 응답 비교 ──
            reflected_fields = _detect_reflected_fields(
                inject_fields, injected_resp.text
            )

            if reflected_fields:
                ended_at = utc_now_iso()
                return ToolResult(
                    tool_id=self.tool_id,
                    tool_name=self.tool_name,
                    status=ToolStatus.VULNERABLE,
                    severity=Severity.HIGH,
                    confidence=Confidence.HIGH,
                    title="Mass Assignment 취약점 발견",
                    description=(
                        f"주입한 필드 중 {reflected_fields}가 응답에 반영되었습니다. "
                        f"서버가 허용되지 않은 필드를 처리하고 있을 가능성이 있습니다."
                    ),
                    owasp=["A04 Insecure Design"],
                    cwe=["CWE-915"],
                    evidence=[
                        Evidence(
                            request={
                                "method": method,
                                "url": url,
                                "headers": mask_sensitive(headers),
                                "body": sanitize_request_body(injected_body),
                            },
                            response_status=injected_resp.status_code,
                            response_headers=dict(injected_resp.headers),
                            response_body_sample=sanitize_response_sample(injected_resp.text),
                            note=f"주입 필드 반영 감지: {reflected_fields}",
                        )
                    ],
                    recommendation=(
                        "서버에서 허용된 필드만 명시적으로 바인딩하세요 (allowlist 방식). "
                        "예: DTO에 허용 필드만 정의하고, 나머지는 무시하도록 설정."
                    ),
                    started_at=started_at,
                    ended_at=ended_at,
                )

            # 반영 안 됨 → 안전
            ended_at = utc_now_iso()
            return ToolResult(
                tool_id=self.tool_id,
                tool_name=self.tool_name,
                status=ToolStatus.PASSED,
                severity=Severity.INFO,
                confidence=Confidence.MEDIUM,
                title="Mass Assignment 취약점 미발견",
                description=(
                    f"주입한 필드({list(inject_fields.keys())})가 응답에 반영되지 않았습니다."
                ),
                owasp=["A04 Insecure Design"],
                cwe=["CWE-915"],
                evidence=[
                    Evidence(
                        request={
                            "method": method,
                            "url": url,
                            "headers": mask_sensitive(headers),
                            "body": sanitize_request_body(injected_body),
                        },
                        response_status=injected_resp.status_code,
                        response_headers={},
                        response_body_sample=sanitize_response_sample(injected_resp.text),
                        note="주입 필드가 응답에 반영되지 않음",
                    )
                ],
                recommendation="현재 허용되지 않은 필드가 차단되고 있습니다. 주기적으로 바인딩 정책을 검토하세요.",
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


def _detect_reflected_fields(
    inject_fields: dict[str, object],
    response_text: str,
) -> list[str]:
    """주입한 필드의 키가 응답 본문에 존재하는지 확인한다."""
    reflected: list[str] = []
    lower_resp = response_text.lower()
    for key in inject_fields:
        if key.lower() in lower_resp:
            reflected.append(key)
    return reflected
