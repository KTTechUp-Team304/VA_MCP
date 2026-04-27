import requests
from datetime import datetime

from va_mcp.core.base import BaseTool
from va_mcp.core.schemas import ToolInput, ToolResult, Evidence
from va_mcp.core.utils import (
    utc_now_iso,
    sanitize_response_sample,
    mask_sensitive,
    build_tool_error,
)
from va_mcp.core.constants import ToolStatus, Severity, Confidence, ErrorCode


class JwtValidationTool(BaseTool):
    tool_id = "auth_jwt"
    tool_name = "JWT Validation Testing"

    def run(self, tool_input: ToolInput) -> ToolResult:
        started_at = utc_now_iso()

        # 1) 입력 검증
        if not tool_input.request or not tool_input.auth:
            return ToolResult(
                tool_id=self.tool_id,
                tool_name=self.tool_name,
                status=ToolStatus.SKIPPED.value,
                severity=Severity.INFO.value,
                confidence=Confidence.LOW.value,
                title="입력 부족",
                description="request 또는 auth 정보가 없습니다.",
                started_at=started_at,
                ended_at=started_at,
                duration_ms=0,
                evidence=[],
            )

        try:
            # 2) JWT 토큰 획득 및 변조
            token = tool_input.auth[0].token or ""
            if not token:
                raise ValueError("JWT 토큰이 비어 있습니다")

            tampered = token[:-1] + "X"
            url = tool_input.target.base_url + tool_input.request.path

            # 3) 정상 토큰 / 변조 토큰 요청 (timeout 적용)
            timeout_s = tool_input.options.timeout / 1000
            headers_valid = {"Authorization": f"Bearer {token}"}
            headers_tampered = {"Authorization": f"Bearer {tampered}"}

            res_valid = requests.request(
                method=tool_input.request.method,
                url=url,
                headers=headers_valid,
                timeout=timeout_s,
            )
            res_tampered = requests.request(
                method=tool_input.request.method,
                url=url,
                headers=headers_tampered,
                timeout=timeout_s,
            )

            # 4) 취약 여부 판단
            vulnerable = (res_valid.status_code == 200 and res_tampered.status_code == 200)

            # 5) ToolResult 필드 설정
            if vulnerable:
                status = ToolStatus.VULNERABLE.value
                severity = Severity.HIGH.value
                title = "JWT 검증 실패"
                description = "변조된 토큰이 허용됩니다."
                owasp = ["A02 Cryptographic Failures"]
                cwe = ["CWE-347"]
                recommendation = "서버에서 JWT 서명 및 유효성 검증을 반드시 수행하세요."
            else:
                status = ToolStatus.PASSED.value
                severity = Severity.INFO.value    # PASSED → INFO
                title = "JWT 검증 정상"
                description = "변조된 토큰이 차단됩니다."
                owasp = ["A02 Cryptographic Failures"]
                cwe = ["CWE-347"]
                recommendation = "변조 토큰이 차단되는지 확인되었습니다."

            ended_at = utc_now_iso()

            # 6) 증거 생성 (변조 토큰에 대한 샘플)
            evidence = [
                Evidence(
                    request={
                        "method": tool_input.request.method,
                        "path": tool_input.request.path,
                        "headers": mask_sensitive(headers_tampered),
                    },
                    response_status=res_tampered.status_code,
                    response_headers=mask_sensitive(dict(res_tampered.headers)),
                    response_body_sample=sanitize_response_sample(res_tampered.text),
                    note="변조 토큰 테스트",
                )
            ]

            # 7) duration 계산
            duration_ms = int(
                (
                    datetime.fromisoformat(ended_at.replace("Z", ""))
                    - datetime.fromisoformat(started_at.replace("Z", ""))
                ).total_seconds()
                * 1000
            )

            return ToolResult(
                tool_id=self.tool_id,
                tool_name=self.tool_name,
                status=status,
                severity=severity,
                confidence=Confidence.HIGH.value,
                title=title,
                description=description,
                evidence=evidence,
                owasp=owasp,
                cwe=cwe,
                recommendation=recommendation,
                started_at=started_at,
                ended_at=ended_at,
                duration_ms=duration_ms,
            )

        # 8) Timeout 예외 처리
        except requests.Timeout as e:
            ended_at = utc_now_iso()
            return ToolResult(
                tool_id=self.tool_id,
                tool_name=self.tool_name,
                status=ToolStatus.ERROR.value,
                severity=Severity.INFO.value,
                confidence=Confidence.LOW.value,
                title="JWT 테스트 타임아웃",
                description=str(e),
                started_at=started_at,
                ended_at=ended_at,
                duration_ms=0,
                evidence=[],
                errors=[build_tool_error(ErrorCode.TIMEOUT.value, str(e), retryable=True)],
            )

        # 9) 기타 HTTP 오류 처리
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
                started_at=started_at,
                ended_at=ended_at,
                duration_ms=0,
                evidence=[],
                errors=[
                    build_tool_error(ErrorCode.HTTP_FAILURE.value, str(e), retryable=True)
                ],
            )

        # 10) 그 외 내부 오류
        except Exception as e:
            ended_at = utc_now_iso()
            return ToolResult(
                tool_id=self.tool_id,
                tool_name=self.tool_name,
                status=ToolStatus.ERROR.value,
                severity=Severity.INFO.value,
                confidence=Confidence.LOW.value,
                title="JWT 테스트 오류",
                description=str(e),
                started_at=started_at,
                ended_at=ended_at,
                duration_ms=0,
                evidence=[],
                errors=[
                    build_tool_error(ErrorCode.INTERNAL_ERROR.value, str(e), retryable=False)
                ],
            )