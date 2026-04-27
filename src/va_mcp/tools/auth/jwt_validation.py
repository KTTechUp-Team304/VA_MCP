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
    name = "JWT Validation Testing"
    tool_id = "auth_jwt"

    def run(self, tool_input: ToolInput) -> ToolResult:
        started_at = utc_now_iso()

        if not tool_input.request or not tool_input.auth:
            return ToolResult(
                tool_id=self.tool_id,
                tool_name=self.name,
                status=ToolStatus.SKIPPED,
                severity=Severity.INFO,
                confidence=Confidence.LOW,
                title="입력 부족",
                description="request 또는 auth 없음",
                started_at=started_at,
                ended_at=started_at,
                duration_ms=0,
                evidence=[],
            )

        try:
            token = tool_input.auth[0].token

            if not token:
                raise ValueError("JWT 토큰이 비어 있음")

            tampered = token[:-1] + "X"

            url = tool_input.target.base_url + tool_input.request.path

            res_valid = requests.request(
                method=tool_input.request.method,
                url=url,
                headers={"Authorization": f"Bearer {token}"},
            )

            res_tampered = requests.request(
                method=tool_input.request.method,
                url=url,
                headers={"Authorization": f"Bearer {tampered}"},
            )

            vulnerable = (
                res_valid.status_code == 200
                and res_tampered.status_code == 200
            )

            if vulnerable:
                status = ToolStatus.VULNERABLE
                severity = Severity.HIGH
                title = "JWT 검증 실패"
                description = "변조된 토큰 허용"
            else:
                status = ToolStatus.PASSED
                severity = Severity.LOW
                title = "JWT 검증 정상"
                description = "변조된 토큰 차단됨"

            ended_at = utc_now_iso()

            evidence = [
                Evidence(
                    request={"headers": {"Authorization": "***"}},
                    response_status=res_tampered.status_code,
                    response_headers=mask_sensitive(dict(res_tampered.headers)),
                    response_body_sample=sanitize_response_sample(res_tampered.text),
                    note="변조 토큰 테스트",
                )
            ]

            return ToolResult(
                tool_id=self.tool_id,
                tool_name=self.name,
                status=status,
                severity=severity,
                confidence=Confidence.HIGH,
                title=title,
                description=description,
                evidence=evidence,
                owasp=["A02 Cryptographic Failures"],
                cwe=["CWE-347"],
                recommendation="JWT 서명 검증을 반드시 수행하세요.",
                started_at=started_at,
                ended_at=ended_at,
                duration_ms=int(
                    (
                        datetime.fromisoformat(ended_at.replace("Z", ""))
                        - datetime.fromisoformat(started_at.replace("Z", ""))
                    ).total_seconds()
                    * 1000
                ),
            )

        except requests.Timeout as e:
            ended_at = utc_now_iso()
            return ToolResult(
                tool_id=self.tool_id,
                tool_name=self.name,
                status=ToolStatus.ERROR,
                severity=Severity.INFO,
                confidence=Confidence.LOW,
                title="JWT 테스트 타임아웃",
                description=str(e),
                started_at=started_at,
                ended_at=ended_at,
                duration_ms=0,
                evidence=[],
                errors=[build_tool_error(ErrorCode.TIMEOUT, str(e), True)],
            )

        except Exception as e:
            ended_at = utc_now_iso()
            return ToolResult(
                tool_id=self.tool_id,
                tool_name=self.name,
                status=ToolStatus.ERROR,
                severity=Severity.INFO,
                confidence=Confidence.LOW,
                title="JWT 테스트 오류",
                description=str(e),
                started_at=started_at,
                ended_at=ended_at,
                duration_ms=0,
                evidence=[],
                errors=[build_tool_error(ErrorCode.INTERNAL_ERROR, str(e))],
            )