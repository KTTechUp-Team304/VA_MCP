import requests
from datetime import datetime

from va_mcp.core.base import BaseTool
from va_mcp.core.schemas import ToolInput, ToolResult, Evidence
from va_mcp.core.utils import (
    utc_now_iso,
    sanitize_request_body,
    sanitize_response_sample,
    mask_sensitive,
    build_tool_error,
)
from va_mcp.core.constants import ToolStatus, Severity, Confidence, ErrorCode


class CredentialEnumTool(BaseTool):
    name = "Credential Enumeration Testing"
    tool_id = "auth_enum"

    def run(self, tool_input: ToolInput) -> ToolResult:
        started_at = utc_now_iso()

        # ✅ 최소 2개 auth 필요
        if not tool_input.request or len(tool_input.auth) < 2:
            return ToolResult(
                tool_id=self.tool_id,
                tool_name=self.name,
                status=ToolStatus.SKIPPED,
                severity=Severity.INFO,
                confidence=Confidence.LOW,
                title="입력 부족",
                description="auth 2개 이상 필요",
                started_at=started_at,
                ended_at=started_at,
                duration_ms=0,
                evidence=[],
            )

        try:
            url = tool_input.target.base_url + tool_input.request.path

            responses = []
            bodies = []

            for auth_ctx in tool_input.auth:
                if not auth_ctx.token:
                    continue

                username, password = auth_ctx.token.split(":", 1)

                body = tool_input.request.body.copy()
                body["username"] = username
                body["password"] = password

                res = requests.request(
                    method=tool_input.request.method,
                    url=url,
                    headers=tool_input.request.headers,
                    json=body,
                    timeout=tool_input.options.timeout / 1000,
                )

                responses.append(res)
                bodies.append(body)

            vulnerable = (
                responses[0].status_code != responses[1].status_code
                or responses[0].text != responses[1].text
            )

            status = ToolStatus.VULNERABLE if vulnerable else ToolStatus.PASSED

            ended_at = utc_now_iso()

            evidence = [
                Evidence(
                    request={"body": sanitize_request_body(bodies[0])},
                    response_status=responses[0].status_code,
                    response_headers=mask_sensitive(dict(responses[0].headers)),
                    response_body_sample=sanitize_response_sample(responses[0].text),
                    note="existing user",
                ),
                Evidence(
                    request={"body": sanitize_request_body(bodies[1])},
                    response_status=responses[1].status_code,
                    response_headers=mask_sensitive(dict(responses[1].headers)),
                    response_body_sample=sanitize_response_sample(responses[1].text),
                    note="non-existing user",
                ),
            ]

            return ToolResult(
                tool_id=self.tool_id,
                tool_name=self.name,
                status=status,
                severity=Severity.MEDIUM,
                confidence=Confidence.HIGH,
                title="계정 유무 노출",
                description="응답 차이 여부 분석",
                evidence=evidence,
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

        # ✅ 에러 분기
        except requests.Timeout as e:
            ended_at = utc_now_iso()
            return ToolResult(
                tool_id=self.tool_id,
                tool_name=self.name,
                status=ToolStatus.ERROR,
                severity=Severity.INFO,
                confidence=Confidence.LOW,
                title="요청 타임아웃",
                description=str(e),
                started_at=started_at,
                ended_at=ended_at,
                duration_ms=0,
                evidence=[],
                errors=[build_tool_error(ErrorCode.TIMEOUT, str(e), True)],
            )

        except requests.RequestException as e:
            ended_at = utc_now_iso()
            return ToolResult(
                tool_id=self.tool_id,
                tool_name=self.name,
                status=ToolStatus.ERROR,
                severity=Severity.INFO,
                confidence=Confidence.LOW,
                title="HTTP 요청 실패",
                description=str(e),
                started_at=started_at,
                ended_at=ended_at,
                duration_ms=0,
                evidence=[],
                errors=[build_tool_error(ErrorCode.HTTP_FAILURE, str(e), True)],
            )

        except Exception as e:
            ended_at = utc_now_iso()
            return ToolResult(
                tool_id=self.tool_id,
                tool_name=self.name,
                status=ToolStatus.ERROR,
                severity=Severity.INFO,
                confidence=Confidence.LOW,
                title="내부 오류",
                description=str(e),
                started_at=started_at,
                ended_at=ended_at,
                duration_ms=0,
                evidence=[],
                errors=[build_tool_error(ErrorCode.INTERNAL_ERROR, str(e))],
            )