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


class AccountLockoutTool(BaseTool):
    name = "Account Lockout Testing"
    tool_id = "auth_lockout"

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
            url = tool_input.target.base_url + tool_input.request.path

            locked = False
            last_res = None

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
                )

                last_res = res

                if res.status_code in (403, 423):
                    locked = True
                    break

            status = ToolStatus.PASSED if locked else ToolStatus.VULNERABLE

            ended_at = utc_now_iso()

            evidence = []
            if last_res:
                evidence.append(
                    Evidence(
                        request={"body": sanitize_request_body(body)},
                        response_status=last_res.status_code,
                        response_headers=mask_sensitive(dict(last_res.headers)),
                        response_body_sample=sanitize_response_sample(last_res.text),
                        note="마지막 로그인 시도",
                    )
                )

            return ToolResult(
                tool_id=self.tool_id,
                tool_name=self.name,
                status=status,
                severity=Severity.MEDIUM,
                confidence=Confidence.HIGH,
                title="계정 잠금 정책 검사",
                description="반복 실패 시 계정 잠금 여부 확인",
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

        except requests.Timeout as e:
            return ToolResult(
                tool_id=self.tool_id,
                tool_name=self.name,
                status=ToolStatus.ERROR,
                severity=Severity.INFO,
                confidence=Confidence.LOW,
                title="타임아웃",
                description=str(e),
                started_at=started_at,
                ended_at=utc_now_iso(),
                duration_ms=0,
                evidence=[],
                errors=[build_tool_error(ErrorCode.TIMEOUT, str(e), True)],
            )

        except Exception as e:
            return ToolResult(
                tool_id=self.tool_id,
                tool_name=self.name,
                status=ToolStatus.ERROR,
                severity=Severity.INFO,
                confidence=Confidence.LOW,
                title="Lockout 오류",
                description=str(e),
                started_at=started_at,
                ended_at=utc_now_iso(),
                duration_ms=0,
                evidence=[],
                errors=[build_tool_error(ErrorCode.INTERNAL_ERROR, str(e))],
            )