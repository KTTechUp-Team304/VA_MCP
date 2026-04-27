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


class BruteForceTool(BaseTool):
    name = "Brute Force Testing"
    tool_id = "auth_bruteforce"

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

            last_res = None
            success_cred = None

            # 🔥 auth 리스트 순회 (브루트포스 핵심)
            for auth_ctx in tool_input.auth:
                if not auth_ctx.token:
                    continue

                # "username:password" 형태
                try:
                    username, password = auth_ctx.token.split(":", 1)
                except ValueError:
                    continue

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

                if res.status_code == 200:
                    success_cred = auth_ctx.token
                    break

            # 🔥 결과 판단
            if success_cred:
                status = ToolStatus.VULNERABLE
                severity = Severity.HIGH
                title = "브루트포스 성공"
                description = f"유효한 자격증명 발견: {success_cred}"
            else:
                status = ToolStatus.PASSED
                severity = Severity.LOW
                title = "브루트포스 방어됨"
                description = "모든 인증 시도 실패"

            ended_at = utc_now_iso()

            evidence = []
            if last_res:
                evidence.append(
                    Evidence(
                        request={
                            "path": tool_input.request.path,
                            "body": "***",
                        },
                        response_status=last_res.status_code,
                        response_headers=mask_sensitive(dict(last_res.headers)),
                        response_body_sample=sanitize_response_sample(last_res.text),
                        note="마지막 시도 기준",
                    )
                )

            return ToolResult(
                tool_id=self.tool_id,
                tool_name=self.name,
                status=status,
                severity=severity,
                confidence=Confidence.HIGH,
                title=title,
                description=description,
                evidence=evidence,
                owasp=["A07 Authentication Failures"],
                cwe=["CWE-307"],
                recommendation="로그인 시도 횟수 제한 및 CAPTCHA 적용",
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
                title="브루트포스 오류",
                description=str(e),
                started_at=started_at,
                ended_at=utc_now_iso(),
                duration_ms=0,
                evidence=[],
                errors=[build_tool_error(ErrorCode.INTERNAL_ERROR, str(e))],
            )