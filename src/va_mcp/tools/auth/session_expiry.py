import time
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


class SessionExpiryTool(BaseTool):
    name = "Session Expiry Testing"
    tool_id = "auth_session"

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
            auth_ctx = tool_input.auth[0]

            headers = tool_input.request.headers.copy()
            headers["Authorization"] = f"Bearer {auth_ctx.token}"

            url = tool_input.target.base_url + tool_input.request.path

            # 1️⃣ 첫 요청
            res1 = requests.request(
                method=tool_input.request.method,
                url=url,
                headers=headers,
            )

            # 2️⃣ 대기
            wait_sec = tool_input.options.extra.get("wait", 2)
            time.sleep(wait_sec)

            # 3️⃣ 두 번째 요청
            res2 = requests.request(
                method=tool_input.request.method,
                url=url,
                headers=headers,
            )

            # 4️⃣ 판단
            vulnerable = res1.status_code == 200 and res2.status_code == 200

            if vulnerable:
                status = ToolStatus.VULNERABLE
                severity = Severity.MEDIUM
                title = "세션 만료 미적용"
                description = "시간 경과 후에도 동일 토큰으로 접근 가능"
            else:
                status = ToolStatus.PASSED
                severity = Severity.LOW
                title = "세션 정상 만료"
                description = "토큰이 만료되어 접근 차단됨"

            ended_at = utc_now_iso()

            evidence = [
                Evidence(
                    request={"headers": mask_sensitive(headers)},
                    response_status=res2.status_code,
                    response_headers=mask_sensitive(dict(res2.headers)),
                    response_body_sample=sanitize_response_sample(res2.text),
                    note=f"{wait_sec}초 후 재요청",
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
                owasp=["A07 Authentication Failures"],
                cwe=["CWE-613"],
                recommendation="세션 및 토큰 만료 시간을 설정하세요.",
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
                title="세션 테스트 타임아웃",
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
                title="세션 테스트 오류",
                description=str(e),
                started_at=started_at,
                ended_at=ended_at,
                duration_ms=0,
                evidence=[],
                errors=[build_tool_error(ErrorCode.INTERNAL_ERROR, str(e))],
            )