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


class RateLimitTool(BaseTool):
    name = "Login Rate Limit Testing"
    tool_id = "auth_rate_limit"

    def run(self, tool_input: ToolInput) -> ToolResult:
        started_at = utc_now_iso()

        # ✅ 입력 검증
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

            status_codes = []
            response_times = []
            last_res = None

            for auth_ctx in tool_input.auth:
                if not auth_ctx.token:
                    continue

                username, password = auth_ctx.token.split(":", 1)

                body = tool_input.request.body.copy()
                body["username"] = username
                body["password"] = password

                t1 = time.time()

                res = requests.request(
                    method=tool_input.request.method,
                    url=url,
                    headers=tool_input.request.headers,
                    json=body,
                    timeout=tool_input.options.timeout / 1000,
                )

                t2 = time.time()

                status_codes.append(res.status_code)
                response_times.append((t2 - t1) * 1000)
                last_res = res

            avg = sum(response_times) / len(response_times)

            is_limited = (
                429 in status_codes
                or status_codes.count(403) > len(status_codes) * 0.3
                or max(response_times) > avg * 2
            )

            if is_limited:
                status = ToolStatus.PASSED
                severity = Severity.LOW
                title = "Rate Limit 정상"
                description = "요청 제한 동작 확인"
            else:
                status = ToolStatus.VULNERABLE
                severity = Severity.MEDIUM
                title = "Rate Limit 없음"
                description = "무차별 요청 가능"

            ended_at = utc_now_iso()

            evidence = []
            if last_res:
                evidence.append(
                    Evidence(
                        request={"body": "***"},
                        response_status=last_res.status_code,
                        response_headers=mask_sensitive(dict(last_res.headers)),
                        response_body_sample=sanitize_response_sample(last_res.text),
                        note=f"{len(status_codes)}회 요청 수행",
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