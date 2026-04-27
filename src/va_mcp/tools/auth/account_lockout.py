import requests
from datetime import datetime

from va_mcp.core import (
    BaseTool,
    ToolInput,
    ToolResult,
    Evidence,
    ToolError,
    AuthContext,
    ToolStatus,
    Severity,
    Confidence,
    ErrorCode,
)
from va_mcp.core.utils import (
    build_tool_error,
    utc_now_iso,
    mask_sensitive,
    sanitize_response_sample,
    sanitize_request_body,
)

class AccountLockoutTool(BaseTool):
    tool_id = "auth_lockout"
    tool_name = "Account Lockout Testing"

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
                evidence=[],
                owasp=[],
                cwe=[],
                recommendation="",
                started_at=started_at,
                ended_at=started_at,
                duration_ms=0,
            )

        try:
            url = tool_input.target.base_url + tool_input.request.path
            orig_body = tool_input.request.body or {}

            locked = False
            last_res = None

            # 2) 각 auth context로 로그인 시도
            for auth_ctx in tool_input.auth:
                token = auth_ctx.token or ""
                if ":" not in token:
                    continue

                username, password = token.split(":", 1)
                body = orig_body.copy()
                body["username"] = username
                body["password"] = password

                res = requests.request(
                    method=tool_input.request.method,
                    url=url,
                    headers=tool_input.request.headers,
                    json=body,
                    timeout=tool_input.options.timeout / 1000,
                )
                last_res = res

                # 403 or 423 응답 시 계정 잠금으로 간주
                if res.status_code in (403, 423):
                    locked = True
                    break

            # 3) 결과 결정
            if locked:
                status = ToolStatus.PASSED.value
                severity = Severity.INFO.value
                confidence = Confidence.LOW.value
                title = "계정 잠금 정상"
                description = "반복 로그인 실패 시 계정 잠금이 정상 동작합니다."
            else:
                status = ToolStatus.VULNERABLE.value
                severity = Severity.HIGH.value
                confidence = Confidence.HIGH.value
                title = "계정 잠금 없음"
                description = "반복 로그인 실패에도 계정 잠금이 동작하지 않습니다."

            # 4) OWASP / CWE / Recommendation
            owasp = ["A07:2025 Identification and Authentication Failures"]
            cwe = ["CWE-307"]
            recommendation = "반복 로그인 실패 시 계정을 잠금 처리하도록 서버 측 정책을 구현하세요."

            ended_at = utc_now_iso()

            # 5) 증거 생성
            evidence: list[Evidence] = []
            if last_res:
                evidence.append(
                    Evidence(
                        request={
                            "method": tool_input.request.method,
                            "path": tool_input.request.path,
                            "headers": mask_sensitive(tool_input.request.headers),
                            "body": sanitize_request_body(body),
                        },
                        response_status=last_res.status_code,
                        response_headers=mask_sensitive(dict(last_res.headers)),
                        response_body_sample=sanitize_response_sample(last_res.text),
                        note=f"마지막 시도 status_code={last_res.status_code}",
                    )
                )

            # 6) 소요 시간(ms) 계산
            duration_ms = int(
                (
                    datetime.fromisoformat(ended_at.replace("Z", ""))
                    - datetime.fromisoformat(started_at.replace("Z", ""))
                ).total_seconds()
                * 1000
            )

            # 7) ToolResult 반환
            return ToolResult(
                tool_id=self.tool_id,
                tool_name=self.tool_name,
                status=status,
                severity=severity,
                confidence=confidence,
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

        except requests.Timeout as e:
            ended_at = utc_now_iso()
            return ToolResult(
                tool_id=self.tool_id,
                tool_name=self.tool_name,
                status=ToolStatus.ERROR.value,
                severity=Severity.INFO.value,
                confidence=Confidence.LOW.value,
                title="요청 타임아웃",
                description=str(e),
                evidence=[],
                owasp=[],
                cwe=[],
                recommendation="",
                errors=[build_tool_error(ErrorCode.TIMEOUT.value, str(e), retryable=True)],
                started_at=started_at,
                ended_at=ended_at,
                duration_ms=0,
            )

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
                evidence=[],
                owasp=[],
                cwe=[],
                recommendation="",
                errors=[build_tool_error(ErrorCode.HTTP_FAILURE.value, str(e), retryable=True)],
                started_at=started_at,
                ended_at=ended_at,
                duration_ms=0,
            )

        except Exception as e:
            ended_at = utc_now_iso()
            return ToolResult(
                tool_id=self.tool_id,
                tool_name=self.tool_name,
                status=ToolStatus.ERROR.value,
                severity=Severity.INFO.value,
                confidence=Confidence.LOW.value,
                title="내부 오류",
                description=str(e),
                evidence=[],
                owasp=[],
                cwe=[],
                recommendation="",
                errors=[build_tool_error(ErrorCode.INTERNAL_ERROR.value, str(e), retryable=False)],
                started_at=started_at,
                ended_at=ended_at,
                duration_ms=0,
            )