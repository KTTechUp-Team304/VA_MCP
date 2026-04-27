import time
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

class RateLimitTool(BaseTool):
    tool_id = "auth_rate_limit"
    tool_name = "Login Rate Limit Testing"

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
            status_codes: list[int] = []
            response_times: list[float] = []
            last_res = None

            # 2) 각 인증 컨텍스트별 요청
            for auth_ctx in tool_input.auth:
                token = auth_ctx.token or ""
                if ":" not in token:
                    continue

                username, password = token.split(":", 1)
                orig_body = tool_input.request.body or {}
                body = orig_body.copy()
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

            # 3) 평균 응답시간 계산 (0건 방어)
            try:
                avg = sum(response_times) / len(response_times)
            except ZeroDivisionError:
                avg = 0.0

            # 4) 쓰로틀링 감지
            is_limited = (
                429 in status_codes
                or (len(status_codes) > 0 and status_codes.count(403) > len(status_codes) * 0.3)
            )

            # 5) 상태·심각도 결정
            if is_limited:
                status = ToolStatus.PASSED.value
                severity = Severity.INFO.value
                title = "Rate Limit 정상"
                description = "요청 제한 동작이 확인되었습니다."
            else:
                status = ToolStatus.VULNERABLE.value
                severity = Severity.MEDIUM.value
                title = "Rate Limit 없음"
                description = "무차별 요청이 가능합니다."

            # ─── 2번 수정사항 반영 ───
            owasp = ["A07:2025 Identification and Authentication Failures"]
            cwe = ["CWE-770"]
            recommendation = (
                "서버 측에 적절한 rate limiting 정책을 도입하고, "
                "과도 요청 시 429 상태코드를 반환하도록 설정하세요."
            )
            # ────────────────────────

            ended_at = utc_now_iso()

            # 6) 증거 생성
            evidence: list[Evidence] = []
            if last_res:
                evidence.append(
                    Evidence(
                        request={
                            "method": tool_input.request.method,
                            "path": tool_input.request.path,
                            "headers": mask_sensitive(tool_input.request.headers),
                            "body": sanitize_request_body(orig_body),
                        },
                        response_status=last_res.status_code,
                        response_headers=mask_sensitive(dict(last_res.headers)),
                        response_body_sample=sanitize_response_sample(last_res.text),
                        note=f"{len(status_codes)}회 요청, avg={avg:.2f}ms",
                    )
                )

            # 7) 소요 시간 계산
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
                errors=[build_tool_error(ErrorCode.INTERNAL_ERROR.value, str(e), retryable=False)],
                started_at=started_at,
                ended_at=ended_at,
                duration_ms=0,
            )