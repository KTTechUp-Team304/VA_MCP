import time
import requests
from datetime import datetime

from va_mcp.core import (
    BaseTool,
    ToolInput,
    ToolResult,
    Evidence,
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
)


class SessionExpiryTool(BaseTool):
    tool_id = "auth_session"
    tool_name = "Session Expiry Testing"

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
            # 2) 인증 토큰 준비
            auth_ctx = tool_input.auth[0]
            token = auth_ctx.token or ""
            if not token:
                raise ValueError("인증 토큰이 비어 있습니다")

            # 3) 헤더 및 URL 구성
            headers = tool_input.request.headers.copy()
            headers["Authorization"] = f"Bearer {token}"
            url = tool_input.target.base_url + tool_input.request.path
            timeout_s = tool_input.options.timeout / 1000

            # 4) 첫 요청 (유효한 토큰 검증)
            res1 = requests.request(
                method=tool_input.request.method,
                url=url,
                headers=headers,
                timeout=timeout_s,
            )

            # 5) 첫 요청이 200이 아니면 테스트 불가능 → SKIPPED
            if res1.status_code != 200:
                ended_at = utc_now_iso()
                return ToolResult(
                    tool_id=self.tool_id,
                    tool_name=self.tool_name,
                    status=ToolStatus.SKIPPED.value,
                    severity=Severity.INFO.value,
                    confidence=Confidence.LOW.value,
                    title="테스트 SKIPPED",
                    description="첫 번째 요청이 성공(200)하지 않아 세션 만료 테스트를 건너뛰었습니다.",
                    evidence=[],
                    owasp=[],
                    cwe=[],
                    recommendation="",
                    started_at=started_at,
                    ended_at=ended_at,
                    duration_ms=0,
                )

            # 6) 대기 후 두 번째 요청
            wait_sec = tool_input.options.extra.get("wait", 2)
            time.sleep(wait_sec)

            res2 = requests.request(
                method=tool_input.request.method,
                url=url,
                headers=headers,
                timeout=timeout_s,
            )

            # 7) 취약 여부 판단
            if res2.status_code == 200:
                status = ToolStatus.VULNERABLE.value
                severity = Severity.MEDIUM.value
                title = "세션 만료 미적용"
                description = "시간 경과 후에도 동일 토큰으로 접근 가능합니다."
                confidence = Confidence.HIGH.value
            else:
                status = ToolStatus.PASSED.value
                severity = Severity.INFO.value
                title = "세션 정상 만료"
                description = "토큰이 만료되어 접근이 차단됨을 확인했습니다."
                confidence = Confidence.LOW.value

            ended_at = utc_now_iso()

            # 8) 증거 생성
            evidence = [
                Evidence(
                    request={
                        "method": tool_input.request.method,
                        "path": tool_input.request.path,
                        "headers": mask_sensitive(headers),
                    },
                    response_status=res2.status_code,
                    response_headers=mask_sensitive(dict(res2.headers)),
                    response_body_sample=sanitize_response_sample(res2.text),
                    note=f"{wait_sec}초 후 재요청",
                )
            ]

            # 9) 소요 시간(ms) 계산
            duration_ms = int(
                (
                    datetime.fromisoformat(ended_at.replace("Z", ""))
                    - datetime.fromisoformat(started_at.replace("Z", ""))
                ).total_seconds()
                * 1000
            )

            # 10) ToolResult 반환 (OWASP/CWE/권고 포함)
            return ToolResult(
                tool_id=self.tool_id,
                tool_name=self.tool_name,
                status=status,
                severity=severity,
                confidence=confidence,
                title=title,
                description=description,
                evidence=evidence,
                owasp=["A07:2025 Identification and Authentication Failures"],
                cwe=["CWE-613"],
                recommendation="세션 및 토큰 만료 시간을 올바르게 설정하세요.",
                started_at=started_at,
                ended_at=ended_at,
                duration_ms=duration_ms,
            )

        # 11) Timeout 예외 처리
        except requests.Timeout as e:
            ended_at = utc_now_iso()
            return ToolResult(
                tool_id=self.tool_id,
                tool_name=self.tool_name,
                status=ToolStatus.ERROR.value,
                severity=Severity.INFO.value,
                confidence=Confidence.LOW.value,
                title="세션 테스트 타임아웃",
                description=str(e),
                evidence=[],
                errors=[build_tool_error(ErrorCode.TIMEOUT.value, str(e), retryable=True)],
                owasp=[],
                cwe=[],
                recommendation="",
                started_at=started_at,
                ended_at=ended_at,
                duration_ms=0,
            )

        # 12) 기타 HTTP 오류 처리
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
                owasp=[],
                cwe=[],
                recommendation="",
                started_at=started_at,
                ended_at=ended_at,
                duration_ms=0,
            )

        # 13) 내부 오류 처리
        except Exception as e:
            ended_at = utc_now_iso()
            return ToolResult(
                tool_id=self.tool_id,
                tool_name=self.tool_name,
                status=ToolStatus.ERROR.value,
                severity=Severity.INFO.value,
                confidence=Confidence.LOW.value,
                title="세션 테스트 오류",
                description=str(e),
                evidence=[],
                errors=[build_tool_error(ErrorCode.INTERNAL_ERROR.value, str(e), retryable=False)],
                owasp=[],
                cwe=[],
                recommendation="",
                started_at=started_at,
                ended_at=ended_at,
                duration_ms=0,
            )