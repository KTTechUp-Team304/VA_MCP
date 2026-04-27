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

class BruteForceTool(BaseTool):
    tool_id = "auth_bruteforce"
    tool_name = "Brute Force Testing"

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

            last_res = None
            success_cred = None

            # body가 None인 경우 빈 dict로 방어
            orig_body = tool_input.request.body or {}

            # 2) auth 리스트 순회 (브루트포스 핵심)
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

                if res.status_code == 200:
                    success_cred = token
                    break

            # 3) 결과 판단 & severity 결정
            if success_cred:
                status = ToolStatus.VULNERABLE.value
                severity = Severity.HIGH.value
                title = "브루트포스 성공"
                # 비밀번호 노출 금지 → 마스킹
                user, pwd = success_cred.split(":", 1)
                masked_cred = f"{user}:***"
                description = f"유효한 자격증명 발견: {masked_cred}"
                confidence = Confidence.HIGH.value
            else:
                status = ToolStatus.PASSED.value
                severity = Severity.INFO.value
                title = "브루트포스 방어됨"
                description = "모든 인증 시도가 실패했습니다."
                confidence = Confidence.LOW.value

            ended_at = utc_now_iso()

            # 4) 증거 생성
            evidence: list[Evidence] = []
            if last_res:
                # 마지막 시도한 body를 그대로 쓰면 비밀번호가 노출될 수 있으므로
                # request.body에는 orig_body 를 쓰고, credentials info는 note로 남기세요.
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
                        note="마지막 시도 결과",
                    )
                )

            # 5) duration 계산
            duration_ms = int(
                (
                    datetime.fromisoformat(ended_at.replace("Z", ""))
                    - datetime.fromisoformat(started_at.replace("Z", ""))
                ).total_seconds()
                * 1000
            )

            # 6) ToolResult 반환 (OWASP/CWE/권고 포함)
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
                cwe=["CWE-307"],
                recommendation="로그인 시도 횟수를 제한하고 CAPTCHA 등을 적용하세요.",
                started_at=started_at,
                ended_at=ended_at,
                duration_ms=duration_ms,
            )

        # 7) Timeout 예외 처리
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
                owasp=[],
                cwe=[],
                recommendation="",
                started_at=started_at,
                ended_at=ended_at,
                duration_ms=0,
            )

        # 8) 기타 HTTP 오류 처리
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

        # 9) 그 외 내부 오류
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
                owasp=[],
                cwe=[],
                recommendation="",
                started_at=started_at,
                ended_at=ended_at,
                duration_ms=0,
            )