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

class CredentialEnumTool(BaseTool):
    tool_id = "auth_enum"
    tool_name = "Credential Enumeration Testing"

    def run(self, tool_input: ToolInput) -> ToolResult:
        started_at = utc_now_iso()

        # 1) 최소 2개 auth 필요
        if not tool_input.request or len(tool_input.auth) < 2:
            return ToolResult(
                tool_id=self.tool_id,
                tool_name=self.tool_name,
                status=ToolStatus.SKIPPED.value,
                severity=Severity.INFO.value,
                confidence=Confidence.LOW.value,
                title="입력 부족",
                description="auth 컨텍스트가 2개 이상 필요합니다.",
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
            responses: list[requests.Response] = []
            bodies: list[dict] = []

            # 2) body가 None인 경우 빈 dict로 방어
            orig_body = tool_input.request.body or {}

            # 3) 각 auth context 로 요청
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
                responses.append(res)
                bodies.append(body)

            # 유효한 응답이 두 건 미만이면 스킵
            if len(responses) < 2:
                ended_at = utc_now_iso()
                return ToolResult(
                    tool_id=self.tool_id,
                    tool_name=self.tool_name,
                    status=ToolStatus.SKIPPED.value,
                    severity=Severity.INFO.value,
                    confidence=Confidence.LOW.value,
                    title="요청 부족",
                    description="유효한 auth 요청이 2건 이상 필요합니다.",
                    evidence=[],
                    owasp=[],
                    cwe=[],
                    recommendation="",
                    started_at=started_at,
                    ended_at=ended_at,
                    duration_ms=0,
                )

            # 4) 취약 여부 판단 (상태 코드나 응답 본문 차이)
            vulnerable = (
                responses[0].status_code != responses[1].status_code
                or responses[0].text != responses[1].text
            )

            # 5) OWASP / CWE / 결과 설정
            owasp = ["A07:2025 Identification and Authentication Failures"]
            cwe = ["CWE-203"]
            if vulnerable:
                status = ToolStatus.VULNERABLE.value
                severity = Severity.MEDIUM.value
                confidence = Confidence.HIGH.value
                title = "Credential Enumeration 가능"
                description = "계정 존재 여부에 따라 응답이 다르게 나타납니다."
                recommendation = (
                    "존재/비존재 차이를 응답 코드나 메시지에 노출하지 않도록 통일하세요."
                )
            else:
                status = ToolStatus.PASSED.value
                severity = Severity.INFO.value
                confidence = Confidence.LOW.value
                title = "Credential Enumeration 불가"
                description = "계정 유무에 따른 응답 차이가 없습니다."
                recommendation = (
                    "응답을 통일하여 계정 존재 여부가 노출되지 않음을 확인했습니다."
                )

            ended_at = utc_now_iso()

            # 6) 증거 생성
            evidence: list[Evidence] = []
            for idx in (0, 1):
                res = responses[idx]
                body = bodies[idx]
                note = "existing user" if idx == 0 else "non-existing user"
                evidence.append(
                    Evidence(
                        request={
                            "method": tool_input.request.method,
                            "path": tool_input.request.path,
                            "headers": mask_sensitive(tool_input.request.headers),
                            "body": sanitize_request_body(body),
                        },
                        response_status=res.status_code,
                        response_headers=mask_sensitive(dict(res.headers)),
                        response_body_sample=sanitize_response_sample(res.text),
                        note=note,
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

            # 8) ToolResult 반환
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