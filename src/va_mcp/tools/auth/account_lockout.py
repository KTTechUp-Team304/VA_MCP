import time
import requests
from typing import List, Dict

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
    sanitize_request_body,
)
from va_mcp.core.resolvers.auth_resolver import (
    parse_credentials,
    apply_field_mapping,
    resolve_auth_headers,
    CredentialResolverError,
)


class AccountLockoutTool(BaseTool):
    tool_id = "auth_lockout"
    tool_name = "Account Lockout Testing"

    def run(self, tool_input: ToolInput) -> ToolResult:
        start_ts = time.time()
        started_at = utc_now_iso()

        req = tool_input.request
        auth_list = tool_input.auth

        # 1) 입력 검증
        if not req or not auth_list:
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

        # 2) credential_fields 매핑 추출
        cred_fields = (
            tool_input.options.extra
            .get("field_mapping", {})
            .get("credential_fields", {})
        )
        if not isinstance(cred_fields, dict) \
           or "username" not in cred_fields \
           or "password" not in cred_fields:
            return ToolResult(
                tool_id=self.tool_id,
                tool_name=self.tool_name,
                status=ToolStatus.SKIPPED.value,
                severity=Severity.INFO.value,
                confidence=Confidence.LOW.value,
                title="매핑 누락",
                description="credential_fields 매핑이 없습니다.",
                evidence=[],
                owasp=[],
                cwe=[],
                recommendation="options.extra.field_mapping.credential_fields를 설정하세요.",
                started_at=started_at,
                ended_at=started_at,
                duration_ms=0,
            )

        # 3) basic AuthContext 필터링
        basic_ctxs = [
            ctx for ctx in auth_list
            if getattr(ctx, "auth_type", "").lower() == "basic"
               and getattr(ctx, "token", None)
        ]
        if not basic_ctxs:
            return ToolResult(
                tool_id=self.tool_id,
                tool_name=self.tool_name,
                status=ToolStatus.SKIPPED.value,
                severity=Severity.INFO.value,
                confidence=Confidence.LOW.value,
                title="basic AuthContext 없음",
                description="auth 리스트에 basic 타입과 token이 없습니다.",
                evidence=[],
                owasp=[],
                cwe=[],
                recommendation="basic AuthContext를 제공하세요.",
                started_at=started_at,
                ended_at=started_at,
                duration_ms=0,
            )

        # 4) URL 및 원본 body/headers 준비
        base = tool_input.target.base_url.rstrip("/")
        path = req.path.lstrip("/")
        url = f"{base}/{path}"

        orig_body = req.body or {}
        orig_headers = req.headers or {}

        locked = False
        last_res: requests.Response | None = None
        last_body: Dict[str, any] = {}

        try:
            # 5) 각 AuthContext로 로그인 시도
            for ctx in basic_ctxs:
                try:
                    parsed = parse_credentials(ctx)
                    payload = apply_field_mapping(
                        parsed, {"credential_fields": cred_fields}
                    )
                    auth_headers = resolve_auth_headers(ctx)
                except CredentialResolverError:
                    continue

                body = {**orig_body, **payload}
                headers = {**orig_headers, **auth_headers}

                res = requests.request(
                    method=req.method,
                    url=url,
                    headers=headers,
                    json=body,
                    timeout=tool_input.options.timeout / 1000,
                )
                last_res = res
                last_body = body

                if res.status_code in (403, 423):
                    locked = True
                    break

            # 6) 결과 결정
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

            owasp = ["A07:2025 Identification and Authentication Failures"]
            cwe = ["CWE-307"]
            recommendation = (
                "반복 로그인 실패 시 계정을 잠금 처리하도록 서버 측 정책을 구현하세요."
            )

            ended_at = utc_now_iso()
            duration_ms = int((time.time() - start_ts) * 1000)

            # 7) 증거 생성
            evidence: List[Evidence] = []
            if last_res:
                evidence.append(
                    Evidence(
                        request={
                            "method": req.method,
                            "path": req.path,
                            "headers": mask_sensitive(orig_headers),
                            "body": sanitize_request_body(last_body),
                        },
                        response_status=last_res.status_code,
                        response_headers=mask_sensitive(dict(last_res.headers)),
                        response_body_sample=sanitize_response_sample(last_res.text),
                        note=f"마지막 시도 status_code={last_res.status_code}",
                    )
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