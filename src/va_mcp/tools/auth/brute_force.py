import requests
import time
import logging
from datetime import datetime
from typing import Any, Dict, List

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
# 필드 매핑 적용을 위한 resolver 추가
from va_mcp.core.resolvers.auth_resolver import parse_credentials, CredentialResolverError


class BruteForceTool(BaseTool):
    tool_id = "auth_bruteforce"
    tool_name = "Brute Force Testing"
    tool_version = "0.1.0"

    def run(self, tool_input: ToolInput) -> ToolResult:
        # 0) 시작 타임스탬프
        start_ts = time.time()
        started_at = utc_now_iso()

        # 1) 입력 검증
        req = tool_input.request
        auth_list = tool_input.auth
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
                recommendation="request와 auth를 확인하세요.",
                started_at=started_at,
                ended_at=started_at,
                duration_ms=0,
                tool_version=self.tool_version,
            )

        # 2) credential_fields 매핑 꺼내기
        mapping = (
            tool_input.options.extra
            .get("field_mapping", {})
            .get("credential_fields")
        )
        if not isinstance(mapping, dict) or "username" not in mapping or "password" not in mapping:
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
                tool_version=self.tool_version,
            )

        # 3) basic auth 컨텍스트만 필터링
        basic_ctxs = [
            ctx for ctx in auth_list
            if ctx.auth_type == "basic" and ctx.token
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
                tool_version=self.tool_version,
            )

        # 4) 안전한 URL 조합
        base = tool_input.target.base_url.rstrip("/")
        path = req.path.lstrip("/")
        url = f"{base}/{path}"

        orig_body = req.body or {}
        headers = req.headers or {}

        last_res = None
        success_creds: Dict[str, Any] | None = None
        status_codes: List[int] = []

        try:
            # 5) 브루트포스 시도
            for auth_ctx in basic_ctxs:
                try:
                    creds = parse_credentials(auth_ctx, mapping)
                except CredentialResolverError as e:
                    # 이 컨텍스트 건너뜀
                    continue

                body = orig_body.copy()
                body.update(creds)

                res = requests.request(
                    method=req.method,
                    url=url,
                    headers=headers,
                    json=body,
                    timeout=tool_input.options.timeout / 1000,
                )
                status_codes.append(res.status_code)
                last_res = res

                if res.status_code == 200:
                    success_creds = creds
                    break

            # 6) 시도가 하나도 없으면 skipped
            if not status_codes:
                return ToolResult(
                    tool_id=self.tool_id,
                    tool_name=self.tool_name,
                    status=ToolStatus.SKIPPED.value,
                    severity=Severity.INFO.value,
                    confidence=Confidence.LOW.value,
                    title="요청 없음",
                    description="유효한 브루트포스 시도가 없습니다.",
                    evidence=[],
                    owasp=[],
                    cwe=[],
                    recommendation="basic AuthContext와 mapping을 검토하세요.",
                    started_at=started_at,
                    ended_at=utc_now_iso(),
                    duration_ms=int((time.time() - start_ts) * 1000),
                    tool_version=self.tool_version,
                )

            # 7) 결과 판단 & 심각도·신뢰도 결정
            if success_creds:
                status = ToolStatus.VULNERABLE.value
                severity = Severity.HIGH.value
                confidence = Confidence.HIGH.value
                title = "브루트포스 성공"
                user_val = success_creds.get(mapping["username"], "<unknown>")
                description = f"유효한 자격증명 발견: {user_val}:***"
            else:
                status = ToolStatus.PASSED.value
                severity = Severity.INFO.value
                confidence = Confidence.LOW.value
                title = "브루트포스 방어됨"
                description = "모든 인증 시도가 실패했습니다."

            owasp = ["A07:2025 Identification and Authentication Failures"]
            cwe = ["CWE-307"]
            recommendation = "로그인 시도 횟수를 제한하고 CAPTCHA 등을 적용하세요."

            ended_at = utc_now_iso()
            duration_ms = int((time.time() - start_ts) * 1000)

            # 8) 증거 생성
            evidence: List[Evidence] = []
            if last_res:
                evidence.append(
                    Evidence(
                        request={
                            "method": req.method,
                            "path": req.path,
                            "headers": mask_sensitive(headers),
                            "body": sanitize_request_body(orig_body),
                        },
                        response_status=last_res.status_code,
                        response_headers=mask_sensitive(dict(last_res.headers)),
                        response_body_sample=sanitize_response_sample(last_res.text),
                        note=f"Attempts={len(status_codes)}, LastStatus={last_res.status_code}",
                    )
                )

            # 9) ToolResult 반환
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
                tool_version=self.tool_version,
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
                owasp=[],
                cwe=[],
                recommendation="요청 시간이 초과되었습니다. 네트워크 상태를 확인하세요.",
                started_at=started_at,
                ended_at=ended_at,
                duration_ms=0,
                tool_version=self.tool_version,
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
                owasp=[],
                cwe=[],
                recommendation="네트워크 연결 및 요청 형식을 확인하세요.",
                started_at=started_at,
                ended_at=ended_at,
                duration_ms=0,
                tool_version=self.tool_version,
            )

        except Exception as e:
            logging.exception("BruteForceTool internal error")
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
                recommendation="도구 내부 오류입니다. 로그를 확인하세요.",
                started_at=started_at,
                ended_at=ended_at,
                duration_ms=0,
                tool_version=self.tool_version,
            )