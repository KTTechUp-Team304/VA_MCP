"""
Insecure JWT Analysis Tool

인증 컨텍스트에서 JWT를 추출하여 정적 분석을 수행한다.
알고리즘 취약성, 만료 정책 부재, 페이로드 내 민감 정보 포함 여부를 검사한다.

OWASP: A04 Cryptographic Failures
CWE:   CWE-347 (Improper Verification of Cryptographic Signature)
       CWE-327 (Use of a Broken or Risky Cryptographic Algorithm)

* HTTP 요청 없이 JWT 자체를 정적 분석하므로 request 없이도 동작한다.
* auth[0].token에 JWT가 담겨 있어야 한다.
"""

from __future__ import annotations

import base64
import json
import time
from typing import Any, Dict, List

import requests

from va_mcp.core import (
    BaseTool,
    Confidence,
    ErrorCode,
    Evidence,
    Severity,
    ToolInput,
    ToolResult,
    ToolStatus,
)
from va_mcp.core.utils import (
    build_tool_error,
    utc_now_iso,
)
from va_mcp.core.resolvers.auth_resolver import (
    parse_credentials,
    resolve_auth_headers,
    CredentialResolverError,
)

# 대칭키 알고리즘 (비밀키 유출 시 위조 가능)
WEAK_ALGORITHMS = {"HS256", "HS384", "HS512"}

# 안전한 비대칭 알고리즘 목록
SAFE_ALGORITHMS = {
    "RS256", "RS384", "RS512",
    "ES256", "ES384", "ES512",
    "PS256", "PS384", "PS512",
}

# 페이로드에 포함되면 안 되는 민감 정보 키
SENSITIVE_PAYLOAD_KEYS = {
    "password", "passwd", "secret", "private_key", "api_key",
    "ssn", "credit_card", "card_number", "cvv", "pin",
}


def _b64_decode(segment: str) -> str:
    """JWT 세그먼트를 base64url 디코딩합니다."""
    padding = 4 - (len(segment) % 4)
    if padding != 4:
        segment += "=" * padding
    return base64.urlsafe_b64decode(segment).decode(
        "utf-8", errors="replace"
    )


class InsecureJwtTool(BaseTool):
    """
    JWT를 정적으로 분석하여 알고리즘, 만료 정책, 민감 정보 포함 여부를 검사합니다.

    - 취약점 발견 시: VULNERABLE
    - 이상 없음:       PASSED
    """
    tool_id = "insecure_jwt"
    tool_name = "Insecure JWT Analysis"
    tool_version = "0.1.0"

    def run(self, tool_input: ToolInput) -> ToolResult:
        start_ts   = time.time()
        started_at = utc_now_iso()

        # 1) auth 방어
        auth_list = tool_input.auth
        if not auth_list:
            ended_at = utc_now_iso()
            duration_ms = int((time.time() - start_ts) * 1000)
            return ToolResult(
                tool_id=self.tool_id,
                tool_name=self.tool_name,
                status=ToolStatus.SKIPPED.value,
                severity=Severity.INFO.value,
                confidence=Confidence.LOW.value,
                title="인증 정보 없음",
                description="auth가 제공되지 않아 JWT 분석을 수행할 수 없습니다.",
                evidence=[],
                started_at=started_at,
                ended_at=ended_at,
                duration_ms=duration_ms,
                tool_version=self.tool_version,
            )

        token_raw = auth_list[0].token
        if not token_raw:
            ended_at = utc_now_iso()
            duration_ms = int((time.time() - start_ts) * 1000)
            return ToolResult(
                tool_id=self.tool_id,
                tool_name=self.tool_name,
                status=ToolStatus.SKIPPED.value,
                severity=Severity.INFO.value,
                confidence=Confidence.LOW.value,
                title="JWT 토큰 없음",
                description="auth[0].token이 비어 있어 JWT 분석을 수행할 수 없습니다.",
                evidence=[],
                started_at=started_at,
                ended_at=ended_at,
                duration_ms=duration_ms,
                tool_version=self.tool_version,
            )

        # 2) Bearer 접두사 제거
        token = token_raw
        if token.lower().startswith("bearer "):
            token = token[7:]

        # 3) JWT 구조 분리
        parts = token.split(".")
        if len(parts) != 3:
            ended_at = utc_now_iso()
            duration_ms = int((time.time() - start_ts) * 1000)
            return ToolResult(
                tool_id=self.tool_id,
                tool_name=self.tool_name,
                status=ToolStatus.ERROR.value,
                severity=Severity.INFO.value,
                confidence=Confidence.LOW.value,
                title="JWT 형식 오류",
                description="전달된 토큰이 JWT 형식(header.payload.signature)이 아닙니다.",
                errors=[build_tool_error(
                    ErrorCode.INVALID_INPUT.value,
                    f"JWT 세그먼트 수가 올바르지 않습니다: {len(parts)}개",
                    retryable=False,
                )],
                started_at=started_at,
                ended_at=ended_at,
                duration_ms=duration_ms,
                tool_version=self.tool_version,
            )

        # 4) header/payload 디코딩
        try:
            header  = json.loads(_b64_decode(parts[0]))
            payload = json.loads(_b64_decode(parts[1]))
        except Exception as e:
            ended_at = utc_now_iso()
            duration_ms = int((time.time() - start_ts) * 1000)
            return ToolResult(
                tool_id=self.tool_id,
                tool_name=self.tool_name,
                status=ToolStatus.ERROR.value,
                severity=Severity.INFO.value,
                confidence=Confidence.LOW.value,
                title="JWT 디코딩 실패",
                description="JWT 헤더 또는 페이로드를 디코딩할 수 없습니다.",
                errors=[build_tool_error(
                    ErrorCode.INVALID_INPUT.value,
                    str(e),
                    retryable=False,
                )],
                started_at=started_at,
                ended_at=ended_at,
                duration_ms=duration_ms,
                tool_version=self.tool_version,
            )

        # 5) 타입 검증
        if not isinstance(header, dict) or not isinstance(payload, dict):
            ended_at = utc_now_iso()
            duration_ms = int((time.time() - start_ts) * 1000)
            return ToolResult(
                tool_id=self.tool_id,
                tool_name=self.tool_name,
                status=ToolStatus.ERROR.value,
                severity=Severity.INFO.value,
                confidence=Confidence.LOW.value,
                title="JWT 구조 오류",
                description="JWT 헤더 또는 페이로드가 올바른 JSON 객체가 아닙니다.",
                errors=[build_tool_error(
                    ErrorCode.INVALID_INPUT.value,
                    f"header 타입: {type(header).__name__}, payload 타입: {type(payload).__name__}",
                    retryable=False,
                )],
                started_at=started_at,
                ended_at=ended_at,
                duration_ms=duration_ms,
                tool_version=self.tool_version,
            )

        # 6) 취약점 분석
        issues: List[str] = []
        alg = header.get("alg", "")
        none_alg = alg.lower() == "none"
        weak_alg = alg in WEAK_ALGORITHMS

        if not alg:
            issues.append("alg 클레임이 누락되어 있습니다.")
        elif none_alg:
            issues.append(f"alg='none'로 서명 검증이 생략됩니다 (alg={alg!r})")
        elif weak_alg:
            issues.append(f"약한 대칭키 알고리즘 사용: {alg}")
        elif alg not in SAFE_ALGORITHMS:
            issues.append(f"알 수 없는 알고리즘 사용: {alg!r}")

        if "exp" not in payload:
            issues.append("만료(exp) 클레임이 없습니다.")

        sensitive = [k for k in payload.keys() if k.lower() in SENSITIVE_PAYLOAD_KEYS]
        if sensitive:
            issues.append(f"페이로드에 민감 정보 포함: {sensitive}")

        # 7) Evidence 생성 (정적 분석이므로 HTTP 정보 없음)
        evidence = Evidence(
            request={
                "token_header": header,
                "token_payload": {
                    k: ("***" if k.lower() in SENSITIVE_PAYLOAD_KEYS else v)
                    for k, v in payload.items()
                },
            },
            response_status=0,
            response_headers={},
            response_body_sample="",
            note="",
        )

        ended_at = utc_now_iso()
        duration_ms = int((time.time() - start_ts) * 1000)

        # 8) 취약 여부 반환
        if issues:
            evidence.note = " | ".join(issues)
            sev = Severity.HIGH if (not alg or none_alg or bool(sensitive)) else Severity.MEDIUM
            return ToolResult(
                tool_id=self.tool_id,
                tool_name=self.tool_name,
                status=ToolStatus.VULNERABLE.value,
                severity=sev.value,
                confidence=Confidence.HIGH.value,
                title="JWT 보안 설정 취약",
                description=f"{len(issues)}개의 보안 문제가 발견되었습니다.",
                owasp=["A04 Cryptographic Failures"],
                cwe=["CWE-347", "CWE-327"],
                evidence=[evidence],
                recommendation=(
                    "비대칭 알고리즘(RS256 등), exp 클레임, 민감 정보 미포함을 보장하세요."
                ),
                started_at=started_at,
                ended_at=ended_at,
                duration_ms=duration_ms,
                tool_version=self.tool_version,
            )

        evidence.note = "알고리즘, exp, 민감 정보 검사 모두 통과"
        return ToolResult(
            tool_id=self.tool_id,
            tool_name=self.tool_name,
            status=ToolStatus.PASSED.value,
            severity=Severity.INFO.value,
            confidence=Confidence.HIGH.value,
            title="JWT 보안 설정 정상",
            description="JWT 설정에 이상이 없습니다.",
            owasp=["A04 Cryptographic Failures"],
            cwe=["CWE-347", "CWE-327"],
            evidence=[evidence],
            recommendation="현재 설정을 유지하세요.",
            started_at=started_at,
            ended_at=ended_at,
            duration_ms=duration_ms,
            tool_version=self.tool_version,
        )