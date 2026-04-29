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
    """JWT 세그먼트를 base64url 디코딩한다."""
    padding = 4 - len(segment) % 4
    if padding != 4:
        segment += "=" * padding
    return base64.urlsafe_b64decode(segment).decode("utf-8", errors="replace")


class InsecureJwtTool(BaseTool):
    """
    JWT를 정적으로 분석하여 알고리즘, 만료 정책, 민감 정보 포함 여부를 검사한다.

    - 취약점 발견 시: VULNERABLE
    - 이상 없음:    PASSED
    """

    tool_id = "insecure_jwt"
    tool_name = "Insecure JWT Analysis"

    def run(self, tool_input: ToolInput) -> ToolResult:
        started_at = utc_now_iso()

        try:
            # ── 입력 검증: JWT 토큰 추출 ──
            if not tool_input.auth:
                ended_at = utc_now_iso()
                return ToolResult(
                    tool_id=self.tool_id,
                    tool_name=self.tool_name,
                    status=ToolStatus.SKIPPED,
                    severity=Severity.INFO,
                    confidence=Confidence.LOW,
                    title="인증 정보 없음",
                    description="auth가 제공되지 않아 JWT 분석을 수행할 수 없습니다.",
                    started_at=started_at,
                    ended_at=ended_at,
                )

            token = tool_input.auth[0].token
            if not token:
                ended_at = utc_now_iso()
                return ToolResult(
                    tool_id=self.tool_id,
                    tool_name=self.tool_name,
                    status=ToolStatus.SKIPPED,
                    severity=Severity.INFO,
                    confidence=Confidence.LOW,
                    title="JWT 토큰 없음",
                    description="auth[0].token이 비어 있어 JWT 분석을 수행할 수 없습니다.",
                    started_at=started_at,
                    ended_at=ended_at,
                )

            # ── JWT 구조 검증 ──
            parts = token.split(".")
            if len(parts) != 3:
                ended_at = utc_now_iso()
                return ToolResult(
                    tool_id=self.tool_id,
                    tool_name=self.tool_name,
                    status=ToolStatus.ERROR,
                    severity=Severity.INFO,
                    confidence=Confidence.LOW,
                    title="JWT 형식 오류",
                    description="전달된 토큰이 JWT 형식(header.payload.signature)이 아닙니다.",
                    started_at=started_at,
                    ended_at=ended_at,
                    errors=[
                        build_tool_error(
                            error_code=ErrorCode.INVALID_INPUT,
                            error_message=f"JWT 세그먼트 수가 올바르지 않습니다: {len(parts)}개",
                            retryable=False,
                        )
                    ],
                )

            # ── 헤더/페이로드 디코딩 ──
            try:
                header = json.loads(_b64_decode(parts[0]))
                payload = json.loads(_b64_decode(parts[1]))
            except Exception as exc:
                ended_at = utc_now_iso()
                return ToolResult(
                    tool_id=self.tool_id,
                    tool_name=self.tool_name,
                    status=ToolStatus.ERROR,
                    severity=Severity.INFO,
                    confidence=Confidence.LOW,
                    title="JWT 디코딩 실패",
                    description="JWT 헤더 또는 페이로드를 디코딩할 수 없습니다.",
                    started_at=started_at,
                    ended_at=ended_at,
                    errors=[
                        build_tool_error(
                            error_code=ErrorCode.INVALID_INPUT,
                            error_message=str(exc),
                            retryable=False,
                        )
                    ],
                )

            # 디코딩 결과가 dict인지 확인
            if not isinstance(header, dict) or not isinstance(payload, dict):
                ended_at = utc_now_iso()
                return ToolResult(
                    tool_id=self.tool_id,
                    tool_name=self.tool_name,
                    status=ToolStatus.ERROR,
                    severity=Severity.INFO,
                    confidence=Confidence.LOW,
                    title="JWT 구조 오류",
                    description="JWT 헤더 또는 페이로드가 올바른 JSON 객체 형식이 아닙니다.",
                    started_at=started_at,
                    ended_at=ended_at,
                    errors=[
                        build_tool_error(
                            error_code=ErrorCode.INVALID_INPUT,
                            error_message=(
                                f"header 타입: {type(header).__name__}, "
                                f"payload 타입: {type(payload).__name__}"
                            ),
                            retryable=False,
                        )
                    ],
                )

            # ── 취약점 분석 ──
            issues: list[str] = []
            alg = header.get("alg", "")
            is_none_alg = alg.lower() == "none"
            is_weak_alg = alg in WEAK_ALGORITHMS

            # 1. alg 누락 또는 빈 문자열 검사 (RFC 7515 위반)
            if not alg:
                issues.append(
                    "alg 클레임이 누락되어 있습니다. "
                    "서명 알고리즘을 명시적으로 지정해야 합니다."
                )

            # 2. alg=none 검사 (대소문자 무관)
            elif is_none_alg:
                issues.append(
                    f"알고리즘이 'none'으로 설정되어 서명 검증이 생략됩니다 (alg={alg!r})"
                )

            # 3. 약한 대칭키 알고리즘 검사
            elif is_weak_alg:
                issues.append(
                    f"대칭키 알고리즘({alg})을 사용 중입니다. "
                    "비밀키 유출 또는 brute-force 공격에 취약할 수 있습니다."
                )

            # 4. 알 수 없는 알고리즘 검사
            elif alg not in SAFE_ALGORITHMS:
                issues.append(
                    f"알 수 없는 알고리즘({alg!r})이 사용되었습니다. "
                    "RS256, ES256 등 검증된 비대칭 알고리즘을 사용하세요."
                )

            # 5. 만료(exp) 클레임 부재 검사
            if "exp" not in payload:
                issues.append("만료(exp) 클레임이 없습니다. 토큰이 영구적으로 유효합니다.")

            # 6. 페이로드 내 민감 정보 검사
            sensitive_found = [
                k for k in payload.keys()
                if k.lower() in SENSITIVE_PAYLOAD_KEYS
            ]
            if sensitive_found:
                issues.append(
                    f"페이로드에 민감 정보 키가 포함되어 있습니다: {sensitive_found}. "
                    "JWT는 서명되지만 암호화되지 않으므로 누구나 디코딩할 수 있습니다."
                )

            # ── Evidence 생성 ──
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
                note="JWT 정적 분석 결과",
            )

            ended_at = utc_now_iso()

            if issues:
                evidence.note = " | ".join(issues)
                severity = Severity.HIGH if (not alg or is_none_alg or bool(sensitive_found)) else Severity.MEDIUM
                return ToolResult(
                    tool_id=self.tool_id,
                    tool_name=self.tool_name,
                    status=ToolStatus.VULNERABLE,
                    severity=severity,
                    confidence=Confidence.HIGH,
                    title="JWT 보안 설정 취약",
                    description=(
                        f"JWT 분석 결과 {len(issues)}개의 보안 문제가 발견되었습니다: "
                        + "; ".join(issues)
                    ),
                    owasp=["A04 Cryptographic Failures"],
                    cwe=["CWE-347", "CWE-327"],
                    evidence=[evidence],
                    recommendation=(
                        "RS256 또는 ES256 등 비대칭 알고리즘을 사용하고, "
                        "exp 클레임을 반드시 포함하세요. "
                        "민감 정보는 JWT 페이로드에 절대 포함하지 마세요. "
                        "서버에서 alg=none을 반드시 거부하도록 설정하세요."
                    ),
                    started_at=started_at,
                    ended_at=ended_at,
                )

            evidence.note = "알고리즘, 만료 정책, 페이로드 민감 정보 모두 정상입니다."
            return ToolResult(
                tool_id=self.tool_id,
                tool_name=self.tool_name,
                status=ToolStatus.PASSED,
                severity=Severity.INFO,
                confidence=Confidence.HIGH,
                title="JWT 보안 설정 정상",
                description=(
                    "JWT 알고리즘, 만료 정책, 페이로드 민감 정보 검사에서 이상이 발견되지 않았습니다."
                ),
                owasp=["A04 Cryptographic Failures"],
                cwe=["CWE-347", "CWE-327"],
                evidence=[evidence],
                recommendation=(
                    "JWT 보안 설정이 적절합니다. 주기적으로 알고리즘과 만료 정책을 검토하세요."
                ),
                started_at=started_at,
                ended_at=ended_at,
            )

        except Exception as exc:
            ended_at = utc_now_iso()
            return ToolResult(
                tool_id=self.tool_id,
                tool_name=self.tool_name,
                status=ToolStatus.ERROR,
                severity=Severity.INFO,
                confidence=Confidence.LOW,
                title="실행 오류",
                description="예상치 못한 오류가 발생했습니다.",
                started_at=started_at,
                ended_at=ended_at,
                errors=[
                    build_tool_error(
                        error_code=ErrorCode.INTERNAL_ERROR,
                        error_message=str(exc),
                        retryable=False,
                    )
                ],
            )
