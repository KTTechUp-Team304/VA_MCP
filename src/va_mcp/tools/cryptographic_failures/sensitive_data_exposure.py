"""
Sensitive Data Exposure Check Tool

API 응답에서 민감 정보(이메일, 전화번호, 주민번호, 신용카드번호 등)가
평문으로 노출되는지 정규식 패턴으로 탐지한다.

OWASP: A04 Cryptographic Failures
CWE:   CWE-319 (Cleartext Transmission of Sensitive Information)
       CWE-523 (Unprotected Transport of Credentials)

extra 옵션:
    extra["custom_patterns"] : list[str] - 추가로 탐지할 정규식 패턴 목록 (기본값: [])
"""

from __future__ import annotations

import re

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
import requests

from va_mcp.core.utils import (
    build_tool_error,
    mask_sensitive,
    sanitize_response_sample,
    utc_now_iso,
)

# 기본 민감 정보 탐지 패턴 (패턴명, 정규식)
DEFAULT_PATTERNS: list[tuple[str, str]] = [
    ("이메일", r"[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}"),
    ("전화번호 (한국)", r"0\d{1,2}[-.\s]?\d{3,4}[-.\s]?\d{4}"),
    ("주민등록번호", r"\d{6}[-\s]?\d{7}"),
    ("신용카드번호", r"\b(?:\d{4}[-\s]?){3}\d{4}\b"),
    ("비밀번호 필드 노출", r'(?i)["\']?(?:password|passwd)["\']?\s*:\s*["\'][^"\']+["\']'),
    ("API 키 패턴", r'(?i)(api_key|apikey|access_token|secret_key)\s*[=:]\s*["\']?[A-Za-z0-9_\-]{16,}'),
    ("AWS Access Key", r"AKIA[0-9A-Z]{16}"),
    ("Private Key 헤더", r"-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----"),
]

# 탐지용 응답 텍스트 최대 크기 (500KB) — 대용량 응답 성능 보호
MAX_SCAN_SIZE = 500_000


class SensitiveDataExposureTool(BaseTool):
    """
    API 응답 본문에서 민감 정보가 평문으로 노출되는지 탐지한다.

    - 패턴 매칭 성공 시: VULNERABLE (민감 정보 노출)
    - 패턴 매칭 없음 시: PASSED
    """

    tool_id = "sensitive_data_exposure"
    tool_name = "Sensitive Data Exposure Check"

    def run(self, tool_input: ToolInput) -> ToolResult:
        started_at = utc_now_iso()

        try:
            # ── 입력 검증 ──
            if tool_input.request is None:
                ended_at = utc_now_iso()
                return ToolResult(
                    tool_id=self.tool_id,
                    tool_name=self.tool_name,
                    status=ToolStatus.SKIPPED,
                    severity=Severity.INFO,
                    confidence=Confidence.LOW,
                    title="요청 정보 없음",
                    description="request가 제공되지 않아 검사를 수행할 수 없습니다.",
                    started_at=started_at,
                    ended_at=ended_at,
                )

            # ── extra 옵션 추출 ──
            custom_patterns_raw = tool_input.options.extra.get("custom_patterns", [])

            if not isinstance(custom_patterns_raw, list):
                ended_at = utc_now_iso()
                return ToolResult(
                    tool_id=self.tool_id,
                    tool_name=self.tool_name,
                    status=ToolStatus.ERROR,
                    severity=Severity.INFO,
                    confidence=Confidence.LOW,
                    title="입력값 오류",
                    description="custom_patterns는 리스트여야 합니다.",
                    started_at=started_at,
                    ended_at=ended_at,
                    errors=[
                        build_tool_error(
                            error_code=ErrorCode.INVALID_INPUT,
                            error_message=f"custom_patterns 값이 유효하지 않습니다: {custom_patterns_raw}",
                            retryable=False,
                        )
                    ],
                )

            # 사용자 정의 패턴 추가
            patterns = list(DEFAULT_PATTERNS)
            for i, pat in enumerate(custom_patterns_raw):
                if isinstance(pat, str):
                    patterns.append((f"사용자 정의 패턴 #{i + 1}", pat))

            # ── URL 조립 ──
            base_url = tool_input.target.base_url.rstrip("/")
            path = tool_input.request.path
            url = f"{base_url}{path}"

            method = tool_input.request.method.upper()
            headers = dict(tool_input.request.headers)
            query = dict(tool_input.request.query)
            body = tool_input.request.body
            timeout_sec = tool_input.options.timeout / 1000

            # ── 인증 헤더 주입 ──
            if tool_input.auth:
                auth_ctx = tool_input.auth[0]
                if auth_ctx.auth_type == "bearer" and auth_ctx.token:
                    headers["Authorization"] = f"Bearer {auth_ctx.token}"
                elif auth_ctx.auth_type == "cookie" and auth_ctx.cookie:
                    headers["Cookie"] = auth_ctx.cookie

            # ── 요청 전송 ──
            resp = requests.request(
                method=method,
                url=url,
                headers=headers,
                params=query,
                json=body if method in ("POST", "PUT", "PATCH") else None,
                timeout=timeout_sec,
            )

            # 탐지용 텍스트는 MAX_SCAN_SIZE 로 제한 (성능 보호)
            response_text = resp.text[:MAX_SCAN_SIZE]

            # ── 패턴 매칭 ──
            matched: list[str] = []          # 탐지된 패턴명 목록
            invalid_patterns: list[str] = [] # 유효하지 않은 정규식 패턴명

            for pattern_name, pattern_regex in patterns:
                try:
                    found = re.search(pattern_regex, response_text)
                    if found:
                        matched.append(pattern_name)
                except re.error:
                    invalid_patterns.append(pattern_name)

            # ── 결과 판정 ──
            evidence = Evidence(
                request={
                    "method": method,
                    "url": url,
                    "headers": mask_sensitive(headers),
                },
                response_status=resp.status_code,
                response_headers=dict(resp.headers),
                response_body_sample=sanitize_response_sample(response_text),
                note="",
            )

            invalid_note = (
                f" (유효하지 않은 정규식 {len(invalid_patterns)}개 스킵: "
                f"{', '.join(invalid_patterns)})"
                if invalid_patterns else ""
            )

            if matched:
                match_summary = ", ".join(matched)
                evidence.note = (
                    f"다음 민감 정보 패턴이 응답에서 발견되었습니다: {match_summary}{invalid_note}"
                )
                ended_at = utc_now_iso()
                return ToolResult(
                    tool_id=self.tool_id,
                    tool_name=self.tool_name,
                    status=ToolStatus.VULNERABLE,
                    severity=Severity.HIGH,
                    confidence=Confidence.MEDIUM,
                    title="민감 정보 노출 탐지",
                    description=(
                        f"API 응답에서 민감 정보가 평문으로 노출되었습니다. "
                        f"탐지된 패턴: {match_summary}"
                    ),
                    owasp=["A04 Cryptographic Failures"],
                    cwe=["CWE-319", "CWE-523"],
                    evidence=[evidence],
                    recommendation=(
                        "응답에서 불필요한 민감 정보를 제거하거나 마스킹하세요. "
                        "비밀번호, API 키, 개인식별정보(PII)는 절대 응답 본문에 포함하지 마세요. "
                        "전송 계층에서 TLS 암호화를 반드시 적용하세요."
                    ),
                    started_at=started_at,
                    ended_at=ended_at,
                )

            evidence.note = f"응답에서 민감 정보 패턴이 발견되지 않았습니다.{invalid_note}"
            ended_at = utc_now_iso()
            return ToolResult(
                tool_id=self.tool_id,
                tool_name=self.tool_name,
                status=ToolStatus.PASSED,
                severity=Severity.INFO,
                confidence=Confidence.MEDIUM,
                title="민감 정보 노출 없음",
                description="API 응답에서 기본 패턴에 해당하는 민감 정보가 탐지되지 않았습니다.",
                owasp=["A04 Cryptographic Failures"],
                cwe=["CWE-319", "CWE-523"],
                evidence=[evidence],
                recommendation="민감 정보가 응답에 포함되지 않도록 정기적으로 점검하세요.",
                started_at=started_at,
                ended_at=ended_at,
            )

        except requests.exceptions.Timeout as exc:
            ended_at = utc_now_iso()
            return ToolResult(
                tool_id=self.tool_id,
                tool_name=self.tool_name,
                status=ToolStatus.ERROR,
                severity=Severity.INFO,
                confidence=Confidence.LOW,
                title="요청 시간 초과",
                description="대상 서버로의 요청이 시간 초과되었습니다.",
                started_at=started_at,
                ended_at=ended_at,
                errors=[
                    build_tool_error(
                        error_code=ErrorCode.TIMEOUT,
                        error_message=str(exc),
                        retryable=True,
                    )
                ],
            )

        except requests.exceptions.RequestException as exc:
            ended_at = utc_now_iso()
            return ToolResult(
                tool_id=self.tool_id,
                tool_name=self.tool_name,
                status=ToolStatus.ERROR,
                severity=Severity.INFO,
                confidence=Confidence.LOW,
                title="HTTP 요청 실패",
                description="대상 서버로의 HTTP 요청이 실패했습니다.",
                started_at=started_at,
                ended_at=ended_at,
                errors=[
                    build_tool_error(
                        error_code=ErrorCode.HTTP_FAILURE,
                        error_message=str(exc),
                        retryable=True,
                    )
                ],
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
