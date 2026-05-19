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
import requests
import time
from typing import Any, Dict, List, Tuple

from va_mcp.core import (
    BaseTool,
    ToolInput,
    ToolResult,
    Evidence,
    ToolStatus,
    Severity,
    Confidence,
    ErrorCode,
    AuthContext,
)
from va_mcp.core.utils import (
    build_tool_error,
    mask_sensitive,
    sanitize_request_body,
    sanitize_response_sample,
    utc_now_iso,
)
from va_mcp.core.resolvers.auth_resolver import (
    parse_credentials,
    resolve_auth_headers,
    CredentialResolverError,
)

# 기본 민감 정보 탐지 패턴 (패턴명, 정규식)
DEFAULT_PATTERNS: List[Tuple[str, str]] = [
    ("이메일", r"[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}"),
    ("전화번호 (한국)", r"0\d{1,2}[-.\s]?\d{3,4}[-.\s]?\d{4}"),
    ("주민등록번호", r"\d{6}[-\s]?\d{7}"),
    ("신용카드번호", r"\b(?:\d{4}[-\s]?){3}\d{4}\b"),
    ("비밀번호 필드 노출", r'(?i)["\']?(?:password|passwd)\w*["\']?\s*:\s*["\'][^"\']{8,}["\']'),
    ("SHA-256 해시 노출", r'\b[0-9a-f]{64}\b'),
    ("bcrypt 해시 노출", r'\$2[aby]\$\d{2}\$[A-Za-z0-9./]{53}'),
    ("API 키 패턴", r'(?i)(api_key|apikey|access_token|accesstoken|secret_key)\s*[=:]\s*["\']?[A-Za-z0-9_\-]{16,}'),
    ("JWT 토큰", r"eyJ[A-Za-z0-9_\-]+\.[A-Za-z0-9_\-]+\.[A-Za-z0-9_\-]+"),
    ("isSensitive 마킹", r'(?i)["\']?isSensitive["\']?\s*:\s*true'),
    ("사용자 ID 노출", r'(?i)["\']?user_?id["\']?\s*:\s*["\']?[A-Za-z0-9\-]+["\']?'),
    ("AWS Access Key", r"AKIA[0-9A-Z]{16}"),
    ("Private Key 헤더", r"-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----"),
    ("서버 내부 파일 경로", r'(?i)["\']?stored_?path["\']?\s*:\s*["\'][^"\']+["\']'),
    ("Unix 절대 경로 노출", r'["\'][/\\](?:uploads|var|tmp|home|srv|opt|etc)[/\\][^"\']{3,}["\']'),
]

# 탐지용 응답 텍스트 최대 크기 (500KB) — 대용량 응답 성능 보호
MAX_SCAN_SIZE = 500_000


class SensitiveDataExposureTool(BaseTool):
    """
    API 응답 본문에서 민감 정보가 평문으로 노출되는지 탐지합니다.

    - 패턴 매칭 성공 시: VULNERABLE
    - 패턴 매칭 없음 시: PASSED
    """
    tool_id = "sensitive_data_exposure"
    tool_name = "Sensitive Data Exposure Check"
    tool_version = "0.1.0"

    def run(self, tool_input: ToolInput) -> ToolResult:
        start_ts   = time.time()
        started_at = utc_now_iso()

        # 1) request 방어
        req = tool_input.request
        if not req:
            ended_at = utc_now_iso()
            return ToolResult(
                tool_id=self.tool_id,
                tool_name=self.tool_name,
                status=ToolStatus.SKIPPED.value,
                severity=Severity.INFO.value,
                confidence=Confidence.LOW.value,
                title="요청 정보 없음",
                description="request가 제공되지 않아 검사를 수행할 수 없습니다.",
                evidence=[],
                started_at=started_at,
                ended_at=ended_at,
                duration_ms=0,
                tool_version=self.tool_version,
            )

        # 2) options/extra 방어
        opts: Any = tool_input.options
        extra: Dict[str, Any] = opts.extra if opts and opts.extra else {}
        timeout_s = (opts.timeout / 1000.0) if opts and opts.timeout else 5
        max_req   = opts.max_requests if opts and opts.max_requests is not None else len(DEFAULT_PATTERNS)

        # 3) 사용자 정의 패턴
        custom_raw = extra.get("custom_patterns", [])
        if not isinstance(custom_raw, list):
            ended_at = utc_now_iso()
            duration_ms = int((time.time() - start_ts) * 1000)
            return ToolResult(
                tool_id=self.tool_id,
                tool_name=self.tool_name,
                status=ToolStatus.ERROR.value,
                severity=Severity.INFO.value,
                confidence=Confidence.LOW.value,
                title="입력값 오류",
                description="custom_patterns는 리스트여야 합니다.",
                evidence=[],
                errors=[build_tool_error(
                    ErrorCode.INVALID_INPUT.value,
                    f"custom_patterns 값이 유효하지 않습니다: {custom_raw}",
                    retryable=False,
                )],
                started_at=started_at,
                ended_at=ended_at,
                duration_ms=duration_ms,
                tool_version=self.tool_version,
            )

        patterns: List[Tuple[str, str]] = list(DEFAULT_PATTERNS)
        for idx, pat in enumerate(custom_raw, start=1):
            if isinstance(pat, str):
                patterns.append((f"사용자 정의 패턴 #{idx}", pat))

        # 4) URL 안전 조합
        base = tool_input.target.base_url.rstrip("/")
        path = req.path.lstrip("/")
        url = f"{base}/{path}"
        method = req.method.upper()

        # 5) headers 방어 및 auth_resolver 적용
        orig_headers = req.headers.copy() if req.headers else {}
        auth_ctx: AuthContext | None = tool_input.auth[0] if tool_input.auth else None
        if auth_ctx:
            try:
                parse_credentials(auth_ctx)
                auth_headers = resolve_auth_headers(auth_ctx)
                headers = {**orig_headers, **auth_headers}
            except CredentialResolverError as e:
                ended_at = utc_now_iso()
                duration_ms = int((time.time() - start_ts) * 1000)
                return ToolResult(
                    tool_id=self.tool_id,
                    tool_name=self.tool_name,
                    status=ToolStatus.SKIPPED.value,
                    severity=Severity.INFO.value,
                    confidence=Confidence.LOW.value,
                    title="Credential 해석 실패",
                    description=str(e),
                    evidence=[],
                    started_at=started_at,
                    ended_at=ended_at,
                    duration_ms=duration_ms,
                    tool_version=self.tool_version,
                )
        else:
            headers = orig_headers

        vulnerable: List[str] = []
        invalid: List[str]    = []

        try:
            # 6) 실제 요청
            resp = requests.request(
                method=method,
                url=url,
                headers=headers,
                params=req.query or None,
                json=req.body if method in ("POST", "PUT", "PATCH") else None,
                timeout=timeout_s,
                allow_redirects=False,
                verify=False,
            )

            # 7) 응답 텍스트 제한
            text = resp.text[:MAX_SCAN_SIZE]

            # 8) 패턴 매칭
            for name, regex in patterns:
                try:
                    if re.search(regex, text):
                        vulnerable.append(name)
                except re.error:
                    invalid.append(name)

            ended_at   = utc_now_iso()
            duration_ms = int((time.time() - start_ts) * 1000)

            # 9) Evidence 생성
            ev = Evidence(
                request={
                    "method": method,
                    "url": url,
                    "headers": mask_sensitive(headers),
                    "body": sanitize_request_body(req.body),
                },
                response_status=resp.status_code,
                response_headers=dict(resp.headers),
                response_body_sample=sanitize_response_sample(text),
                note="",
            )

            # 10) 취약 시
            if vulnerable:
                inv_note = f" (유효하지 않은 패턴 {len(invalid)}개 스킵)" if invalid else ""
                ev.note = (
                    f"{', '.join(vulnerable)} 패턴이 응답에서 발견됨{inv_note}"
                )
                return ToolResult(
                    tool_id=self.tool_id,
                    tool_name=self.tool_name,
                    status=ToolStatus.VULNERABLE.value,
                    severity=Severity.HIGH.value,
                    confidence=Confidence.MEDIUM.value,
                    title="민감 정보 노출 탐지",
                    description=(
                        f"API 응답에서 민감 정보가 평문으로 노출되었습니다: "
                        f"{', '.join(vulnerable)}"
                    ),
                    owasp=["A04 Cryptographic Failures"],
                    cwe=["CWE-319", "CWE-523"],
                    evidence=[ev],
                    recommendation=(
                        "불필요한 민감 정보는 제거 또는 마스킹하고, "
                        "응답 본문에 PII를 제외하세요. TLS 적용 필수."
                    ),
                    started_at=started_at,
                    ended_at=ended_at,
                    duration_ms=duration_ms,
                    tool_version=self.tool_version,
                )

            # 11) PASSED
            inv_note = f" (유효하지 않은 패턴 {len(invalid)}개 스킵)" if invalid else ""
            ev.note = f"민감 정보 패턴 미발견{inv_note}"
            return ToolResult(
                tool_id=self.tool_id,
                tool_name=self.tool_name,
                status=ToolStatus.PASSED.value,
                severity=Severity.INFO.value,
                confidence=Confidence.MEDIUM.value,
                title="민감 정보 미노출",
                description="API 응답에서 기본 패턴에 해당하는 민감 정보가 탐지되지 않았습니다.",
                owasp=["A04 Cryptographic Failures"],
                cwe=["CWE-319", "CWE-523"],
                evidence=[ev],
                recommendation="정기적으로 민감 정보 노출 여부를 점검하세요.",
                started_at=started_at,
                ended_at=ended_at,
                duration_ms=duration_ms,
                tool_version=self.tool_version,
            )

        except requests.Timeout as exc:
            ended_at = utc_now_iso()
            return ToolResult(
                tool_id=self.tool_id,
                tool_name=self.tool_name,
                status=ToolStatus.ERROR.value,
                severity=Severity.INFO.value,
                confidence=Confidence.LOW.value,
                title="요청 시간 초과",
                description=str(exc),
                evidence=[],
                errors=[build_tool_error(ErrorCode.TIMEOUT.value, str(exc), retryable=True)],
                started_at=started_at,
                ended_at=ended_at,
                duration_ms=0,
                tool_version=self.tool_version,
            )

        except requests.RequestException as exc:
            ended_at = utc_now_iso()
            return ToolResult(
                tool_id=self.tool_id,
                tool_name=self.tool_name,
                status=ToolStatus.ERROR.value,
                severity=Severity.INFO.value,
                confidence=Confidence.LOW.value,
                title="HTTP 요청 실패",
                description=str(exc),
                evidence=[],
                errors=[build_tool_error(ErrorCode.HTTP_FAILURE.value, str(exc), retryable=True)],
                started_at=started_at,
                ended_at=ended_at,
                duration_ms=0,
                tool_version=self.tool_version,
            )

        except Exception as exc:
            ended_at = utc_now_iso()
            return ToolResult(
                tool_id=self.tool_id,
                tool_name=self.tool_name,
                status=ToolStatus.ERROR.value,
                severity=Severity.INFO.value,
                confidence=Confidence.LOW.value,
                title="실행 오류",
                description="예상치 못한 오류가 발생했습니다.",
                evidence=[],
                errors=[build_tool_error(ErrorCode.INTERNAL_ERROR.value, str(exc), retryable=False)],
                started_at=started_at,
                ended_at=ended_at,
                duration_ms=0,
                tool_version=self.tool_version,
            )