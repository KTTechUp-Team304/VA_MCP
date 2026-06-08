"""
IDOR / BOLA (Insecure Direct Object Reference / Broken Object Level Authorization) 테스트 도구.

access_type 기반 교차 접근 테스트:
  resource_context.access_type == "private"일 때만 실행한다.
  auth[0](소유자 역할)로 리소스 접근을 확인한 뒤,
  auth[-1](타 사용자/공격자 역할)으로 동일 리소스에 접근 시도한다.
  타 사용자도 2xx 응답을 받으면 IDOR로 판정한다.

auth 구성:
  auth[0]  = 소유자 역할 (낮은 권한 — resource를 소유한 첫 번째 계정)
  auth[-1] = 공격자 역할 (마지막 계정 — 소유권 없이 접근 시도)

SKIPPED 조건:
  - request 없음
  - auth 2개 미만
  - resource_context.access_type이 "private"이 아님 (공개 리소스)
  - auth[0](소유자) 요청이 2xx 아님 (리소스 접근 불가)
  - 양쪽 응답 본문이 모두 비어 있음 ([], {}) — IDOR 입증 불가
"""

from __future__ import annotations

import json
import re
from typing import Any

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
    mask_sensitive,
    sanitize_response_sample,
    utc_now_iso,
)
from va_mcp.core.resolvers.auth_resolver import (
    parse_credentials,
    resolve_auth_headers,
    CredentialResolverError,
)

_PARAM_ID_KEYS = (
    "userId",
    "user_id",
    "id",
    "enrollmentId",
    "enrollment_id",
    "courseId",
    "course_id",
)


def extract_resource_id(path: str, params: dict[str, Any] | None) -> str | None:
    """path/params에서 리소스 ID를 추출한다 (evidence 기록용)."""
    if params:
        for key in _PARAM_ID_KEYS:
            if key in params and params[key] is not None:
                return str(params[key])
        for value in params.values():
            if value is not None and str(value).isdigit():
                return str(value)

    segments = [p for p in path.strip("/").split("/") if p]
    if not segments or segments[-1] == "me" or "me" in segments:
        return None

    numeric = [p for p in segments if p.isdigit()]
    if numeric:
        return numeric[0]

    # UUID 등 비숫자 ID (간단 패턴)
    for part in reversed(segments):
        if re.fullmatch(r"[0-9a-fA-F-]{8,}", part):
            return part

    return None


def is_vacuous_response_body(text: str) -> bool:
    """IDOR 비교에 쓸 수 없는 빈/무의미 성공 body."""
    stripped = text.strip()
    if not stripped:
        return True
    if stripped in ("[]", "{}"):
        return True
    try:
        parsed = json.loads(stripped)
    except json.JSONDecodeError:
        return False
    return parsed == [] or parsed == {}


class IdorBolaTool(BaseTool):
    """
    IDOR/BOLA 취약점 탐지 도구.
    resource_context.access_type='private' 힌트 기반 교차 접근 테스트로
    비소유자(타 사용자)의 무단 접근 가능 여부를 확인한다.
    """

    tool_id = "idor_bola"
    tool_name = "IDOR / BOLA Testing"
    tool_version = "0.3.0"

    def run(self, tool_input: ToolInput) -> ToolResult:
        started_at = utc_now_iso()

        if not tool_input.request:
            return self._skipped(started_at, "request가 제공되지 않았습니다.")
        if len(tool_input.auth) < 2:
            return self._skipped(started_at, "auth가 2개 이상 필요합니다.")

        # resource_context에서 access_type 확인 — "private"이 아니면 공개 리소스로 간주하여 SKIPPED
        extra = (tool_input.options.extra or {}) if tool_input.options else {}
        resource_context = extra.get("resource_context") or {}
        access_type = resource_context.get("access_type")
        if access_type != "private":
            return self._skipped(
                started_at,
                "resource_context.access_type이 'private'이 아닙니다. "
                "공개 리소스는 IDOR 테스트를 건너뜁니다.",
            )

        req = tool_input.request
        base = tool_input.target.base_url.rstrip("/")
        url = f"{base}/{req.path.lstrip('/')}"
        timeout_s = (
            tool_input.options.timeout / 1000
            if tool_input.options and tool_input.options.timeout
            else 5
        )

        # auth[0] = 소유자(첫 번째 계정), auth[-1] = 공격자(마지막 계정)
        owner = tool_input.auth[0]
        attacker = tool_input.auth[-1]

        # 소유자 접근 확인 — 2xx 아니면 리소스가 없거나 소유자 토큰 문제
        try:
            parse_credentials(owner)
            owner_headers = resolve_auth_headers(owner)
        except CredentialResolverError as e:
            return self._skipped(started_at, f"Credential 해석 실패 (owner): {e}")

        try:
            owner_resp = requests.request(
                method=req.method,
                url=url,
                headers={**(req.headers or {}), **owner_headers},
                params=req.query or None,
                json=req.body,
                timeout=timeout_s,
            )
        except requests.Timeout:
            return self._error(
                started_at,
                ErrorCode.TIMEOUT,
                "HTTP 요청 타임아웃이 발생했습니다.",
                retryable=True,
            )
        except requests.RequestException as exc:
            return self._error(started_at, ErrorCode.HTTP_FAILURE, str(exc))

        if not (200 <= owner_resp.status_code < 300):
            return self._skipped(
                started_at,
                f"소유자({owner.role}) 요청 실패({owner_resp.status_code}). "
                "경로 또는 소유자 토큰을 확인하세요.",
            )

        # 공격자 접근 시도 — 동일 리소스에 타 계정으로 접근
        try:
            parse_credentials(attacker)
            attacker_headers = resolve_auth_headers(attacker)
        except CredentialResolverError as e:
            return self._skipped(started_at, f"Credential 해석 실패 (attacker): {e}")

        try:
            attacker_resp = requests.request(
                method=req.method,
                url=url,
                headers={**(req.headers or {}), **attacker_headers},
                params=req.query or None,
                json=req.body,
                timeout=timeout_s,
            )
        except requests.Timeout:
            return self._error(
                started_at,
                ErrorCode.TIMEOUT,
                "HTTP 요청 타임아웃이 발생했습니다.",
                retryable=True,
            )
        except requests.RequestException as exc:
            return self._error(started_at, ErrorCode.HTTP_FAILURE, str(exc))

        ended_at = utc_now_iso()

        if 200 <= attacker_resp.status_code < 300:
            if is_vacuous_response_body(owner_resp.text) and is_vacuous_response_body(
                attacker_resp.text
            ):
                return self._skipped(
                    started_at,
                    "양쪽 응답이 빈 본문([], {})이라 타 사용자 리소스 교차 접근 여부를 판단할 수 없습니다.",
                )

            bodies_match = attacker_resp.text.strip() == owner_resp.text.strip()
            confidence_level = Confidence.HIGH if bodies_match else Confidence.MEDIUM

            evidence = Evidence(
                request={
                    "method": req.method,
                    "url": url,
                    "headers": mask_sensitive(dict(attacker_resp.request.headers)),
                    "attacker_role": attacker.role,
                    "owner_role": owner.role,
                    "resource_id": extract_resource_id(req.path, req.params or None),
                },
                response_status=attacker_resp.status_code,
                response_headers=dict(attacker_resp.headers),
                response_body_sample=sanitize_response_sample(attacker_resp.text),
                note=(
                    f"공격자({attacker.role})가 소유자({owner.role})의 리소스에 접근 성공. "
                    f"응답 body {'소유자 응답과 일치' if bodies_match else '소유자 응답과 상이'}."
                ),
            )

            return ToolResult(
                tool_id=self.tool_id,
                tool_name=self.tool_name,
                status=ToolStatus.VULNERABLE,
                severity=Severity.HIGH,
                confidence=confidence_level,
                title="타 사용자 리소스 무단 접근 가능 (IDOR/BOLA)",
                description=(
                    f"공격자({attacker.role})가 소유자({owner.role})의 리소스({req.path})에 "
                    f"HTTP {attacker_resp.status_code} 응답으로 접근에 성공했습니다."
                ),
                owasp=["A01:2025 Broken Access Control"],
                cwe=["CWE-639"],
                evidence=[evidence],
                recommendation=(
                    "리소스 접근 시 요청자의 ID와 리소스 소유자 ID를 서버 측에서 반드시 비교 검증하세요. "
                    "클라이언트가 전달하는 ID만 신뢰하지 마세요."
                ),
                started_at=started_at,
                ended_at=ended_at,
                duration_ms=0,
            )

        return ToolResult(
            tool_id=self.tool_id,
            tool_name=self.tool_name,
            status=ToolStatus.PASSED,
            severity=Severity.INFO,
            confidence=Confidence.HIGH,
            title="타 사용자 리소스 접근 차단 확인",
            description=(
                f"공격자({attacker.role})의 접근이 {attacker_resp.status_code}으로 차단되었습니다."
            ),
            owasp=["A01:2025 Broken Access Control"],
            cwe=["CWE-639"],
            started_at=started_at,
            ended_at=ended_at,
            duration_ms=0,
        )

    def _skipped(self, started_at: str, reason: str) -> ToolResult:
        return ToolResult(
            tool_id=self.tool_id,
            tool_name=self.tool_name,
            status=ToolStatus.SKIPPED,
            severity=Severity.INFO,
            confidence=Confidence.LOW,
            title="테스트 건너뜀",
            description=reason,
            started_at=started_at,
            ended_at=utc_now_iso(),
        )

    def _error(
        self,
        started_at: str,
        error_code: ErrorCode,
        message: str,
        retryable: bool = False,
    ) -> ToolResult:
        return ToolResult(
            tool_id=self.tool_id,
            tool_name=self.tool_name,
            status=ToolStatus.ERROR,
            severity=Severity.INFO,
            confidence=Confidence.LOW,
            title="실행 오류",
            description=message,
            started_at=started_at,
            ended_at=utc_now_iso(),
            errors=[build_tool_error(error_code, message, retryable=retryable)],
        )
