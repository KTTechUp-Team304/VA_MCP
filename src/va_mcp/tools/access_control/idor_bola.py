"""
IDOR / BOLA (Insecure Direct Object Reference / Broken Object Level Authorization) 테스트 도구.

소유자/공격자 역할:
  request.path(또는 params)의 리소스 ID와 JWT payload(sub 등)를 비교해 결정한다.
  - 소유자: JWT subject == path 리소스 ID
  - 공격자: 그 외 auth 중 하나 (동률 시 역할 rank가 낮은 계정)

request.path 예: /api/users/2/profile  (리소스 ID 2)

SKIPPED 조건:
  - request 없음
  - auth 2개 미만
  - path에서 교차 객체 리소스 ID 추출 불가 (/me 등)
  - 리소스 ID와 매칭되는 소유자 JWT 없음
  - 소유자 요청 실패(2xx 아님)
  - 양쪽 응답 본문이 모두 비어 있음 ([], {} 등) — IDOR 입증 불가
"""

from __future__ import annotations

import base64
import json
import re
from typing import Any

import requests

from va_mcp.core import (
    AuthContext,
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

_ROLE_RANK = {"guest": 0, "student": 1, "user": 1, "instructor": 2, "admin": 3}

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
    """
    path/params에서 교차 객체 테스트용 리소스 ID를 추출한다.
    /me 등 컨텍스트 전용 경로는 None.
    """
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


def jwt_subject(token: str | None) -> str | None:
    """Bearer JWT payload에서 사용자 ID(sub, userId, id)를 추출한다."""
    if not token or token.count(".") < 2:
        return None
    segment = token.split(".")[1]
    padding = 4 - (len(segment) % 4)
    if padding != 4:
        segment += "=" * padding
    try:
        payload = json.loads(base64.urlsafe_b64decode(segment))
    except (json.JSONDecodeError, ValueError, UnicodeDecodeError):
        return None
    if not isinstance(payload, dict):
        return None
    for key in ("sub", "userId", "user_id", "id"):
        if key in payload and payload[key] is not None:
            return str(payload[key])
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


def resolve_idor_pair(
    auth: list[AuthContext],
    path: str,
    params: dict[str, Any] | None,
) -> tuple[AuthContext | None, AuthContext | None, str | None]:
    """
    (attacker, owner, skip_reason) 반환.
    skip_reason이 있으면 attacker/owner는 None.
    """
    resource_id = extract_resource_id(path, params)
    if resource_id is None:
        return (
            None,
            None,
            "path에서 교차 객체 리소스 ID를 추출할 수 없습니다 (/me 등).",
        )

    owners: list[AuthContext] = []
    others: list[AuthContext] = []
    for ctx in auth:
        sub = jwt_subject(ctx.token)
        if sub is not None and sub == resource_id:
            owners.append(ctx)
        else:
            others.append(ctx)

    if len(owners) != 1:
        return (
            None,
            None,
            f"리소스 ID({resource_id})와 일치하는 소유자 JWT(sub)를 찾을 수 없습니다.",
        )
    if not others:
        return None, None, "비소유자(공격자) auth가 없습니다."

    owner = owners[0]
    attacker = min(others, key=lambda a: _ROLE_RANK.get(getattr(a, "role", ""), 0))
    return attacker, owner, None


class IdorBolaTool(BaseTool):
    tool_id = "idor_bola"
    tool_name = "IDOR / BOLA Testing"
    tool_version = "0.2.0"

    def run(self, tool_input: ToolInput) -> ToolResult:
        started_at = utc_now_iso()

        if not tool_input.request:
            return self._skipped(started_at, "request가 제공되지 않았습니다.")
        if len(tool_input.auth) < 2:
            return self._skipped(
                started_at,
                "auth가 2개 이상 필요합니다.",
            )

        req = tool_input.request
        base = tool_input.target.base_url.rstrip("/")
        url = f"{base}/{req.path.lstrip('/')}"
        timeout_s = (
            tool_input.options.timeout / 1000
            if tool_input.options and tool_input.options.timeout
            else 5
        )

        attacker, owner, skip_reason = resolve_idor_pair(
            tool_input.auth,
            req.path,
            req.params or None,
        )
        if skip_reason:
            return self._skipped(started_at, skip_reason)

        assert attacker is not None and owner is not None

        try:
            parse_credentials(owner)
            owner_headers = resolve_auth_headers(owner)
        except CredentialResolverError as e:
            return self._skipped(
                started_at,
                f"Credential 해석 실패 (owner): {e}",
            )

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
            return self._error(
                started_at,
                ErrorCode.HTTP_FAILURE,
                str(exc),
            )

        if owner_resp.status_code not in (200, 201, 204):
            return self._skipped(
                started_at,
                f"소유자({owner.role}) 요청도 실패({owner_resp.status_code}). 경로 또는 소유자 토큰을 확인하세요.",
            )

        try:
            parse_credentials(attacker)
            attacker_headers = resolve_auth_headers(attacker)
        except CredentialResolverError as e:
            return self._skipped(
                started_at,
                f"Credential 해석 실패 (attacker): {e}",
            )

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
            return self._error(
                started_at,
                ErrorCode.HTTP_FAILURE,
                str(exc),
            )

        ended_at = utc_now_iso()

        if attacker_resp.status_code in (200, 201, 204):
            if is_vacuous_response_body(owner_resp.text) and is_vacuous_response_body(
                attacker_resp.text
            ):
                return self._skipped(
                    started_at,
                    "양쪽 응답이 빈 본문([], {})이라 타 사용자 리소스 교차 접근 여부를 판단할 수 없습니다.",
                )

            bodies_match = (
                attacker_resp.text.strip() == owner_resp.text.strip()
            )
            confidence_level = (
                Confidence.HIGH if bodies_match else Confidence.MEDIUM
            )

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
