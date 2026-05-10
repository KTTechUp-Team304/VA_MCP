"""
파라미터 변조 테스트 도구.

권한 관련 파라미터(role, is_admin 등)를 조작하여 접근 제어 우회 가능 여부를 확인한다.
request.query / request.body 에서 권한 관련 키를 자동 탐지하거나 extra로 명시할 수 있다.

auth 구성:
  auth[0] = 테스트에 사용할 인증 컨텍스트 (없으면 비인증 요청)

extra 옵션:
  extra["target_params"] = [
      {"key": "role", "values": ["admin", "superuser"]}
  ]
  → 이 목록이 있으면 자동 탐지 대신 명시된 파라미터만 변조

판단 기준:
  원본 403 → 변조 후 200  → VULNERABLE, severity=HIGH,   confidence=HIGH
  상태코드 동일 + body 변화 → VULNERABLE, severity=MEDIUM, confidence=MEDIUM
  변화 없음               → PASSED, severity=INFO

SKIPPED 조건:
  - request 없음
  - query/body 에 변조 가능한 파라미터가 없음
"""

from __future__ import annotations

import copy
import requests
import time
from typing import Any, Dict, List

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
    sanitize_request_body,
    sanitize_response_sample,
    utc_now_iso,
)
from va_mcp.core.resolvers.auth_resolver import (
    parse_credentials,
    resolve_auth_headers,
    CredentialResolverError,
)

PRIVILEGE_KEYWORDS = {
    "role", "is_admin", "admin", "user_type", "privilege",
    "permission", "access_level", "group", "scope",
}

DEFAULT_PAYLOADS = ["admin", "administrator", "superuser", "root", "true", "1", "0", "-1", "99999"]


class ParameterTamperTool(BaseTool):
    tool_id = "parameter_tamper"
    tool_name = "Parameter Tampering"
    tool_version = "0.1.0"

    def run(self, tool_input: ToolInput) -> ToolResult:
        start_ts = time.time()
        started_at = utc_now_iso()

        # 1) request 방어
        req = tool_input.request
        if not req:
            return self._skipped(started_at, "request가 제공되지 않았습니다.")

        # 2) extra 안전 처리 및 매핑 추출
        extra: Dict[str, Any] = (
            tool_input.options.extra
            if tool_input.options and tool_input.options.extra
            else {}
        )
        mapping: Dict[str, Any] = extra.get("field_mapping", {})

        # 3) 타겟 파라미터 목록 (explicit 또는 자동 탐지)
        explicit: List[Dict[str, Any]] = mapping.get("target_params", [])
        if explicit and isinstance(explicit, list):
            tamper_targets = explicit
        else:
            tamper_targets = self._detect_targets(req.query or {}, req.body or {})

        if not tamper_targets:
            return self._skipped(
                started_at,
                "변조 가능한 권한 관련 파라미터가 발견되지 않았습니다. "
                "extra['field_mapping']['target_params']로 명시하거나 query/body에 권한 관련 키를 포함하세요.",
            )

        # 4) URL/timeout/auth 준비
        base = tool_input.target.base_url.rstrip("/")
        url = f"{base}/{req.path.lstrip('/')}"
        timeout_s = (
            tool_input.options.timeout / 1000
            if tool_input.options and tool_input.options.timeout
            else 5
        )
        auth_ctx: AuthContext | None = tool_input.auth[0] if tool_input.auth else None
        if auth_ctx:
            try:
                parse_credentials(auth_ctx)
                auth_headers = resolve_auth_headers(auth_ctx)
            except CredentialResolverError as e:
                ended_at = utc_now_iso()
                return self._skipped(
                    started_at,
                    f"Credential 해석 실패: {e}",
                )
        else:
            auth_headers = {}

        # 5) 기준 요청
        try:
            original_resp = requests.request(
                method=req.method,
                url=url,
                headers={**(req.headers or {}), **auth_headers},
                params=req.query or None,
                json=req.body,
                timeout=timeout_s,
                allow_redirects=False,
            )
        except requests.Timeout:
            return self._error(started_at, ErrorCode.TIMEOUT, "기준 요청 타임아웃이 발생했습니다.", retryable=True)
        except requests.RequestException as exc:
            return self._error(started_at, ErrorCode.HTTP_FAILURE, str(exc))

        # 6) 변조 시도
        vulnerable_evidences: List[Evidence] = []
        request_count = 1
        max_requests = (
            tool_input.options.max_requests
            if tool_input.options and tool_input.options.max_requests is not None
            else 1
        )

        try:
            for target in tamper_targets:
                key = target.get("key")
                payloads = target.get("values", DEFAULT_PAYLOADS)
                for payload in payloads:
                    if request_count >= max_requests:
                        break

                    # apply tamper
                    tampered_query = copy.deepcopy(req.query or {})
                    tampered_body = copy.deepcopy(req.body or {})
                    if key in tampered_query:
                        tampered_query[key] = str(payload)
                    if isinstance(tampered_body, dict) and key in tampered_body:
                        tampered_body[key] = str(payload)

                    # 요청
                    resp = requests.request(
                        method=req.method,
                        url=url,
                        headers={**(req.headers or {}), **auth_headers},
                        params=tampered_query or None,
                        json=tampered_body,
                        timeout=timeout_s,
                        allow_redirects=False,
                    )
                    request_count += 1

                    # 평가
                    vuln = self._evaluate(
                        url, req.method, key, payload,
                        original_resp, resp, tampered_query, tampered_body,
                    )
                    if vuln:
                        vulnerable_evidences.append(vuln)

        except requests.Timeout:
            return self._error(started_at, ErrorCode.TIMEOUT, "변조 요청 타임아웃이 발생했습니다.", retryable=True)
        except requests.RequestException as exc:
            return self._error(started_at, ErrorCode.HTTP_FAILURE, str(exc))

        ended_at = utc_now_iso()

        # 7) 결과 반환
        if vulnerable_evidences:
            max_severity_is_high = any(
                "상태코드 변화" in e.note for e in vulnerable_evidences
            )
            severity = Severity.HIGH if max_severity_is_high else Severity.MEDIUM
            confidence = Confidence.HIGH if max_severity_is_high else Confidence.MEDIUM

            return ToolResult(
                tool_id=self.tool_id,
                tool_name=self.tool_name,
                status=ToolStatus.VULNERABLE,
                severity=severity,
                confidence=confidence,
                title="파라미터 변조를 통한 접근 제어 우회 가능",
                description=(
                    f"권한 관련 파라미터를 변조하여 접근 제어를 우회하는 데 성공했습니다. "
                    f"취약 케이스 수: {len(vulnerable_evidences)}"
                ),
                owasp=["A01:2025 Broken Access Control"],
                cwe=["CWE-639", "CWE-284"],
                evidence=vulnerable_evidences,
                recommendation=(
                    "서버 측에서 클라이언트가 전달하는 권한 파라미터를 신뢰하지 마세요. "
                    "권한 정보는 서버 세션 또는 토큰에서만 추출하여 검증해야 합니다."
                ),
                started_at=started_at,
                ended_at=ended_at,
            )

        return ToolResult(
            tool_id=self.tool_id,
            tool_name=self.tool_name,
            status=ToolStatus.PASSED,
            severity=Severity.INFO,
            confidence=Confidence.MEDIUM,
            title="파라미터 변조 취약점 미발견",
            description=(
                f"테스트한 파라미터 변조 케이스에서 접근 제어 우회가 확인되지 않았습니다. "
                f"총 요청 수: {request_count}"
            ),
            owasp=["A01:2025 Broken Access Control"],
            cwe=["CWE-639", "CWE-284"],
            started_at=started_at,
            ended_at=ended_at,
        )

    # ------------------------------------------------------------------
    # helpers
    # ------------------------------------------------------------------

    def _detect_targets(
        self, query: dict[str, Any], body: dict[str, Any] | None
    ) -> List[Dict[str, Any]]:
        targets: List[Dict[str, Any]] = []
        keys = set(query.keys())
        if body:
            keys.update(body.keys())
        for k in keys:
            if k.lower() in PRIVILEGE_KEYWORDS:
                targets.append({"key": k, "values": DEFAULT_PAYLOADS})
        return targets

    def _evaluate(
        self,
        url: str,
        method: str,
        key: str,
        payload: Any,
        original_resp: requests.Response,
        tampered_resp: requests.Response,
        tampered_query: dict[str, Any],
        tampered_body: dict[str, Any] | None,
    ) -> Evidence | None:
        orig_status = original_resp.status_code
        new_status = tampered_resp.status_code

        if orig_status in (401, 403) and new_status in (200, 201, 204):
            return Evidence(
                request={
                    "method": method,
                    "url": url,
                    "headers": mask_sensitive(dict(tampered_resp.request.headers)),
                    "tampered_param": {key: payload},
                    "query": tampered_query,
                    "body": sanitize_request_body(tampered_body),
                },
                response_status=new_status,
                response_headers=dict(tampered_resp.headers),
                response_body_sample=sanitize_response_sample(tampered_resp.text),
                note=f"상태코드 변화({orig_status}→{new_status}): {key}={payload} 변조로 접근 성공",
            )

        if orig_status == new_status and tampered_resp.text.strip() != original_resp.text.strip():
            return Evidence(
                request={
                    "method": method,
                    "url": url,
                    "headers": mask_sensitive(dict(tampered_resp.request.headers)),
                    "tampered_param": {key: payload},
                    "query": tampered_query,
                    "body": sanitize_request_body(tampered_body),
                },
                response_status=new_status,
                response_headers=dict(tampered_resp.headers),
                response_body_sample=sanitize_response_sample(tampered_resp.text),
                note=f"body 변화(status {new_status} 유지): {key}={payload} 변조 후 응답 내용 변경됨",
            )

        return None

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