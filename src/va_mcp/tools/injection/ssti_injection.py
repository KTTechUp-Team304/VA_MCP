"""
SSTI (Server-Side Template Injection) Testing Tool

OWASP: A05:2025 - Injection
CWE:   CWE-1336 (SSTI)

extra 옵션:
    - payload_list (list[dict]): 테스트할 SSTI 페이로드 목록
      각 항목은 {"payload": str, "expected": str} 형태
      기본값: 기본 템플릿 엔진별 페이로드 세트 사용

주의:
    - 카나리 검증을 위해 max_requests는 최소 2 이상이어야 합니다.
      1로 설정 시 카나리 검증 없이 결과를 반환하며,
      이 경우 confidence가 HIGH 대신 MEDIUM으로 설정됩니다.
"""

from __future__ import annotations

import requests
import time
from typing import Any, Dict, List
from urllib.parse import urljoin

from va_mcp.core.base import BaseTool
from va_mcp.core.schemas import ToolInput, ToolResult, Evidence
from va_mcp.core.constants import ToolStatus, Severity, Confidence, ErrorCode
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


# ── 기본 SSTI 페이로드 (페이로드 → 기대 결과 매핑) ─────────────────────
DEFAULT_PAYLOADS = [
    {"payload": "{{7*7}}", "expected": "49"},           # Jinja2 / Twig
    {"payload": "{{7*'7'}}", "expected": "7777777"},    # Jinja2 특화
    {"payload": "${7*7}", "expected": "49"},             # Mako / Freemarker
    {"payload": "<%= 7*7 %>", "expected": "49"},         # ERB (Ruby)
    {"payload": "#{7*7}", "expected": "49"},             # Pebble / Java EL
    {"payload": "{7*7}", "expected": "49"},              # Smarty
]

# 카나리 검증에 필요한 최소 요청 수
MIN_REQUESTS_FOR_CANARY = 2


def _validate_payload_entry(entry: object) -> bool:
    """페이로드 항목이 올바른 형식인지 검증"""
    if not isinstance(entry, dict):
        return False
    if "payload" not in entry or "expected" not in entry:
        return False
    if not isinstance(entry["payload"], str) or not isinstance(entry["expected"], str):
        return False
    return True


class SstiInjectionTool(BaseTool):
    """
    SSTI (Server-Side Template Injection) Testing

    서버 사이드 템플릿 엔진에 삽입된 데이터를 통해 임의 코드 실행 여부를 파악합니다.
    """
    tool_id = "ssti_injection"
    tool_name = "SSTI (Server-Side Template Injection) Testing"
    tool_version = "0.1.0"

    def run(self, tool_input: ToolInput) -> ToolResult:
        start_ts   = time.time()
        started_at = utc_now_iso()

        # 1) request 방어
        req = tool_input.request
        if not req:
            ended_at   = utc_now_iso()
            duration_ms = int((time.time() - start_ts) * 1000)
            return ToolResult(
                tool_id=self.tool_id,
                tool_name=self.tool_name,
                status=ToolStatus.SKIPPED.value,
                severity=Severity.INFO.value,
                confidence=Confidence.LOW.value,
                title="요청 정보 없음",
                description="ToolInput.request가 None입니다.",
                evidence=[],
                started_at=started_at,
                ended_at=ended_at,
                duration_ms=duration_ms,
                tool_version=self.tool_version,
            )

        # 2) options/extra 방어
        opts: Any = tool_input.options
        extra: Dict[str, Any] = opts.extra if opts and opts.extra else {}
        timeout_s = (opts.timeout / 1000.0) if opts and opts.timeout else 5
        max_req   = opts.max_requests if opts and opts.max_requests is not None else MIN_REQUESTS_FOR_CANARY

        # 3) 커스텀 페이로드 검증 및 목록 생성
        raw_list = extra.get("payload_list", DEFAULT_PAYLOADS)
        payload_list: List[Dict[str,str]] = []
        invalid_entries: List[str] = []
        for i, entry in enumerate(raw_list):
            if _validate_payload_entry(entry):
                payload_list.append(entry)
            else:
                invalid_entries.append(f"[{i}] {repr(entry)}")

        if not payload_list:
            ended_at   = utc_now_iso()
            duration_ms = int((time.time() - start_ts) * 1000)
            return ToolResult(
                tool_id=self.tool_id,
                tool_name=self.tool_name,
                status=ToolStatus.ERROR.value,
                severity=Severity.INFO.value,
                confidence=Confidence.LOW.value,
                title="페이로드 형식 오류",
                description=(
                    "모든 커스텀 페이로드가 잘못된 형식입니다. "
                    '각 항목은 {"payload": str, "expected": str} 형태여야 합니다. '
                    f"잘못된 항목: {', '.join(invalid_entries[:5])}"
                ),
                evidence=[],
                errors=[build_tool_error(
                    ErrorCode.INVALID_INPUT.value,
                    '페이로드는 {"payload": str, "expected": str} 형식의 dict 리스트여야 합니다.',
                    retryable=False,
                )],
                started_at=started_at,
                ended_at=ended_at,
                duration_ms=duration_ms,
                tool_version=self.tool_version,
            )

        # 카나리 검증 가능 여부
        canary_enabled = max_req >= MIN_REQUESTS_FOR_CANARY

        # 4) 테스트할 파라미터 결정
        method = req.method.upper()
        path   = req.path
        query  = req.query or {}
        body   = req.body or {}
        if method == "GET":
            test_params = list(query.keys())
        else:
            test_params = list(body.keys())

        if not test_params:
            ended_at   = utc_now_iso()
            duration_ms = int((time.time() - start_ts) * 1000)
            return ToolResult(
                tool_id=self.tool_id,
                tool_name=self.tool_name,
                status=ToolStatus.SKIPPED.value,
                severity=Severity.INFO.value,
                confidence=Confidence.LOW.value,
                title="테스트할 파라미터 없음",
                description="요청에서 테스트할 파라미터를 찾지 못했습니다.",
                evidence=[],
                started_at=started_at,
                ended_at=ended_at,
                duration_ms=duration_ms,
                tool_version=self.tool_version,
            )

        # 5) URL 조합
        base_url = tool_input.target.base_url.rstrip("/")
        full_url = urljoin(f"{base_url}/", path.lstrip("/"))

        # 6) headers 방어 및 auth 처리
        orig_headers = req.headers or {}
        auth_ctx = tool_input.auth[0] if tool_input.auth else None
        if auth_ctx:
            try:
                parse_credentials(auth_ctx)
                auth_hdrs = resolve_auth_headers(auth_ctx)
                headers = {**orig_headers, **auth_hdrs}
            except CredentialResolverError as e:
                ended_at   = utc_now_iso()
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

        evidences: List[Evidence] = []
        request_count = 0

        try:
            # 7) 페이로드 테스트 루프
            for param in test_params:
                for entry in payload_list:
                    if request_count >= max_req:
                        break

                    pl = entry["payload"]
                    exp = entry["expected"]

                    if method == "GET":
                        test_q = dict(query)
                        test_q[param] = pl
                        resp = requests.get(
                            full_url,
                            params=test_q,
                            headers=headers,
                            timeout=timeout_s,
                            allow_redirects=False,
                        )
                        req_info = {
                            "method": "GET",
                            "path": path,
                            "headers": mask_sensitive(headers),
                            "query": {param: pl},
                        }
                    else:
                        test_b = dict(body)
                        test_b[param] = pl
                        resp = requests.request(
                            method,
                            full_url,
                            headers=headers,
                            json=test_b,
                            timeout=timeout_s,
                            allow_redirects=False,
                        )
                        req_info = {
                            "method": method,
                            "path": path,
                            "headers": mask_sensitive(headers),
                            "body": sanitize_request_body(test_b),
                        }

                    request_count += 1

                    # 템플릿 연산 결과가 응답에 포함되는지 확인
                    text = resp.text or ""
                    if exp in text:
                        # 카나리 검증
                        canary_skipped = False
                        if canary_enabled and request_count < max_req:
                            try:
                                if method == "GET":
                                    c_q = dict(query)
                                    c_q[param] = "SSTI_CANARY_98765"
                                    c_resp = requests.get(
                                        full_url,
                                        params=c_q,
                                        headers=headers,
                                        timeout=timeout_s,
                                        allow_redirects=False,
                                    )
                                else:
                                    c_b = dict(body)
                                    c_b[param] = "SSTI_CANARY_98765"
                                    c_resp = requests.request(
                                        method,
                                        full_url,
                                        headers=headers,
                                        json=c_b,
                                        timeout=timeout_s,
                                        allow_redirects=False,
                                    )
                                request_count += 1
                                if exp in (c_resp.text or ""):
                                    continue
                            except requests.RequestException:
                                request_count += 1
                        else:
                            canary_skipped = True

                        evidences.append(
                            Evidence(
                                request=req_info,
                                response_status=resp.status_code,
                                response_headers=dict(resp.headers),
                                response_body_sample=sanitize_response_sample(text),
                                note=(
                                    f"파라미터 '{param}'에 페이로드 '{pl}' 삽입 시 "
                                    f"템플릿 연산 결과 '{exp}' 포함"
                                    + (" (카나리 검증 생략)" if canary_skipped else "")
                                ),
                            )
                        )

                if request_count >= max_req:
                    break

            ended_at   = utc_now_iso()
            duration_ms = int((time.time() - start_ts) * 1000)

            # 8) 결과 판정
            if evidences:
                conf = Confidence.MEDIUM if canary_skipped else Confidence.HIGH
                return ToolResult(
                    tool_id=self.tool_id,
                    tool_name=self.tool_name,
                    status=ToolStatus.VULNERABLE.value,
                    severity=Severity.CRITICAL.value,
                    confidence=conf.value,
                    title="SSTI (Server-Side Template Injection) 취약점 발견",
                    description=(
                        f"총 {len(evidences)}건의 SSTI 징후가 감지되었습니다. "
                        f"테스트 파라미터: {test_params}"
                    ),
                    owasp=["A05:2025 Injection"],
                    cwe=["CWE-1336"],
                    evidence=evidences,
                    recommendation=(
                        "사용자 입력을 템플릿에 직접 삽입하지 마세요. "
                        "샌드박스 템플릿 엔진 사용과 입력 검증을 적용하세요."
                    ),
                    started_at=started_at,
                    ended_at=ended_at,
                    duration_ms=duration_ms,
                    tool_version=self.tool_version,
                )

            # PASSED
            return ToolResult(
                tool_id=self.tool_id,
                tool_name=self.tool_name,
                status=ToolStatus.PASSED.value,
                severity=Severity.INFO.value,
                confidence=Confidence.MEDIUM.value,
                title="SSTI 취약점 미발견",
                description=(
                    f"테스트한 파라미터({test_params})에서 SSTI 징후 미감지 "
                    f"(총 {request_count}회 요청)"
                ),
                evidence=[],
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
                title="SSTI 테스트 실행 오류",
                description=str(exc),
                evidence=[],
                errors=[build_tool_error(ErrorCode.INTERNAL_ERROR.value, str(exc), retryable=False)],
                started_at=started_at,
                ended_at=ended_at,
                duration_ms=0,
                tool_version=self.tool_version,
            )