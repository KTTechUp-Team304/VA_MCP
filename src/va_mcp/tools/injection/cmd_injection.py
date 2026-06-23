"""
OS Command Injection Testing Tool

OWASP: A05:2025 - Injection
CWE:   CWE-78 (OS Command Injection)

extra 옵션:
    - payload_list (list[str]): 테스트할 명령어 인젝션 페이로드 목록
      기본값: safe_mode에 따라 자동 선택
"""

from __future__ import annotations

import requests
import time
from typing import Any, Dict, List
from urllib.parse import urljoin, quote

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

# safe_mode=True일 때 사용하는 시간 기반 페이로드
SAFE_PAYLOADS = [
    "; sleep 5", "| sleep 5", "$(sleep 5)", "`sleep 5`",
    "& timeout /t 5", "| ping -c 5 127.0.0.1",
]
SAFE_MODE_THRESHOLD_SEC = 4

# safe_mode=False일 때 사용하는 출력 기반 페이로드
DEFAULT_PAYLOADS = [
    "; ls", "| ls", "& ls",
    "; cat /etc/passwd", "| cat /etc/passwd", "& cat /etc/passwd",
    "; whoami", "| whoami", "& whoami", "$(whoami)", "`whoami`",
    "; dir", "| dir", "& dir",
]

# 명령어 실행 성공 시그니처 (소문자 비교)
CMD_SUCCESS_SIGNATURES = [
    "root:", "daemon:", "/bin/bash", "/bin/sh",
    "uid=", "gid=", "total ", "drwx",
    "volume serial number", "directory of", "<dir>",
]


def _inject_payload_into_path(path: str, original_value: str, new_value: str) -> str:
    """path의 세그먼트 중 원본 path param 값과 정확히 일치하는 세그먼트만 new_value로 치환한다.
    new_value를 percent-encode하여 항상 단일 세그먼트로 고정한다 — 인코딩하지 않으면 payload 안의
    '/'가 경로 구분자로 해석되어 의도한 세그먼트 경계를 벗어난다(기본 payload에는 없지만
    extra.payload_list로 임의 문자열이 들어올 수 있음).
    """
    encoded = quote(new_value, safe="")
    segments = path.split("/")
    return "/".join(encoded if seg == original_value else seg for seg in segments)


class CmdInjectionTool(BaseTool):
    tool_id = "cmd_injection"
    tool_name = "OS Command Injection Testing"
    tool_version = "0.2.0"

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
        max_req = opts.max_requests if opts and opts.max_requests is not None else 1
        safe_mode = opts.safe_mode if opts and hasattr(opts, "safe_mode") else False

        # 3) payload 리스트 선택
        payload_list = (
            extra.get("payload_list", SAFE_PAYLOADS)
            if safe_mode else
            extra.get("payload_list", DEFAULT_PAYLOADS)
        )

        # 4) 테스트할 파라미터 결정
        method = req.method.upper()
        query = req.query or {}
        body  = req.body or {}

        path_params = list((req.params or {}).keys())
        test_params = list(query.keys()) if method == "GET" else list(body.keys())
        test_params = test_params or path_params
        # query/body에 실제 파라미터가 없어 path_params로 폴백한 경우 — 페이로드를 쿼리스트링이
        # 아니라 실제 URL 경로 세그먼트에 주입해야 한다(T-23).
        has_real_params = bool(query) if method == "GET" else bool(body)
        using_path_fallback = not has_real_params and bool(path_params)
        if not test_params:
            ended_at = utc_now_iso()
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

        # 5) URL 안전 조합
        base = tool_input.target.base_url.rstrip("/")
        full_url = urljoin(f"{base}/", req.path.lstrip("/"))

        # 6) headers 방어 및 auth_resolver 적용
        orig_headers = req.headers or {}
        auth_ctx = tool_input.auth[0] if tool_input.auth else None
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

        evidences: List[Evidence] = []
        request_count = 0

        try:
            # 7) 페이로드 테스트
            for param in test_params:
                for payload in payload_list:
                    if request_count >= max_req:
                        break

                    if using_path_fallback:
                        original_value = str((req.params or {}).get(param, ""))
                        combined_value = original_value + payload
                        test_path = _inject_payload_into_path(req.path, original_value, combined_value)
                        test_url = urljoin(f"{base}/", test_path.lstrip("/"))
                        if method == "GET":
                            resp = requests.get(
                                test_url,
                                params=query or None,
                                headers=headers,
                                timeout=timeout_s,
                                allow_redirects=False,
                            )
                        else:
                            resp = requests.request(
                                method,
                                test_url,
                                headers=headers,
                                json=body or None,
                                timeout=timeout_s,
                                allow_redirects=False,
                            )
                        req_info = {
                            "method": method,
                            "path": test_path,
                            "headers": mask_sensitive(headers),
                        }
                    elif method == "GET":
                        test_q = {**query, param: query.get(param, "") + payload}
                        resp = requests.get(
                            full_url,
                            params=test_q,
                            headers=headers,
                            timeout=timeout_s,
                            allow_redirects=False,
                        )
                        req_info = {
                            "method": "GET",
                            "path": req.path,
                            "headers": mask_sensitive(headers),
                            "query": {param: test_q[param]},
                        }
                    else:
                        test_b = {**body}
                        test_b[param] = str(body.get(param, "")) + payload
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
                            "path": req.path,
                            "headers": mask_sensitive(headers),
                            "body": sanitize_request_body(test_b),
                        }

                    request_count += 1

                    if safe_mode:
                        elapsed = resp.elapsed.total_seconds()
                        if elapsed >= SAFE_MODE_THRESHOLD_SEC:
                            evidences.append(
                                Evidence(
                                    request=req_info,
                                    response_status=resp.status_code,
                                    response_headers=dict(resp.headers),
                                    response_body_sample=sanitize_response_sample(resp.text),
                                    note=(
                                        f"파라미터 '{param}'에 페이로드 '{payload}' 삽입 시 "
                                        f"응답 지연 {elapsed:.1f}s 감지 (임계={SAFE_MODE_THRESHOLD_SEC}s)"
                                    ),
                                )
                            )
                    else:
                        low = resp.text.lower()
                        detected = [
                            sig for sig in CMD_SUCCESS_SIGNATURES if sig in low
                        ]
                        if detected:
                            evidences.append(
                                Evidence(
                                    request=req_info,
                                    response_status=resp.status_code,
                                    response_headers=dict(resp.headers),
                                    response_body_sample=sanitize_response_sample(resp.text),
                                    note=(
                                        f"파라미터 '{param}'에 페이로드 '{payload}' 삽입 시 "
                                        f"명령 실행 시그니처 감지: {detected[:3]}"
                                    ),
                                )
                            )

                if request_count >= max_req:
                    break

            ended_at = utc_now_iso()
            duration_ms = int((time.time() - start_ts) * 1000)

            # 8) 결과 판정
            if evidences:
                return ToolResult(
                    tool_id=self.tool_id,
                    tool_name=self.tool_name,
                    status=ToolStatus.VULNERABLE.value,
                    severity=Severity.CRITICAL.value,
                    confidence=(
                        Confidence.MEDIUM.value
                        if safe_mode else Confidence.HIGH.value
                    ),
                    title=(
                        "OS Command Injection (시간 기반)"
                        if safe_mode else "OS Command Injection"
                    ),
                    description=(
                        f"총 {len(evidences)}건의 명령어 인젝션 징후 감지. "
                        f"테스트 파라미터: {test_params}"
                        + (" (safe_mode)" if safe_mode else "")
                    ),
                    owasp=["A05:2025 Injection"],
                    cwe=["CWE-78"],
                    evidence=evidences,
                    recommendation=(
                        "사용자 입력을 OS 명령어에 직접 포함하지 마세요.\n"
                        "subprocess 사용 시 shell=False를 적용하세요.\n"
                        "명령어 인자 화이트리스트를 검증하세요.\n"
                        "최소 권한 원칙을 적용하세요."
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
                title="OS Command Injection 미발견",
                description=(
                    f"테스트한 파라미터({test_params})에서 "
                    f"명령어 인젝션 징후 미감지 (총 {request_count}회 요청)"
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
                title="요청 타임아웃",
                description=str(exc),
                evidence=[],
                errors=[build_tool_error(
                    ErrorCode.TIMEOUT.value, str(exc), retryable=True
                )],
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
                errors=[build_tool_error(
                    ErrorCode.HTTP_FAILURE.value, str(exc), retryable=True
                )],
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
                description=str(exc),
                evidence=[],
                errors=[build_tool_error(
                    ErrorCode.INTERNAL_ERROR.value, str(exc), retryable=False
                )],
                started_at=started_at,
                ended_at=ended_at,
                duration_ms=0,
                tool_version=self.tool_version,
            )