"""
SQL Injection Tool 테스트 (1단계: Mock)

필수 3종:
  - test_passed: 취약점 미발견 → PASSED
  - test_vulnerable: SQL 에러 시그니처 감지 → VULNERABLE + evidence
  - test_error: 예외 발생 → ERROR + errors
"""

from __future__ import annotations

from unittest.mock import MagicMock, patch

from va_mcp.core.constants import Confidence, Severity, ToolStatus
from va_mcp.core.schemas import ApiRequest, TargetInfo, ToolInput, ToolOptions
from va_mcp.tools.sql_injection import SqlInjectionTool


# ── 헬퍼 ──────────────────────────────────────────────────────

def make_tool_input(
    method: str = "GET",
    path: str = "/api/search",
    query: dict | None = None,
    body: dict | None = None,
    headers: dict | None = None,
    safe_mode: bool = True,
    max_requests: int = 20,
    **extra_opts,
) -> ToolInput:
    return ToolInput(
        target=TargetInfo(base_url="https://test-target.com"),
        request=ApiRequest(
            method=method,
            path=path,
            headers=headers or {},
            query=query or {},
            body=body,
        ),
        options=ToolOptions(
            safe_mode=safe_mode,
            max_requests=max_requests,
            extra=extra_opts,
        ),
    )


# ── 필수 3종 테스트 ───────────────────────────────────────────

def test_passed():
    """SQL 에러 시그니처 없는 정상 응답 → PASSED"""
    mock_resp = MagicMock()
    mock_resp.status_code = 200
    mock_resp.text = '{"results": [], "total": 0}'
    mock_resp.headers = {"Content-Type": "application/json"}

    with patch("va_mcp.tools.sql_injection.http_client.get", return_value=mock_resp):
        result = SqlInjectionTool().run(
            make_tool_input(
                method="GET",
                path="/api/search",
                query={"q": "hello"},
                payload_list=["' OR '1'='1"],
            )
        )

    assert result.status == ToolStatus.PASSED.value
    assert result.severity == Severity.INFO.value


def test_vulnerable():
    """SQL 에러 시그니처가 응답에 포함 → VULNERABLE + evidence"""
    mock_resp = MagicMock()
    mock_resp.status_code = 500
    mock_resp.text = (
        "<html><body>Error: You have an error in your SQL syntax; "
        "check the manual that corresponds to your MySQL server version</body></html>"
    )
    mock_resp.headers = {"Content-Type": "text/html"}

    with patch("va_mcp.tools.sql_injection.http_client.get", return_value=mock_resp):
        result = SqlInjectionTool().run(
            make_tool_input(
                method="GET",
                path="/api/search",
                query={"q": "hello"},
                payload_list=["' OR '1'='1"],
            )
        )

    assert result.status == ToolStatus.VULNERABLE.value
    assert result.severity == Severity.CRITICAL.value
    assert len(result.evidence) > 0
    assert result.evidence[0].note != ""


def test_error():
    """예외 발생 → ERROR + errors"""
    with patch(
        "va_mcp.tools.sql_injection.http_client.get",
        side_effect=Exception("connection refused"),
    ):
        result = SqlInjectionTool().run(
            make_tool_input(
                method="GET",
                path="/api/search",
                query={"q": "hello"},
                payload_list=["' OR '1'='1"],
            )
        )

    assert result.status == ToolStatus.ERROR.value
    assert result.severity == Severity.INFO.value
    assert result.confidence == Confidence.LOW.value
    assert len(result.errors) > 0


# ── 추가 테스트 ───────────────────────────────────────────────

def test_skipped_no_request():
    """request가 None이면 SKIPPED"""
    tool_input = ToolInput(
        target=TargetInfo(base_url="https://test-target.com"),
        request=None,
    )
    result = SqlInjectionTool().run(tool_input)

    assert result.status == ToolStatus.SKIPPED.value
    assert result.evidence == []


def test_skipped_no_params():
    """query/body 파라미터가 없으면 SKIPPED"""
    result = SqlInjectionTool().run(
        make_tool_input(
            method="GET",
            path="/api/health",
            query={},
        )
    )

    assert result.status == ToolStatus.SKIPPED.value
    assert result.evidence == []


def test_vulnerable_post():
    """POST body 파라미터에서도 취약점 감지"""
    mock_resp = MagicMock()
    mock_resp.status_code = 500
    mock_resp.text = "Unclosed quotation mark after the character string"
    mock_resp.headers = {"Content-Type": "text/plain"}

    with patch("va_mcp.tools.sql_injection.http_client.request", return_value=mock_resp):
        result = SqlInjectionTool().run(
            make_tool_input(
                method="POST",
                path="/api/login",
                body={"username": "admin", "password": "1234"},
                payload_list=["admin'--"],
            )
        )

    assert result.status == ToolStatus.VULNERABLE.value
    assert len(result.evidence) > 0


def test_max_requests_limit():
    """max_requests 제한을 초과하지 않는지 확인"""
    call_count = 0

    def counting_get(*args, **kwargs):
        nonlocal call_count
        call_count += 1
        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.text = '{"ok": true}'
        mock_resp.headers = {}
        return mock_resp

    with patch("va_mcp.tools.sql_injection.http_client.get", side_effect=counting_get):
        result = SqlInjectionTool().run(
            make_tool_input(
                method="GET",
                path="/api/search",
                query={"q": "hello", "page": "1", "sort": "name"},
                max_requests=5,
            )
        )

    assert call_count <= 5


def test_sensitive_headers_masked():
    """Evidence에 민감 헤더가 마스킹되는지 확인"""
    mock_resp = MagicMock()
    mock_resp.status_code = 500
    mock_resp.text = "You have an error in your SQL syntax"
    mock_resp.headers = {"Content-Type": "text/html"}

    with patch("va_mcp.tools.sql_injection.http_client.get", return_value=mock_resp):
        result = SqlInjectionTool().run(
            make_tool_input(
                method="GET",
                path="/api/search",
                query={"q": "hello"},
                headers={"Authorization": "Bearer SECRET_TOKEN"},
                payload_list=["' OR '1'='1"],
            )
        )

    assert result.status == ToolStatus.VULNERABLE.value
    evidence_headers = result.evidence[0].request.get("headers", {})
    assert evidence_headers.get("Authorization") == "***"


def test_time_based_blind():
    """시간 기반 Blind SQLi: 타임아웃 발생 시 감지"""
    import requests as req_lib

    with patch(
        "va_mcp.tools.sql_injection.http_client.get",
        side_effect=req_lib.Timeout("Request timed out"),
    ):
        result = SqlInjectionTool().run(
            make_tool_input(
                method="GET",
                path="/api/search",
                query={"q": "hello"},
                payload_list=["1' WAITFOR DELAY '0:0:5'--"],
                detect_time_based=True,
            )
        )

    assert result.status == ToolStatus.VULNERABLE.value
    assert len(result.evidence) > 0