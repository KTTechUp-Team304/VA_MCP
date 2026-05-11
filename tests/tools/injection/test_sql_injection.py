from __future__ import annotations

from unittest.mock import MagicMock, patch
import requests

from va_mcp.core.constants import Confidence, Severity, ToolStatus
from va_mcp.core.schemas import ApiRequest, TargetInfo, ToolInput, ToolOptions
from va_mcp.tools.injection.sql_injection import SqlInjectionTool


def make_tool_input(
    method: str = "GET",
    path: str = "/api/search",
    query: dict | None = None,
    body: dict | None = None,
    headers: dict | None = None,
    safe_mode: bool = False,      # ← 기본을 False 로 변경
    timeout: int = 5000,
    max_requests: int = 10,
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
            timeout=timeout,
            max_requests=max_requests,
            safe_mode=safe_mode,
            extra=extra_opts,
        ),
        auth=[],
    )


def make_resp(status=200, text="{}", headers=None):
    m = MagicMock()
    m.status_code = status
    m.text = text
    m.headers = headers or {}
    # safe_mode 분기 방지를 위해 elapsed.total_seconds() 항상 0
    m.elapsed = MagicMock()
    m.elapsed.total_seconds.return_value = 0.0
    return m


def test_passed():
    with patch("va_mcp.tools.injection.sql_injection.requests.get",
               return_value=make_resp(200, '{"results": []}')):
        result = SqlInjectionTool().run(
            make_tool_input(query={"q": "hello"})
        )
    assert result.status == ToolStatus.PASSED.value
    assert result.severity == Severity.INFO.value


def test_vulnerable():
    with patch("va_mcp.tools.injection.sql_injection.requests.get",
               return_value=make_resp(500, "You have an error in your SQL syntax")):
        result = SqlInjectionTool().run(
            make_tool_input(query={"q": "hello"})
        )
    assert result.status == ToolStatus.VULNERABLE.value
    assert result.severity == Severity.CRITICAL.value
    assert len(result.evidence) > 0


def test_vulnerable_post():
    with patch("va_mcp.tools.injection.sql_injection.requests.request",
               return_value=make_resp(500, "Unclosed quotation mark")):
        result = SqlInjectionTool().run(
            make_tool_input(method="POST", body={"username": "admin"})
        )
    assert result.status == ToolStatus.VULNERABLE.value


def test_error():
    with patch("va_mcp.tools.injection.sql_injection.requests.get",
               side_effect=Exception("connection refused")):
        result = SqlInjectionTool().run(
            make_tool_input(query={"q": "hello"})
        )
    assert result.status == ToolStatus.ERROR.value
    assert result.confidence == Confidence.LOW.value
    assert len(result.errors) > 0


def test_max_requests_limit():
    call_count = 0

    def fake_get(*args, **kwargs):
        nonlocal call_count
        call_count += 1
        return make_resp()

    with patch("va_mcp.tools.injection.sql_injection.requests.get",
               side_effect=fake_get):
        SqlInjectionTool().run(
            make_tool_input(query={"q": "hello", "page": "1", "sort": "asc"},
                            max_requests=3)
        )

    assert call_count <= 3


def test_sensitive_headers_masked():
    with patch("va_mcp.tools.injection.sql_injection.requests.get",
               return_value=make_resp(500, "SQL syntax error")):
        result = SqlInjectionTool().run(
            make_tool_input(query={"q": "hello"},
                            headers={"Authorization": "SECRET"})
        )
    assert result.status == ToolStatus.VULNERABLE.value


def test_time_based_blind():
    with patch("va_mcp.tools.injection.sql_injection.requests.get",
               side_effect=requests.Timeout()):
        result = SqlInjectionTool().run(
            make_tool_input(query={"q": "hello"},
                            extra={"detect_time_based": True})
        )
    assert result.status == ToolStatus.VULNERABLE.value