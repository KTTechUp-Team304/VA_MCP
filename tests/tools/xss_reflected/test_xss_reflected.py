"""Reflected XSS Tool 테스트 (1단계: Mock)"""

from __future__ import annotations

from unittest.mock import MagicMock, patch

from va_mcp.core.constants import Confidence, Severity, ToolStatus
from va_mcp.core.schemas import ApiRequest, TargetInfo, ToolInput, ToolOptions
from va_mcp.tools.injection.xss_reflected import XssReflectedTool


def make_tool_input(
    method: str = "GET",
    path: str = "/api/search",
    query: dict | None = None,
    body: dict | None = None,
    headers: dict | None = None,
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
        options=ToolOptions(extra=extra_opts),
    )


def test_passed():
    """페이로드가 반사되지 않는 정상 응답 → PASSED"""
    mock_resp = MagicMock()
    mock_resp.status_code = 200
    mock_resp.text = '{"results": [], "query": "sanitized_input"}'
    mock_resp.headers = {"Content-Type": "application/json"}

    with patch("va_mcp.tools.injection.xss_reflected.http_client.get", return_value=mock_resp):
        result = XssReflectedTool().run(
            make_tool_input(
                query={"q": "hello"},
                payload_list=["<script>alert(1)</script>"],
            )
        )

    assert result.status == ToolStatus.PASSED.value
    assert result.severity == Severity.INFO.value


def test_vulnerable():
    """페이로드가 응답에 그대로 반사 → VULNERABLE + evidence"""
    payload = "<script>alert(1)</script>"
    mock_resp = MagicMock()
    mock_resp.status_code = 200
    mock_resp.text = f'<html><body>검색 결과: {payload}</body></html>'
    mock_resp.headers = {"Content-Type": "text/html"}

    with patch("va_mcp.tools.injection.xss_reflected.http_client.get", return_value=mock_resp):
        result = XssReflectedTool().run(
            make_tool_input(
                query={"q": "hello"},
                payload_list=[payload],
            )
        )

    assert result.status == ToolStatus.VULNERABLE.value
    assert result.severity == Severity.HIGH.value
    assert len(result.evidence) > 0
    assert "반사" in result.evidence[0].note


def test_vulnerable_img_tag():
    """img 태그 XSS 페이로드 반사 감지"""
    payload = '<img src=x onerror=alert(1)>'
    mock_resp = MagicMock()
    mock_resp.status_code = 200
    mock_resp.text = f'<html><body>{payload}</body></html>'
    mock_resp.headers = {"Content-Type": "text/html"}

    with patch("va_mcp.tools.injection.xss_reflected.http_client.get", return_value=mock_resp):
        result = XssReflectedTool().run(
            make_tool_input(
                query={"q": "hello"},
                payload_list=[payload],
            )
        )

    assert result.status == ToolStatus.VULNERABLE.value
    assert len(result.evidence) > 0


def test_error():
    """예외 발생 → ERROR + errors"""
    with patch(
        "va_mcp.tools.injection.xss_reflected.http_client.get",
        side_effect=Exception("connection refused"),
    ):
        result = XssReflectedTool().run(
            make_tool_input(
                query={"q": "hello"},
                payload_list=["<script>alert(1)</script>"],
            )
        )

    assert result.status == ToolStatus.ERROR.value
    assert result.severity == Severity.INFO.value
    assert result.confidence == Confidence.LOW.value
    assert len(result.errors) > 0


def test_skipped_no_params():
    """파라미터 없으면 SKIPPED"""
    result = XssReflectedTool().run(
        make_tool_input(query={})
    )
    assert result.status == ToolStatus.SKIPPED.value
    assert result.evidence == []


def test_vulnerable_post():
    """POST body에서도 반사 감지"""
    payload = '<script>alert(1)</script>'
    mock_resp = MagicMock()
    mock_resp.status_code = 200
    mock_resp.text = f'<html><body>입력값: {payload}</body></html>'
    mock_resp.headers = {"Content-Type": "text/html"}

    with patch("va_mcp.tools.injection.xss_reflected.http_client.request", return_value=mock_resp):
        result = XssReflectedTool().run(
            make_tool_input(
                method="POST",
                path="/api/comment",
                body={"content": "hello"},
                payload_list=[payload],
            )
        )

    assert result.status == ToolStatus.VULNERABLE.value
    assert len(result.evidence) > 0