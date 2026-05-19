"""HTTP Header Injection Tool 테스트 (1단계: Mock)"""

from __future__ import annotations

from unittest.mock import MagicMock, patch

from va_mcp.core.constants import Confidence, Severity, ToolStatus
from va_mcp.core.schemas import ApiRequest, TargetInfo, ToolInput, ToolOptions
from va_mcp.tools.injection.header_injection import HeaderInjectionTool


def make_tool_input(
    method: str = "GET",
    path: str = "/api/redirect",
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
    """인젝션 시그니처 없는 정상 응답 → PASSED"""
    mock_resp = MagicMock()
    mock_resp.status_code = 302
    mock_resp.text = ""
    mock_resp.headers = {
        "Location": "https://example.com",
        "Content-Type": "text/html",
    }

    with patch("requests.get", return_value=mock_resp):
        result = HeaderInjectionTool().run(
            make_tool_input(
                query={"url": "https://example.com"},
                payload_list=["%0d%0aInjected-Header:true"],
            )
        )

    assert result.status == ToolStatus.PASSED.value
    assert result.severity == Severity.INFO.value


def test_vulnerable_header():
    """응답 헤더에 인젝션된 헤더 감지 → VULNERABLE"""
    mock_resp = MagicMock()
    mock_resp.status_code = 302
    mock_resp.text = ""
    mock_resp.headers = {
        "Location": "https://example.com",
        "Injected-Header": "true",
        "Content-Type": "text/html",
    }

    with patch("requests.get", return_value=mock_resp):
        result = HeaderInjectionTool().run(
            make_tool_input(
                query={"url": "https://example.com"},
                payload_list=["%0d%0aInjected-Header:true"],
            )
        )

    assert result.status == ToolStatus.VULNERABLE.value
    assert result.severity == Severity.MEDIUM.value
    assert len(result.evidence) > 0


def test_vulnerable_body():
    """응답 본문에 인젝션 시그니처 감지 → VULNERABLE"""
    mock_resp = MagicMock()
    mock_resp.status_code = 200
    mock_resp.text = "HTTP/1.1 200 OK\r\nSet-Cookie:hacked=1\r\n\r\n<html>test</html>"
    mock_resp.headers = {"Content-Type": "text/html"}

    with patch("requests.get", return_value=mock_resp):
        result = HeaderInjectionTool().run(
            make_tool_input(
                query={"url": "https://example.com"},
                payload_list=["%0d%0aSet-Cookie:hacked=1"],
            )
        )

    assert result.status == ToolStatus.VULNERABLE.value
    assert len(result.evidence) > 0


def test_error():
    """예외 발생 → ERROR + errors"""
    with patch("requests.get", side_effect=Exception("connection refused")):
        result = HeaderInjectionTool().run(
            make_tool_input(
                query={"url": "https://example.com"},
                payload_list=["%0d%0aInjected-Header:true"],
            )
        )

    assert result.status == ToolStatus.ERROR.value
    assert result.severity == Severity.INFO.value
    assert result.confidence == Confidence.LOW.value
    assert len(result.errors) > 0


def test_skipped_no_params():
    """파라미터 없으면 SKIPPED"""
    result = HeaderInjectionTool().run(
        make_tool_input(query={})
    )
    assert result.status == ToolStatus.SKIPPED.value
    assert result.evidence == []