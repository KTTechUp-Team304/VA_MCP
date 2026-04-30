from __future__ import annotations

from unittest.mock import MagicMock, patch

from va_mcp.core.schemas import ApiRequest, TargetInfo, ToolInput, ToolOptions
from va_mcp.tools.security_misconfiguration.security_headers import SecurityHeadersTool

ALL_SECURITY_HEADERS = {
    "Content-Security-Policy": "default-src 'self'",
    "Strict-Transport-Security": "max-age=31536000; includeSubDomains",
    "X-Content-Type-Options": "nosniff",
    "X-Frame-Options": "DENY",
    "Referrer-Policy": "no-referrer",
    "Permissions-Policy": "geolocation=()",
}


def make_tool_input():
    return ToolInput(
        target=TargetInfo(base_url="https://test-target.com"),
        request=ApiRequest(method="GET", path="/"),
        options=ToolOptions(timeout=5000),
    )


@patch("va_mcp.tools.security_misconfiguration.security_headers.requests.request")
def test_security_headers_passed(mock_request):
    mock_resp = MagicMock()
    mock_resp.status_code = 200
    mock_resp.text = ""
    mock_resp.headers = ALL_SECURITY_HEADERS
    mock_request.return_value = mock_resp

    result = SecurityHeadersTool().run(make_tool_input())

    assert result.status == "passed"
    assert result.severity == "info"
    assert result.confidence == "high"
    assert result.evidence == []


@patch("va_mcp.tools.security_misconfiguration.security_headers.requests.request")
def test_security_headers_vulnerable(mock_request):
    mock_resp = MagicMock()
    mock_resp.status_code = 200
    mock_resp.text = ""
    mock_resp.headers = {}
    mock_request.return_value = mock_resp

    result = SecurityHeadersTool().run(make_tool_input())

    assert result.status == "vulnerable"
    assert result.severity == "medium"
    assert result.confidence == "high"
    assert len(result.evidence) > 0
    assert result.evidence[0].note != ""


@patch("va_mcp.tools.security_misconfiguration.security_headers.requests.request")
def test_security_headers_error(mock_request):
    mock_request.side_effect = Exception("Mock Network Error")

    result = SecurityHeadersTool().run(make_tool_input())

    assert result.status == "error"
    assert result.severity == "info"
    assert result.confidence == "low"
    assert len(result.errors) > 0
