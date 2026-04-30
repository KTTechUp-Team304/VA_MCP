from __future__ import annotations

from unittest.mock import MagicMock, patch

from va_mcp.core.schemas import ApiRequest, TargetInfo, ToolInput, ToolOptions
from va_mcp.tools.security_misconfiguration.cors_misconfiguration import CorsMisconfigurationTool

TEST_ORIGIN = "https://evil.example.com"


def make_tool_input():
    return ToolInput(
        target=TargetInfo(base_url="https://test-target.com"),
        request=ApiRequest(method="GET", path="/api/data"),
        options=ToolOptions(
            timeout=5000,
            extra={"test_origins": [TEST_ORIGIN]},
        ),
    )


@patch("va_mcp.tools.security_misconfiguration.cors_misconfiguration.requests.request")
def test_cors_misconfiguration_passed(mock_request):
    mock_resp = MagicMock()
    mock_resp.status_code = 200
    mock_resp.text = ""
    mock_resp.headers = {
        "Access-Control-Allow-Origin": "https://trusted.example.com",
        "Access-Control-Allow-Credentials": "false",
    }
    mock_request.return_value = mock_resp

    result = CorsMisconfigurationTool().run(make_tool_input())

    assert result.status == "passed"
    assert result.severity == "info"
    assert result.evidence == []


@patch("va_mcp.tools.security_misconfiguration.cors_misconfiguration.requests.request")
def test_cors_misconfiguration_vulnerable(mock_request):
    mock_resp = MagicMock()
    mock_resp.status_code = 200
    mock_resp.text = ""
    mock_resp.headers = {
        "Access-Control-Allow-Origin": TEST_ORIGIN,
        "Access-Control-Allow-Credentials": "true",
    }
    mock_request.return_value = mock_resp

    result = CorsMisconfigurationTool().run(make_tool_input())

    assert result.status == "vulnerable"
    assert result.severity == "high"
    assert result.confidence == "high"
    assert len(result.evidence) > 0
    assert result.evidence[0].note != ""


@patch("va_mcp.tools.security_misconfiguration.cors_misconfiguration.requests.request")
def test_cors_misconfiguration_error(mock_request):
    mock_request.side_effect = Exception("Mock Network Error")

    result = CorsMisconfigurationTool().run(make_tool_input())

    assert result.status == "error"
    assert result.severity == "info"
    assert result.confidence == "low"
    assert len(result.errors) > 0
