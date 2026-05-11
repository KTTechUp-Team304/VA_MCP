from __future__ import annotations

from unittest.mock import MagicMock, patch
from requests import RequestException

from va_mcp.core.schemas import ApiRequest, TargetInfo, ToolInput, ToolOptions
from va_mcp.tools.security_misconfiguration.error_info_exposure import ErrorInfoExposureTool


def make_tool_input():
    return ToolInput(
        target=TargetInfo(base_url="https://test-target.com"),
        request=ApiRequest(method="GET", path="/api/data"),
        options=ToolOptions(
            timeout=5000,
            extra={"error_payloads": ["'"]},
        ),
    )


@patch("va_mcp.tools.security_misconfiguration.error_info_exposure.requests.request")
def test_error_info_exposure_passed(mock_request):
    mock_resp = MagicMock()
    mock_resp.status_code = 400
    mock_resp.text = '{"error": "Bad Request"}'
    mock_resp.headers = {"Content-Type": "application/json"}
    mock_request.return_value = mock_resp

    result = ErrorInfoExposureTool().run(make_tool_input())

    assert result.status == "passed"
    assert result.severity == "info"
    assert result.evidence == []


@patch("va_mcp.tools.security_misconfiguration.error_info_exposure.requests.request")
def test_error_info_exposure_vulnerable(mock_request):
    mock_resp = MagicMock()
    mock_resp.status_code = 500
    mock_resp.text = "Traceback (most recent call last):\n  File '/app/main.py'"
    mock_resp.headers = {"X-Powered-By": "PHP/7.4.3"}
    mock_request.return_value = mock_resp

    result = ErrorInfoExposureTool().run(make_tool_input())

    assert result.status == "vulnerable"
    assert result.severity == "high"
    assert result.confidence == "high"
    assert len(result.evidence) > 0
    assert result.evidence[0].note != ""


@patch("va_mcp.tools.security_misconfiguration.error_info_exposure.requests.request")
def test_error_info_exposure_error(mock_request):
    mock_request.side_effect = RequestException("Mock Network Error")

    result = ErrorInfoExposureTool().run(make_tool_input())

    assert result.status == "error"
    assert result.severity == "info"
    assert result.confidence == "low"
    assert len(result.errors) > 0