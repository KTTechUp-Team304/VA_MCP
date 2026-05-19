from __future__ import annotations

from unittest.mock import MagicMock, patch
from requests import RequestException

from va_mcp.core.schemas import ApiRequest, TargetInfo, ToolInput, ToolOptions
from va_mcp.tools.security_misconfiguration.debug_endpoint import DebugEndpointTool


def make_tool_input(paths: list[str] | None = None):
    return ToolInput(
        target=TargetInfo(base_url="https://test-target.com"),
        request=ApiRequest(method="GET", path="/"),
        options=ToolOptions(
            timeout=5000,
            extra={"debug_paths": paths if paths is not None else ["/actuator"]},
        ),
    )


@patch("va_mcp.tools.security_misconfiguration.debug_endpoint.requests.get")
def test_debug_endpoint_passed(mock_get):
    mock_resp = MagicMock()
    mock_resp.status_code = 404
    mock_resp.text = "Not Found"
    mock_resp.headers = {}
    mock_get.return_value = mock_resp

    result = DebugEndpointTool().run(make_tool_input())

    assert result.status == "passed"
    assert result.severity == "info"
    assert result.evidence == []


@patch("va_mcp.tools.security_misconfiguration.debug_endpoint.requests.get")
def test_debug_endpoint_vulnerable(mock_get):
    mock_resp = MagicMock()
    mock_resp.status_code = 200
    mock_resp.text = '{"status":"UP","components":{"db":{"status":"UP"}}}'
    mock_resp.headers = {}
    mock_get.return_value = mock_resp

    result = DebugEndpointTool().run(make_tool_input())

    assert result.status == "vulnerable"
    assert result.severity == "high"
    assert result.confidence == "high"
    assert len(result.evidence) > 0
    assert result.evidence[0].response_status == 200


@patch("va_mcp.tools.security_misconfiguration.debug_endpoint.requests.get")
def test_debug_endpoint_error(mock_get):
    mock_get.side_effect = RequestException("Mock Network Error")

    result = DebugEndpointTool().run(make_tool_input())

    assert result.status == "error"
    assert result.severity == "info"
    assert result.confidence == "low"
    assert len(result.errors) > 0