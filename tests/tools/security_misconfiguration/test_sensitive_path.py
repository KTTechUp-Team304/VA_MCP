from __future__ import annotations

from unittest.mock import MagicMock, patch

from va_mcp.core.schemas import ApiRequest, TargetInfo, ToolInput, ToolOptions
from va_mcp.tools.security_misconfiguration.sensitive_path import SensitivePathTool


def make_tool_input(paths: list[str] | None = None):
    return ToolInput(
        target=TargetInfo(base_url="https://test-target.com"),
        request=ApiRequest(method="GET", path="/"),
        options=ToolOptions(
            timeout=5000,
            extra={"sensitive_paths": paths if paths is not None else ["/.env"]},
        ),
    )


@patch("va_mcp.tools.security_misconfiguration.sensitive_path.requests.get")
def test_sensitive_path_passed(mock_get):
    mock_resp = MagicMock()
    mock_resp.status_code = 404
    mock_resp.text = "Not Found"
    mock_resp.headers = {}
    mock_get.return_value = mock_resp

    result = SensitivePathTool().run(make_tool_input())

    assert result.status == "passed"
    assert result.severity == "info"
    assert result.evidence == []


@patch("va_mcp.tools.security_misconfiguration.sensitive_path.requests.get")
def test_sensitive_path_vulnerable(mock_get):
    mock_resp = MagicMock()
    mock_resp.status_code = 200
    mock_resp.text = "SECRET_KEY=abc123\nDB_PASSWORD=admin"
    mock_resp.headers = {}
    mock_get.return_value = mock_resp

    result = SensitivePathTool().run(make_tool_input())

    assert result.status == "vulnerable"
    assert result.severity == "high"
    assert result.confidence == "high"
    assert len(result.evidence) > 0
    assert result.evidence[0].response_status == 200


@patch("va_mcp.tools.security_misconfiguration.sensitive_path.requests.get")
def test_sensitive_path_error(mock_get):
    mock_get.side_effect = Exception("Mock Network Error")

    result = SensitivePathTool().run(make_tool_input())

    assert result.status == "error"
    assert result.severity == "info"
    assert result.confidence == "low"
    assert len(result.errors) > 0
