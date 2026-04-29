from __future__ import annotations

from unittest.mock import MagicMock, patch

from va_mcp.core.schemas import ApiRequest, TargetInfo, ToolInput, ToolOptions
from va_mcp.tools.security_misconfiguration.default_config import DefaultConfigTool


def make_tool_input():
    return ToolInput(
        target=TargetInfo(base_url="https://test-target.com"),
        request=ApiRequest(method="POST", path="/login"),
        options=ToolOptions(
            timeout=5000,
            extra={
                "credential_pairs": [["admin", "admin"]],
                "admin_paths": ["/admin"],
            },
        ),
    )


@patch("va_mcp.tools.security_misconfiguration.default_config.requests.get")
@patch("va_mcp.tools.security_misconfiguration.default_config.requests.post")
def test_default_config_passed(mock_post, mock_get):
    mock_post_resp = MagicMock()
    mock_post_resp.status_code = 401
    mock_post_resp.text = '{"error": "Unauthorized"}'
    mock_post_resp.headers = {}
    mock_post.return_value = mock_post_resp

    mock_get_resp = MagicMock()
    mock_get_resp.status_code = 404
    mock_get_resp.text = "Not Found"
    mock_get_resp.headers = {}
    mock_get.return_value = mock_get_resp

    result = DefaultConfigTool().run(make_tool_input())

    assert result.status == "passed"
    assert result.severity == "info"
    assert result.evidence == []


@patch("va_mcp.tools.security_misconfiguration.default_config.requests.get")
@patch("va_mcp.tools.security_misconfiguration.default_config.requests.post")
def test_default_config_vulnerable(mock_post, mock_get):
    mock_post_resp = MagicMock()
    mock_post_resp.status_code = 200
    mock_post_resp.text = '{"token": "eyJhbGci..."}'
    mock_post_resp.headers = {}
    mock_post.return_value = mock_post_resp

    mock_get_resp = MagicMock()
    mock_get_resp.status_code = 404
    mock_get_resp.text = "Not Found"
    mock_get_resp.headers = {}
    mock_get.return_value = mock_get_resp

    result = DefaultConfigTool().run(make_tool_input())

    assert result.status == "vulnerable"
    assert result.severity == "critical"
    assert result.confidence == "high"
    assert len(result.evidence) > 0
    assert result.evidence[0].note != ""


@patch("va_mcp.tools.security_misconfiguration.default_config.requests.post")
def test_default_config_error(mock_post):
    mock_post.side_effect = Exception("Mock Network Error")

    result = DefaultConfigTool().run(make_tool_input())

    assert result.status == "error"
    assert result.severity == "info"
    assert result.confidence == "low"
    assert len(result.errors) > 0
