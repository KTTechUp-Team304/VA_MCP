from __future__ import annotations

from unittest.mock import MagicMock, patch

from va_mcp.core.schemas import ApiRequest, TargetInfo, ToolInput, ToolOptions
from va_mcp.tools.security_misconfiguration.directory_listing import DirectoryListingTool


def make_tool_input(paths: list[str] | None = None):
    return ToolInput(
        target=TargetInfo(base_url="https://test-target.com"),
        request=ApiRequest(method="GET", path="/"),
        options=ToolOptions(
            timeout=5000,
            extra={"check_paths": paths if paths is not None else ["/uploads/"]},
        ),
    )


@patch("va_mcp.tools.security_misconfiguration.directory_listing.requests.get")
def test_directory_listing_passed(mock_get):
    mock_resp = MagicMock()
    mock_resp.status_code = 200
    mock_resp.text = "<html><body><h1>Welcome</h1></body></html>"
    mock_resp.headers = {}
    mock_get.return_value = mock_resp

    result = DirectoryListingTool().run(make_tool_input())

    assert result.status == "passed"
    assert result.severity == "info"
    assert result.evidence == []


@patch("va_mcp.tools.security_misconfiguration.directory_listing.requests.get")
def test_directory_listing_vulnerable(mock_get):
    mock_resp = MagicMock()
    mock_resp.status_code = 200
    mock_resp.text = (
        "<html><head><title>Index of /uploads/</title></head>"
        "<body><h1>Index of /uploads/</h1>"
        "<a href='?C=N;O=D'>Name</a>"
        "<a href='../'>Parent Directory</a>"
        "<a href='file.zip'>file.zip</a>"
        "</body></html>"
    )
    mock_resp.headers = {}
    mock_get.return_value = mock_resp

    result = DirectoryListingTool().run(make_tool_input())

    assert result.status == "vulnerable"
    assert result.severity == "high"
    assert result.confidence == "high"
    assert len(result.evidence) > 0
    assert result.evidence[0].note != ""


@patch("va_mcp.tools.security_misconfiguration.directory_listing.requests.get")
def test_directory_listing_error(mock_get):
    mock_get.side_effect = Exception("Mock Network Error")

    result = DirectoryListingTool().run(make_tool_input())

    assert result.status == "error"
    assert result.severity == "info"
    assert result.confidence == "low"
    assert len(result.errors) > 0
