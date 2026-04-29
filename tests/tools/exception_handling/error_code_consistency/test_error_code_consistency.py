import pytest
from unittest.mock import patch, MagicMock
from va_mcp.core.schemas import ToolInput, TargetInfo, ApiRequest, ToolOptions
from va_mcp.tools.exception_handling.error_code_consistency import ErrorCodeConsistencyTool

def make_tool_input():
    return ToolInput(
        target=TargetInfo(base_url="https://test-target.com"),
        request=ApiRequest(method="GET", path="/api/test"),
        options=ToolOptions()
    )

@patch('requests.get')
@patch('requests.post')
def test_error_code_consistency_vulnerable(mock_post, mock_get):
    # POST 에러는 JSON, GET 에러는 HTML로 응답 (불일치 = 취약)
    resp1 = MagicMock()
    resp1.headers = {"Content-Type": "application/json"}
    resp1.status_code = 400
    resp1.text = "{}"
    mock_post.return_value = resp1

    resp2 = MagicMock()
    resp2.headers = {"Content-Type": "text/html"}
    resp2.status_code = 404
    resp2.text = "<html>"
    mock_get.return_value = resp2

    tool = ErrorCodeConsistencyTool()
    result = tool.run(make_tool_input())
    assert result.status == "vulnerable"

@patch('requests.get')
@patch('requests.post')
def test_error_code_consistency_passed(mock_post, mock_get):
    # 두 에러 모두 JSON으로 응답 (일관성 유지 = 안전)
    resp_safe = MagicMock()
    resp_safe.headers = {"Content-Type": "application/json"}
    resp_safe.status_code = 400
    resp_safe.text = "{}"
    
    mock_post.return_value = resp_safe
    mock_get.return_value = resp_safe

    tool = ErrorCodeConsistencyTool()
    result = tool.run(make_tool_input())
    assert result.status == "passed"

@patch('requests.post')
def test_error_code_consistency_error(mock_post):
    mock_post.side_effect = Exception("Mock Network Error")

    tool = ErrorCodeConsistencyTool()
    result = tool.run(make_tool_input())
    assert result.status == "error"