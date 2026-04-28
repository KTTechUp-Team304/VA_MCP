import pytest
from unittest.mock import patch, MagicMock
from va_mcp.core.schemas import ToolInput, TargetInfo, ApiRequest, ToolOptions
from va_mcp.tools.exception_handling.retry_handling import RetryHandlingTool

def make_tool_input():
    return ToolInput(
        target=TargetInfo(base_url="https://test-target.com"),
        request=ApiRequest(method="POST", path="/api/login"),
        options=ToolOptions(max_requests=5)
    )

@patch('requests.request')
def test_retry_handling_vulnerable(mock_request):
    # 5번 모두 200 성공 응답을 반환 (방어 실패)
    mock_resp = MagicMock()
    mock_resp.status_code = 200
    mock_request.return_value = mock_resp

    tool = RetryHandlingTool()
    result = tool.run(make_tool_input())
    assert result.status == "vulnerable"

@patch('requests.request')
def test_retry_handling_passed(mock_request):
    # 요청 시 429 Too Many Requests 반환 (방어 성공)
    mock_resp = MagicMock()
    mock_resp.status_code = 429
    mock_request.return_value = mock_resp

    tool = RetryHandlingTool()
    result = tool.run(make_tool_input())
    assert result.status == "passed"

@patch('requests.request')
def test_retry_handling_error(mock_request):
    mock_request.side_effect = Exception("Mock Network Error")

    tool = RetryHandlingTool()
    result = tool.run(make_tool_input())
    assert result.status == "error"