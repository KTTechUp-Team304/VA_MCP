import pytest
import requests
from unittest.mock import patch, MagicMock
from va_mcp.core.schemas import ToolInput, TargetInfo, ApiRequest, ToolOptions
from va_mcp.tools.exception_handling.timeout_handling import TimeoutHandlingTool

def make_tool_input():
    return ToolInput(
        target=TargetInfo(base_url="https://test-target.com"),
        request=ApiRequest(method="GET", path="/api/heavy-task"),
        options=ToolOptions(extra={"delay_seconds": 15})
    )

@patch('requests.request')
def test_timeout_handling_vulnerable(mock_request):
    # 클라이언트 타임아웃 예외를 발생시킴 (서버가 응답을 안 끊어줌)
    mock_request.side_effect = requests.exceptions.Timeout("Request timed out")

    tool = TimeoutHandlingTool()
    result = tool.run(make_tool_input())
    assert result.status == "vulnerable"

@patch('requests.request')
def test_timeout_handling_passed(mock_request):
    mock_resp = MagicMock()
    mock_resp.text = "Gateway Timeout"
    mock_resp.status_code = 504 # 안전한 타임아웃 코드
    mock_resp.headers = {}
    mock_request.return_value = mock_resp

    tool = TimeoutHandlingTool()
    result = tool.run(make_tool_input())
    assert result.status == "passed"

@patch('requests.request')
def test_timeout_handling_error(mock_request):
    # 일반적인 알 수 없는 에러 발생
    mock_request.side_effect = Exception("Mock System Error")

    tool = TimeoutHandlingTool()
    result = tool.run(make_tool_input())
    assert result.status == "error"