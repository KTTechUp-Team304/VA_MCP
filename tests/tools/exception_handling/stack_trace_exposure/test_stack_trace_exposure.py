import pytest
from unittest.mock import patch, MagicMock
from va_mcp.core.schemas import ToolInput, TargetInfo, ApiRequest, ToolOptions
from va_mcp.tools.exception_handling.stack_trace_exposure import StackTraceExposureTool

def make_tool_input():
    return ToolInput(
        target=TargetInfo(base_url="https://test-target.com"),
        request=ApiRequest(method="GET", path="/api/test"),
        options=ToolOptions(max_requests=1, extra={"payloads": ["'"]})
    )

@patch('requests.request')
def test_stack_trace_vulnerable(mock_request):
    mock_resp = MagicMock()
    mock_resp.text = "Error: java.lang.NullPointerException at com.example"
    mock_resp.status_code = 500
    mock_resp.headers = {}
    mock_request.return_value = mock_resp

    tool = StackTraceExposureTool()
    result = tool.run(make_tool_input())
    assert result.status == "vulnerable"

@patch('requests.request')
def test_stack_trace_passed(mock_request):
    mock_resp = MagicMock()
    mock_resp.text = '{"error": "Bad Request"}'
    mock_resp.status_code = 400
    mock_resp.headers = {}
    mock_request.return_value = mock_resp

    tool = StackTraceExposureTool()
    result = tool.run(make_tool_input())
    assert result.status == "passed"

@patch('requests.request')
def test_stack_trace_error(mock_request):
    mock_request.side_effect = Exception("Mock Network Error")
    
    tool = StackTraceExposureTool()
    result = tool.run(make_tool_input())
    assert result.status == "error"