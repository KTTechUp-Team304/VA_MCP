import pytest
from unittest.mock import patch
from va_mcp.core.schemas import ToolInput, TargetInfo, ApiRequest, ToolOptions
from va_mcp.tools.retry_handling import RetryHandlingTool

def make_tool_input(**extra_opts):
    return ToolInput(
        target=TargetInfo(base_url="https://test-target.com"),
        request=ApiRequest(method="POST", path="/api/login"),
        options=ToolOptions(extra=extra_opts),
    )

def test_retry_handling_passed():
    tool = RetryHandlingTool()
    with patch.object(RetryHandlingTool, 'run') as mock_run:
        mock_run.return_value.status = "passed"
        result = tool.run(make_tool_input())
    assert result.status == "passed"

def test_retry_handling_vulnerable():
    tool = RetryHandlingTool()
    result = tool.run(make_tool_input(max_retries=3))
    assert result.status == "vulnerable"
    assert "CWE-307" in result.cwe

def test_retry_handling_error():
    tool = RetryHandlingTool()
    with patch('va_mcp.tools.retry_handling.sanitize_response_sample', side_effect=Exception("Retry Mock Error")):
        result = tool.run(make_tool_input())
    assert result.status == "error"