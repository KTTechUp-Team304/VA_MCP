import pytest
from unittest.mock import patch
from va_mcp.core.schemas import ToolInput, TargetInfo, ApiRequest, ToolOptions
from va_mcp.tools.error_code_consistency import ErrorCodeConsistencyTool

def make_tool_input(**extra_opts):
    return ToolInput(
        target=TargetInfo(base_url="https://test-target.com"),
        request=ApiRequest(method="GET", path="/api/test"),
        options=ToolOptions(extra=extra_opts),
    )

def test_error_code_consistency_passed():
    tool = ErrorCodeConsistencyTool()
    with patch.object(ErrorCodeConsistencyTool, 'run') as mock_run:
        mock_run.return_value.status = "passed"
        result = tool.run(make_tool_input())
    assert result.status == "passed"

def test_error_code_consistency_vulnerable():
    tool = ErrorCodeConsistencyTool()
    result = tool.run(make_tool_input())
    assert result.status == "vulnerable"
    # Evidence가 2개(400, 404) 들어갔는지 확인
    assert len(result.evidence) == 2

def test_error_code_consistency_error():
    tool = ErrorCodeConsistencyTool()
    with patch('va_mcp.tools.error_code_consistency.sanitize_response_sample', side_effect=Exception("Consistency Mock Error")):
        result = tool.run(make_tool_input())
    assert result.status == "error"