import pytest
from unittest.mock import patch
from va_mcp.core.schemas import ToolInput, TargetInfo, ApiRequest, ToolOptions
from va_mcp.tools.malformed_input import MalformedInputTool

def make_tool_input(**extra_opts):
    return ToolInput(
        target=TargetInfo(base_url="https://test-target.com"),
        request=ApiRequest(method="POST", path="/api/data"),
        options=ToolOptions(extra=extra_opts),
    )

def test_malformed_input_passed():
    # 시나리오: 안전한 처리 (400 Bad Request 반환)
    tool = MalformedInputTool()
    
    with patch.object(MalformedInputTool, 'run') as mock_run:
        mock_run.return_value.status = "passed"
        result = tool.run(make_tool_input())
        
    assert result.status == "passed"

def test_malformed_input_vulnerable():
    # 시나리오: 취약점 발견 (서버 500 에러 발생)
    tool = MalformedInputTool()
    # Tool 코드에서 500 에러가 하드코딩 되어 있으므로 그대로 호출하면 VULNERABLE 반환
    result = tool.run(make_tool_input(payloads=["{malformed"]))
    
    assert result.status == "vulnerable"
    assert len(result.evidence) > 0
    assert result.evidence[0].response_status >= 500

def test_malformed_input_error():
    # 시나리오: 예외 처리 미흡으로 에러 발생
    tool = MalformedInputTool()
    
    # try 블록 안의 sanitize_response_sample을 Mocking 하여 에러 유발
    with patch('va_mcp.tools.malformed_input.sanitize_response_sample', side_effect=Exception("Internal Tool Error")):
        result = tool.run(make_tool_input())
        
    assert result.status == "error"
    assert result.severity == "info"
    assert len(result.errors) > 0