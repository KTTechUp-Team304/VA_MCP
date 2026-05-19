import requests
import pytest
from unittest.mock import patch, MagicMock

# 실제 툴 모듈 import
import va_mcp.tools.insecure_design.resource_exhaustion as re_mod
from va_mcp.tools.insecure_design.resource_exhaustion import ResourceExhaustionTool
from va_mcp.core.schemas import ApiRequest, TargetInfo, ToolInput, ToolOptions

# ----------------------------------
# http_client 를 requests 로 설정
# ----------------------------------
# 리팩토링된 툴 모듈에 `http_client = None` 이 선언되어 있어야 하고,
# 실제 실행 시 여기서 requests 를 주입해 줍니다.
re_mod.http_client = requests


# ----------------------------------
# ToolInput 생성 헬퍼
# ----------------------------------
def make_tool_input(extra: dict | None = None) -> ToolInput:
    """
    ToolOptions 의 timeout, max_requests, safe_mode, extra 모두
    지정해 줘야 에러가 없습니다.
    """
    opts_extra = {
        "payload_size": 100,
        "test_field": "data",
    }
    if extra:
        opts_extra.update(extra)

    return ToolInput(
        target=TargetInfo(base_url="https://test-target.com"),
        request=ApiRequest(
            method="POST",
            path="/api/upload",
            headers={},
            query={},
            body={"data": "x"},
        ),
        options=ToolOptions(
            timeout=5000,
            max_requests=1,
            safe_mode=False,
            extra=opts_extra,
        ),
        auth=[],
    )


# ----------------------------------
# PASSED (413 Payload Too Large)
# ----------------------------------
@patch("va_mcp.tools.insecure_design.resource_exhaustion.http_client.request")
def test_resource_exhaustion_passed(mock_request):
    mock_resp = MagicMock(status_code=413, text="Payload Too Large", headers={})
    mock_request.return_value = mock_resp

    result = ResourceExhaustionTool().run(make_tool_input())
    assert result.status == "passed"
    assert result.severity == "info"
    assert result.confidence == "high"
    assert hasattr(result, "evidence") and len(result.evidence) == 1


# ----------------------------------
# VULNERABLE (200 OK)
# ----------------------------------
@patch("va_mcp.tools.insecure_design.resource_exhaustion.http_client.request")
def test_resource_exhaustion_vulnerable_ok(mock_request):
    mock_resp = MagicMock(status_code=200, text="OK", headers={})
    mock_request.return_value = mock_resp

    result = ResourceExhaustionTool().run(make_tool_input())
    assert result.status == "vulnerable"
    assert result.severity == "medium"
    assert result.confidence == "medium"
    assert hasattr(result, "evidence") and len(result.evidence) == 1


# ----------------------------------
# VULNERABLE (500 Server Error)
# ----------------------------------
@patch("va_mcp.tools.insecure_design.resource_exhaustion.http_client.request")
def test_resource_exhaustion_vulnerable_500(mock_request):
    mock_resp = MagicMock(status_code=500, text="Server Error", headers={})
    mock_request.return_value = mock_resp

    result = ResourceExhaustionTool().run(make_tool_input())
    assert result.status == "vulnerable"
    assert result.severity == "high"
    assert result.confidence == "medium"


# ----------------------------------
# TIMEOUT → VULNERABLE
# ----------------------------------
@patch("va_mcp.tools.insecure_design.resource_exhaustion.http_client.request")
def test_resource_exhaustion_timeout(mock_request):
    mock_request.side_effect = requests.exceptions.Timeout()

    result = ResourceExhaustionTool().run(make_tool_input())
    assert result.status == "vulnerable"
    assert result.severity == "high"
    assert result.confidence == "medium"
    # timeout 시에도 evidence를 남기는 구현이라면 다음도 확인
    assert hasattr(result, "evidence") and len(result.evidence) == 1


# ----------------------------------
# INVALID payload_size → ERROR
# ----------------------------------
def test_resource_exhaustion_invalid_payload_size():
    ti = make_tool_input(extra={"payload_size": 0})
    result = ResourceExhaustionTool().run(ti)
    assert result.status == "error"
    assert hasattr(result, "errors") and len(result.errors) >= 1


# ----------------------------------
# INVALID test_field → ERROR
# ----------------------------------
def test_resource_exhaustion_invalid_field():
    ti = make_tool_input(extra={"test_field": ""})
    result = ResourceExhaustionTool().run(ti)
    assert result.status == "error"
    assert hasattr(result, "errors") and len(result.errors) >= 1