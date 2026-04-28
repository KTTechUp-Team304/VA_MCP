"""
Resource Exhaustion Check Tool 테스트

필수 3종: test_passed / test_vulnerable / test_error
"""

from __future__ import annotations

from unittest.mock import MagicMock, patch

from va_mcp.core.schemas import ApiRequest, TargetInfo, ToolInput, ToolOptions
from va_mcp.tools.insecure_design.resource_exhaustion import ResourceExhaustionTool


def _make_tool_input(**extra_opts) -> ToolInput:
    return ToolInput(
        target=TargetInfo(base_url="https://test-target.com"),
        request=ApiRequest(
            method="POST",
            path="/api/search",
            body={"query": "test"},
        ),
        options=ToolOptions(extra=extra_opts),
    )


def test_passed():
    """413 응답이 오면 크기 제한 존재 → PASSED"""
    mock_resp = MagicMock()
    mock_resp.status_code = 413
    mock_resp.text = "Payload Too Large"
    mock_resp.headers = {}

    with patch(
        "va_mcp.tools.insecure_design.resource_exhaustion.requests.request",
        return_value=mock_resp,
    ):
        result = ResourceExhaustionTool().run(_make_tool_input())

    assert result.status == "passed"
    assert result.severity == "info"
    assert result.confidence == "high"
    assert len(result.evidence) > 0
    assert result.evidence[0].response_status == 413


def test_vulnerable_200():
    """200 응답이면 크기 제한 없음 → VULNERABLE"""
    mock_resp = MagicMock()
    mock_resp.status_code = 200
    mock_resp.text = '{"ok": true}'
    mock_resp.headers = {}

    with patch(
        "va_mcp.tools.insecure_design.resource_exhaustion.requests.request",
        return_value=mock_resp,
    ):
        result = ResourceExhaustionTool().run(_make_tool_input())

    assert result.status == "vulnerable"
    assert result.severity == "medium"
    assert len(result.evidence) > 0


def test_vulnerable_500():
    """500 응답이면 서버 과부하 → VULNERABLE (HIGH)"""
    mock_resp = MagicMock()
    mock_resp.status_code = 500
    mock_resp.text = "Internal Server Error"
    mock_resp.headers = {}

    with patch(
        "va_mcp.tools.insecure_design.resource_exhaustion.requests.request",
        return_value=mock_resp,
    ):
        result = ResourceExhaustionTool().run(_make_tool_input())

    assert result.status == "vulnerable"
    assert result.severity == "high"


def test_error():
    """요청 예외 발생 시 → ERROR"""
    import requests as req_lib

    with patch(
        "va_mcp.tools.insecure_design.resource_exhaustion.requests.request",
        side_effect=req_lib.exceptions.ConnectionError("connection refused"),
    ):
        result = ResourceExhaustionTool().run(_make_tool_input())

    assert result.status == "error"
    assert result.severity == "info"
    assert result.confidence == "low"
    assert len(result.errors) > 0
    assert result.errors[0].error_code == "HTTP_FAILURE"


def test_skipped_no_request():
    """request가 None이면 → SKIPPED"""
    tool_input = ToolInput(
        target=TargetInfo(base_url="https://test-target.com"),
        request=None,
    )
    result = ResourceExhaustionTool().run(tool_input)

    assert result.status == "skipped"
    assert len(result.evidence) == 0


def test_skipped_get_method():
    """GET 메서드는 검사 대상 아님 → SKIPPED"""
    tool_input = ToolInput(
        target=TargetInfo(base_url="https://test-target.com"),
        request=ApiRequest(method="GET", path="/api/search"),
    )
    result = ResourceExhaustionTool().run(tool_input)

    assert result.status == "skipped"


def test_invalid_payload_size():
    """payload_size가 유효하지 않으면 → ERROR + INVALID_INPUT"""
    result = ResourceExhaustionTool().run(_make_tool_input(payload_size=-1))

    assert result.status == "error"
    assert result.errors[0].error_code == "INVALID_INPUT"
