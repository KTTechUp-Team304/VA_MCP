"""
Rate Limit Check Tool 테스트

필수 3종: test_passed / test_vulnerable / test_error
"""

from __future__ import annotations

from unittest.mock import MagicMock, patch

from va_mcp.core.schemas import ApiRequest, TargetInfo, ToolInput, ToolOptions
from va_mcp.tools.insecure_design.rate_limit_check import RateLimitCheckTool


def _make_tool_input(**extra_opts) -> ToolInput:
    return ToolInput(
        target=TargetInfo(base_url="https://test-target.com"),
        request=ApiRequest(method="POST", path="/api/login"),
        options=ToolOptions(extra=extra_opts),
    )


def test_passed():
    """429 응답이 오면 Rate Limit 존재 → PASSED"""
    responses = []
    for i in range(5):
        mock = MagicMock()
        mock.status_code = 200
        mock.text = '{"ok": true}'
        mock.headers = {}
        responses.append(mock)

    mock_429 = MagicMock()
    mock_429.status_code = 429
    mock_429.text = "Too Many Requests"
    mock_429.headers = {"Retry-After": "60"}
    responses.append(mock_429)

    with patch(
        "va_mcp.tools.insecure_design.rate_limit_check.requests.request",
        side_effect=responses,
    ):
        result = RateLimitCheckTool().run(_make_tool_input(repeat_count=10))

    assert result.status == "passed"
    assert result.severity == "info"
    assert result.confidence == "high"
    assert len(result.evidence) > 0
    assert result.evidence[0].response_status == 429


def test_vulnerable():
    """429 응답이 없으면 Rate Limit 미존재 → VULNERABLE"""
    mock_resp = MagicMock()
    mock_resp.status_code = 200
    mock_resp.text = '{"ok": true}'
    mock_resp.headers = {}

    with patch(
        "va_mcp.tools.insecure_design.rate_limit_check.requests.request",
        return_value=mock_resp,
    ):
        result = RateLimitCheckTool().run(_make_tool_input(repeat_count=5))

    assert result.status == "vulnerable"
    assert result.severity == "medium"
    assert result.confidence == "medium"
    assert len(result.evidence) > 0
    assert "429" in result.evidence[0].note


def test_error():
    """요청 예외 발생 시 → ERROR"""
    import requests as req_lib

    with patch(
        "va_mcp.tools.insecure_design.rate_limit_check.requests.request",
        side_effect=req_lib.exceptions.ConnectionError("connection refused"),
    ):
        result = RateLimitCheckTool().run(_make_tool_input(repeat_count=3))

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
    result = RateLimitCheckTool().run(tool_input)

    assert result.status == "skipped"
    assert len(result.evidence) == 0


def test_invalid_repeat_count():
    """repeat_count가 유효하지 않으면 → ERROR + INVALID_INPUT"""
    result = RateLimitCheckTool().run(_make_tool_input(repeat_count=-1))

    assert result.status == "error"
    assert result.errors[0].error_code == "INVALID_INPUT"
