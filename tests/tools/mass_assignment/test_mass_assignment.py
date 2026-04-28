"""
Mass Assignment Check Tool 테스트

필수 3종: test_passed / test_vulnerable / test_error
"""

from __future__ import annotations

from unittest.mock import MagicMock, patch

from va_mcp.core.schemas import ApiRequest, TargetInfo, ToolInput, ToolOptions
from va_mcp.tools.insecure_design.mass_assignment import MassAssignmentTool


def _make_tool_input(**extra_opts) -> ToolInput:
    return ToolInput(
        target=TargetInfo(base_url="https://test-target.com"),
        request=ApiRequest(
            method="POST",
            path="/api/users",
            body={"name": "testuser", "email": "test@example.com"},
        ),
        options=ToolOptions(extra=extra_opts),
    )


def test_passed():
    """주입 필드가 응답에 반영되지 않으면 → PASSED"""
    mock_original = MagicMock()
    mock_original.status_code = 201
    mock_original.text = '{"id": 1, "name": "testuser", "email": "test@example.com"}'
    mock_original.headers = {}

    mock_injected = MagicMock()
    mock_injected.status_code = 201
    mock_injected.text = '{"id": 1, "name": "testuser", "email": "test@example.com"}'
    mock_injected.headers = {}

    with patch(
        "va_mcp.tools.insecure_design.mass_assignment.requests.request",
        side_effect=[mock_original, mock_injected],
    ):
        result = MassAssignmentTool().run(_make_tool_input())

    assert result.status == "passed"
    assert result.severity == "info"
    assert len(result.evidence) > 0


def test_vulnerable():
    """주입 필드가 응답에 반영되면 → VULNERABLE"""
    mock_original = MagicMock()
    mock_original.status_code = 201
    mock_original.text = '{"id": 1, "name": "testuser"}'
    mock_original.headers = {}

    mock_injected = MagicMock()
    mock_injected.status_code = 201
    mock_injected.text = '{"id": 1, "name": "testuser", "role": "admin", "is_admin": true}'
    mock_injected.headers = {}

    with patch(
        "va_mcp.tools.insecure_design.mass_assignment.requests.request",
        side_effect=[mock_original, mock_injected],
    ):
        result = MassAssignmentTool().run(_make_tool_input())

    assert result.status == "vulnerable"
    assert result.severity == "high"
    assert result.confidence == "high"
    assert len(result.evidence) > 0
    assert "role" in result.evidence[0].note


def test_error():
    """요청 예외 발생 시 → ERROR"""
    import requests as req_lib

    with patch(
        "va_mcp.tools.insecure_design.mass_assignment.requests.request",
        side_effect=req_lib.exceptions.ConnectionError("connection refused"),
    ):
        result = MassAssignmentTool().run(_make_tool_input())

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
    result = MassAssignmentTool().run(tool_input)

    assert result.status == "skipped"
    assert len(result.evidence) == 0


def test_skipped_get_method():
    """GET 메서드는 검사 대상 아님 → SKIPPED"""
    tool_input = ToolInput(
        target=TargetInfo(base_url="https://test-target.com"),
        request=ApiRequest(method="GET", path="/api/users"),
    )
    result = MassAssignmentTool().run(tool_input)

    assert result.status == "skipped"


def test_invalid_inject_fields():
    """inject_fields가 dict가 아니면 → ERROR + INVALID_INPUT"""
    result = MassAssignmentTool().run(_make_tool_input(inject_fields="not_a_dict"))

    assert result.status == "error"
    assert result.errors[0].error_code == "INVALID_INPUT"
