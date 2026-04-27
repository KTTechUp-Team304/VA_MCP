"""
RbacCheckTool 테스트.

테스트 구성:
  test_passed               - 저권한 접근이 차단될 때 PASSED 반환
  test_vulnerable           - 저권한 접근이 성공할 때 VULNERABLE + evidence 반환
  test_vulnerable_body_match - body까지 일치하면 confidence=HIGH
  test_error_timeout        - Timeout 발생 시 ERROR + errors 반환
  test_error_request_fail   - RequestException 발생 시 ERROR + errors 반환
  test_skipped_no_request   - request 없으면 SKIPPED
  test_skipped_insufficient_auth - auth < 2개면 SKIPPED
  test_skipped_high_auth_fails   - 고권한도 실패하면 SKIPPED
"""

from unittest.mock import MagicMock, patch

import pytest
import requests

from va_mcp.core import AuthContext, TargetInfo, ToolInput, ToolOptions
from va_mcp.core.schemas import ApiRequest
from va_mcp.tools.rbac_check import RbacCheckTool


# ------------------------------------------------------------------
# 공통 헬퍼
# ------------------------------------------------------------------

def make_tool_input(
    auth=None,
    request=None,
    options=None,
) -> ToolInput:
    return ToolInput(
        target=TargetInfo(base_url="https://test.example.com"),
        request=request or ApiRequest(method="GET", path="/api/admin/users"),
        auth=auth or [
            AuthContext(role="user", auth_type="bearer", token="USER_TOKEN"),
            AuthContext(role="admin", auth_type="bearer", token="ADMIN_TOKEN"),
        ],
        options=options or ToolOptions(),
    )


def mock_response(status_code: int, text: str = "{}") -> MagicMock:
    resp = MagicMock()
    resp.status_code = status_code
    resp.text = text
    resp.headers = {"Content-Type": "application/json"}
    resp.request = MagicMock()
    resp.request.headers = {"Authorization": "Bearer TOKEN"}
    return resp


# ------------------------------------------------------------------
# 테스트
# ------------------------------------------------------------------

def test_passed():
    """저권한(user) 요청이 403으로 차단되면 PASSED를 반환한다."""
    admin_resp = mock_response(200, '{"users": []}')
    user_resp = mock_response(403, '{"error": "Forbidden"}')

    with patch("requests.request", side_effect=[admin_resp, user_resp]):
        result = RbacCheckTool().run(make_tool_input())

    assert result.status == "passed"
    assert result.evidence == []


def test_vulnerable():
    """저권한(user) 요청이 200이면 VULNERABLE + evidence를 반환한다."""
    admin_resp = mock_response(200, '{"users": [{"id": 1}]}')
    user_resp = mock_response(200, '{"users": [{"id": 1}]}')

    with patch("requests.request", side_effect=[admin_resp, user_resp]):
        result = RbacCheckTool().run(make_tool_input())

    assert result.status == "vulnerable"
    assert len(result.evidence) == 1
    assert result.severity == "high"
    assert result.confidence == "high"


def test_vulnerable_body_mismatch_lowers_confidence():
    """body가 달라지면 confidence=MEDIUM으로 낮아진다."""
    admin_resp = mock_response(200, '{"users": [{"id": 1, "secret": "xyz"}]}')
    user_resp = mock_response(200, '{"partial": true}')

    with patch("requests.request", side_effect=[admin_resp, user_resp]):
        result = RbacCheckTool().run(make_tool_input())

    assert result.status == "vulnerable"
    assert result.confidence == "medium"


def test_error_timeout():
    """Timeout 발생 시 ERROR + errors를 반환한다."""
    with patch("requests.request", side_effect=requests.Timeout):
        result = RbacCheckTool().run(make_tool_input())

    assert result.status == "error"
    assert len(result.errors) > 0
    assert result.errors[0].error_code == "TIMEOUT"
    assert result.severity == "info"
    assert result.confidence == "low"


def test_error_request_fail():
    """RequestException 발생 시 ERROR + errors를 반환한다."""
    with patch("requests.request", side_effect=requests.RequestException("connection refused")):
        result = RbacCheckTool().run(make_tool_input())

    assert result.status == "error"
    assert len(result.errors) > 0
    assert result.errors[0].error_code == "HTTP_FAILURE"


def test_skipped_no_request():
    """request가 없으면 SKIPPED를 반환한다."""
    tool_input = ToolInput(
        target=TargetInfo(base_url="https://test.example.com"),
        request=None,
        auth=[
            AuthContext(role="user", auth_type="bearer", token="USER_TOKEN"),
            AuthContext(role="admin", auth_type="bearer", token="ADMIN_TOKEN"),
        ],
    )
    result = RbacCheckTool().run(tool_input)

    assert result.status == "skipped"
    assert result.evidence == []


def test_skipped_insufficient_auth():
    """auth가 1개 이하면 SKIPPED를 반환한다."""
    tool_input = make_tool_input(
        auth=[AuthContext(role="user", auth_type="bearer", token="USER_TOKEN")]
    )
    result = RbacCheckTool().run(tool_input)

    assert result.status == "skipped"
    assert result.evidence == []


def test_skipped_high_auth_fails():
    """고권한 요청도 실패하면 엔드포인트 오류로 SKIPPED를 반환한다."""
    admin_fail = mock_response(500, '{"error": "Internal Server Error"}')

    with patch("requests.request", return_value=admin_fail):
        result = RbacCheckTool().run(make_tool_input())

    assert result.status == "skipped"
