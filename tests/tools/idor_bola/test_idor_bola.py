"""
IdorBolaTool 테스트.

테스트 구성:
  test_passed               - 공격자 접근이 차단될 때 PASSED 반환
  test_vulnerable           - 공격자가 소유자 리소스에 접근 성공 시 VULNERABLE + evidence
  test_vulnerable_body_match - body 일치 시 confidence=HIGH
  test_error_timeout        - Timeout 발생 시 ERROR + errors
  test_error_request_fail   - RequestException 발생 시 ERROR + errors
  test_skipped_no_request   - request 없으면 SKIPPED
  test_skipped_insufficient_auth - auth < 2개면 SKIPPED
  test_skipped_owner_fails  - 소유자 요청도 실패하면 SKIPPED
"""

from unittest.mock import MagicMock, patch

import requests

from va_mcp.core import AuthContext, TargetInfo, ToolInput, ToolOptions
from va_mcp.core.schemas import ApiRequest
from va_mcp.tools.idor_bola import IdorBolaTool


# ------------------------------------------------------------------
# 공통 헬퍼
# ------------------------------------------------------------------

def make_tool_input(auth=None, request=None) -> ToolInput:
    return ToolInput(
        target=TargetInfo(base_url="https://test.example.com"),
        request=request or ApiRequest(method="GET", path="/api/users/2/profile"),
        auth=auth or [
            AuthContext(role="user_a", auth_type="bearer", token="TOKEN_A"),
            AuthContext(role="user_b", auth_type="bearer", token="TOKEN_B"),
        ],
        options=ToolOptions(),
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
    """공격자(user_a) 접근이 403으로 차단되면 PASSED를 반환한다."""
    owner_resp = mock_response(200, '{"id": 2, "email": "user2@test.com"}')
    attacker_resp = mock_response(403, '{"error": "Forbidden"}')

    with patch("requests.request", side_effect=[owner_resp, attacker_resp]):
        result = IdorBolaTool().run(make_tool_input())

    assert result.status == "passed"
    assert result.evidence == []


def test_vulnerable():
    """공격자가 소유자 리소스에 접근 성공하면 VULNERABLE + evidence를 반환한다."""
    owner_resp = mock_response(200, '{"id": 2, "email": "user2@test.com"}')
    attacker_resp = mock_response(200, '{"id": 2, "email": "user2@test.com"}')

    with patch("requests.request", side_effect=[owner_resp, attacker_resp]):
        result = IdorBolaTool().run(make_tool_input())

    assert result.status == "vulnerable"
    assert len(result.evidence) == 1
    assert result.severity == "high"
    assert result.confidence == "high"
    assert "CWE-639" in result.cwe


def test_vulnerable_body_mismatch_lowers_confidence():
    """body가 달라지면 confidence=MEDIUM으로 낮아진다."""
    owner_resp = mock_response(200, '{"id": 2, "email": "user2@test.com", "secret": "xyz"}')
    attacker_resp = mock_response(200, '{"id": 2}')

    with patch("requests.request", side_effect=[owner_resp, attacker_resp]):
        result = IdorBolaTool().run(make_tool_input())

    assert result.status == "vulnerable"
    assert result.confidence == "medium"


def test_error_timeout():
    """Timeout 발생 시 ERROR + errors를 반환한다."""
    with patch("requests.request", side_effect=requests.Timeout):
        result = IdorBolaTool().run(make_tool_input())

    assert result.status == "error"
    assert len(result.errors) > 0
    assert result.errors[0].error_code == "TIMEOUT"
    assert result.severity == "info"
    assert result.confidence == "low"


def test_error_request_fail():
    """RequestException 발생 시 ERROR + errors를 반환한다."""
    with patch("requests.request", side_effect=requests.RequestException("network error")):
        result = IdorBolaTool().run(make_tool_input())

    assert result.status == "error"
    assert result.errors[0].error_code == "HTTP_FAILURE"


def test_skipped_no_request():
    """request가 없으면 SKIPPED를 반환한다."""
    tool_input = ToolInput(
        target=TargetInfo(base_url="https://test.example.com"),
        request=None,
        auth=[
            AuthContext(role="user_a", auth_type="bearer", token="TOKEN_A"),
            AuthContext(role="user_b", auth_type="bearer", token="TOKEN_B"),
        ],
    )
    result = IdorBolaTool().run(tool_input)

    assert result.status == "skipped"
    assert result.evidence == []


def test_skipped_insufficient_auth():
    """auth가 1개 이하면 SKIPPED를 반환한다."""
    tool_input = make_tool_input(
        auth=[AuthContext(role="user_a", auth_type="bearer", token="TOKEN_A")]
    )
    result = IdorBolaTool().run(tool_input)

    assert result.status == "skipped"
    assert result.evidence == []


def test_skipped_owner_fails():
    """소유자(user_b) 요청도 실패하면 SKIPPED를 반환한다."""
    owner_fail = mock_response(404, '{"error": "Not Found"}')

    with patch("requests.request", return_value=owner_fail):
        result = IdorBolaTool().run(make_tool_input())

    assert result.status == "skipped"
