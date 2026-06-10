"""
BflaTool 테스트.

테스트 구성:
  test_passed                  - 관리자 기능 접근이 차단될 때 PASSED 반환
  test_vulnerable              - 낮은 권한으로 관리자 기능 접근 성공 시 VULNERABLE + evidence
  test_vulnerable_multiple_paths - additional_paths 중 일부 취약하면 evidence 여러 개
  test_error_timeout           - Timeout 발생 시 ERROR + errors
  test_error_request_fail      - RequestException 발생 시 ERROR + errors
  test_skipped_no_request      - request 없으면 SKIPPED
  test_skipped_no_auth         - auth 없으면 SKIPPED
  test_additional_paths        - extra["additional_paths"] 경로도 테스트됨
"""

from unittest.mock import MagicMock, patch

import requests

from va_mcp.core import AuthContext, TargetInfo, ToolInput, ToolOptions
from va_mcp.core.schemas import ApiRequest
from va_mcp.tools.access_control.bfla import BflaTool


# ------------------------------------------------------------------
# 공통 헬퍼
# ------------------------------------------------------------------

def make_tool_input(auth=None, request=None, extra=None) -> ToolInput:
    return ToolInput(
        target=TargetInfo(base_url="https://test.example.com"),
        request=request or ApiRequest(method="GET", path="/api/admin/users"),
        auth=auth or [
            AuthContext(role="user", auth_type="bearer", token="USER_TOKEN"),
        ],
        options=ToolOptions(extra=extra or {}),
    )


def mock_response(status_code: int, text: str = "{}") -> MagicMock:
    resp = MagicMock()
    resp.status_code = status_code
    resp.text = text
    resp.headers = {"Content-Type": "application/json"}
    resp.request = MagicMock()
    resp.request.headers = {"Authorization": "Bearer USER_TOKEN"}
    return resp


# ------------------------------------------------------------------
# 테스트
# ------------------------------------------------------------------

def test_passed():
    """저권한(user) 관리자 기능 접근이 403으로 차단되면 PASSED를 반환한다."""
    with patch("requests.request", return_value=mock_response(403, '{"error": "Forbidden"}')):
        result = BflaTool().run(make_tool_input())

    assert result.status == "passed"
    assert result.evidence == []


def test_vulnerable():
    """저권한(user)으로 관리자 기능 접근이 성공하면 VULNERABLE + evidence를 반환한다."""
    with patch("requests.request", return_value=mock_response(200, '{"users": []}')):
        result = BflaTool().run(make_tool_input())

    assert result.status == "vulnerable"
    assert len(result.evidence) == 1
    assert result.severity == "high"
    assert result.confidence == "high"
    assert "CWE-285" in result.cwe


def test_vulnerable_multiple_paths():
    """additional_paths 중 여러 경로가 취약하면 evidence가 여러 개 반환된다."""
    vuln_resp = mock_response(200, '{"data": "admin data"}')
    block_resp = mock_response(403)

    with patch("requests.request", side_effect=[vuln_resp, block_resp, vuln_resp]):
        result = BflaTool().run(
            make_tool_input(
                extra={"additional_paths": ["/api/admin/reports", "/api/admin/settings"]}
            )
        )

    assert result.status == "vulnerable"
    assert len(result.evidence) == 2


def test_additional_paths_all_blocked():
    """additional_paths 경로도 차단되면 PASSED를 반환한다."""
    with patch("requests.request", return_value=mock_response(403)):
        result = BflaTool().run(
            make_tool_input(extra={"additional_paths": ["/api/admin/reports"]})
        )

    assert result.status == "passed"


def test_error_timeout():
    """Timeout 발생 시 ERROR + errors를 반환한다."""
    with patch("requests.request", side_effect=requests.Timeout):
        result = BflaTool().run(make_tool_input())

    assert result.status == "error"
    assert len(result.errors) > 0
    assert result.errors[0].error_code == "TIMEOUT"
    assert result.severity == "info"
    assert result.confidence == "low"


def test_error_request_fail():
    """RequestException 발생 시 ERROR + errors를 반환한다."""
    with patch("requests.request", side_effect=requests.RequestException("connection error")):
        result = BflaTool().run(make_tool_input())

    assert result.status == "error"
    assert result.errors[0].error_code == "HTTP_FAILURE"


def test_skipped_no_request():
    """request가 없으면 SKIPPED를 반환한다."""
    tool_input = ToolInput(
        target=TargetInfo(base_url="https://test.example.com"),
        request=None,
        auth=[AuthContext(role="user", auth_type="bearer", token="TOKEN")],
    )
    result = BflaTool().run(tool_input)

    assert result.status == "skipped"
    assert result.evidence == []


def test_skipped_no_auth():
    """auth가 없으면 SKIPPED를 반환한다."""
    tool_input = ToolInput(
        target=TargetInfo(base_url="https://test.example.com"),
        request=ApiRequest(method="GET", path="/api/admin/users"),
        auth=[],
    )
    result = BflaTool().run(tool_input)

    assert result.status == "skipped"
    assert result.evidence == []


# ------------------------------------------------------------------
# T-5 fix: auth[-1] 사전 검증 + 2xx 범위 + 메서드별 분기
# ------------------------------------------------------------------

def test_vulnerable_201():
    """저권한 응답이 201이어도 VULNERABLE로 판정한다 (2xx 범위 전체 포함)."""
    with patch("requests.request", return_value=mock_response(201, '{"created": true}')):
        result = BflaTool().run(make_tool_input())

    assert result.status == "vulnerable"
    assert len(result.evidence) == 1


def test_get_privileged_blocked_skips_path():
    """GET + 2 auths에서 auth[-1] 사전 검증이 4xx이면 해당 경로를 건너뛰고 PASSED를 반환한다."""
    two_auths = [
        AuthContext(role="user", auth_type="bearer", token="USER_TOKEN"),
        AuthContext(role="admin", auth_type="bearer", token="ADMIN_TOKEN"),
    ]
    with patch("requests.request", side_effect=[mock_response(403)]) as mock_req:
        result = BflaTool().run(make_tool_input(auth=two_auths))

    assert result.status == "passed"
    # auth[-1] 사전 검증 1회만 호출 (auth[0] 요청은 발생하지 않음)
    assert mock_req.call_count == 1


def test_post_skips_privileged_pre_validation():
    """POST 메서드에서는 auth[-1] 사전 검증 없이 auth[0] 요청만 1회 실행한다."""
    two_auths = [
        AuthContext(role="user", auth_type="bearer", token="USER_TOKEN"),
        AuthContext(role="admin", auth_type="bearer", token="ADMIN_TOKEN"),
    ]
    with patch("requests.request", side_effect=[mock_response(201)]) as mock_req:
        result = BflaTool().run(
            make_tool_input(
                auth=two_auths,
                request=ApiRequest(method="POST", path="/api/admin/audit-logs/clear"),
            )
        )

    assert result.status == "vulnerable"
    # auth[0] 단독 1회 호출만 발생 (auth[-1] 사전 검증 없음)
    assert mock_req.call_count == 1
