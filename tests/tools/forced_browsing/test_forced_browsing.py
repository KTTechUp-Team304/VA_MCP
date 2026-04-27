"""
ForcedBrowsingTool 테스트.

주의: 이 도구는 requests.get()을 사용한다 (requests.request 아님).

테스트 구성:
  test_passed                - 모든 기본 경로가 차단될 때 PASSED 반환
  test_vulnerable            - 특정 경로에 200 응답 시 VULNERABLE + evidence
  test_vulnerable_multiple   - 여러 경로에 200 응답 시 evidence 여러 개
  test_403_is_not_vulnerable - 403은 VULNERABLE이 아님 (PASSED 반환)
  test_extra_paths           - extra["paths"] 추가 경로도 테스트됨
  test_error_timeout         - Timeout 발생 시 ERROR + errors
  test_error_request_fail    - RequestException 발생 시 ERROR + errors
  test_with_auth             - auth 제공 시 인증 헤더 포함 요청
"""

from unittest.mock import MagicMock, call, patch

import requests

from va_mcp.core import AuthContext, TargetInfo, ToolInput, ToolOptions
from va_mcp.tools.access_control.forced_browsing import ForcedBrowsingTool


# ------------------------------------------------------------------
# 공통 헬퍼
# ------------------------------------------------------------------

def make_tool_input(auth=None, extra=None) -> ToolInput:
    return ToolInput(
        target=TargetInfo(base_url="https://test.example.com"),
        auth=auth or [],
        options=ToolOptions(extra=extra or {}),
    )


def mock_response(status_code: int, text: str = "") -> MagicMock:
    resp = MagicMock()
    resp.status_code = status_code
    resp.text = text
    resp.headers = {}
    resp.request = MagicMock()
    resp.request.headers = {}
    return resp


def blocked_side_effect(*args, **kwargs):
    """모든 경로에 404 반환."""
    return mock_response(404)


# ------------------------------------------------------------------
# 테스트
# ------------------------------------------------------------------

def test_passed():
    """모든 기본 경로가 404/403으로 차단되면 PASSED를 반환한다."""
    with patch("requests.get", side_effect=blocked_side_effect):
        result = ForcedBrowsingTool().run(make_tool_input())

    assert result.status == "passed"
    assert result.evidence == []


def test_vulnerable():
    """기본 경로 중 /admin 이 200이면 VULNERABLE + evidence를 반환한다."""
    def side_effect(url, **kwargs):
        if "/admin" in url and "administrator" not in url and "api" not in url:
            return mock_response(200, "<html>Admin Panel</html>")
        return mock_response(404)

    with patch("requests.get", side_effect=side_effect):
        result = ForcedBrowsingTool().run(make_tool_input())

    assert result.status == "vulnerable"
    assert len(result.evidence) >= 1
    assert result.severity == "high"
    assert result.confidence == "high"
    assert "CWE-425" in result.cwe


def test_vulnerable_multiple_paths():
    """여러 경로에서 200이 오면 evidence가 여러 개 반환된다."""
    base = "https://test.example.com"
    exposed_urls = {f"{base}/admin", f"{base}/swagger"}

    def side_effect(url, **kwargs):
        if url in exposed_urls:
            return mock_response(200, "exposed")
        return mock_response(404)

    with patch("requests.get", side_effect=side_effect):
        result = ForcedBrowsingTool().run(make_tool_input())

    assert result.status == "vulnerable"
    assert len(result.evidence) == 2


def test_403_is_not_vulnerable():
    """403은 취약점이 아니므로 PASSED를 반환한다."""
    with patch("requests.get", return_value=mock_response(403)):
        result = ForcedBrowsingTool().run(make_tool_input())

    assert result.status == "passed"
    assert result.evidence == []


def test_extra_paths_vulnerable():
    """extra['paths']로 추가된 경로에서 200이 오면 VULNERABLE을 반환한다."""
    def side_effect(url, **kwargs):
        if "/internal/debug" in url:
            return mock_response(200, '{"debug": true}')
        return mock_response(404)

    with patch("requests.get", side_effect=side_effect):
        result = ForcedBrowsingTool().run(
            make_tool_input(extra={"paths": ["/internal/debug"]})
        )

    assert result.status == "vulnerable"
    assert any("/internal/debug" in e.note for e in result.evidence)


def test_error_timeout():
    """Timeout 발생 시 ERROR + errors를 반환한다."""
    with patch("requests.get", side_effect=requests.Timeout):
        result = ForcedBrowsingTool().run(make_tool_input())

    assert result.status == "error"
    assert len(result.errors) > 0
    assert result.errors[0].error_code == "TIMEOUT"
    assert result.severity == "info"
    assert result.confidence == "low"


def test_error_request_fail():
    """RequestException 발생 시 ERROR + errors를 반환한다."""
    with patch("requests.get", side_effect=requests.RequestException("connection reset")):
        result = ForcedBrowsingTool().run(make_tool_input())

    assert result.status == "error"
    assert result.errors[0].error_code == "HTTP_FAILURE"


def test_with_auth_sends_authorization_header():
    """auth 제공 시 Authorization 헤더가 포함된 요청을 보낸다."""
    sent_headers = []

    def side_effect(url, headers=None, **kwargs):
        sent_headers.append(headers or {})
        return mock_response(404)

    auth = [AuthContext(role="user", auth_type="bearer", token="MY_TOKEN")]

    with patch("requests.get", side_effect=side_effect):
        ForcedBrowsingTool().run(make_tool_input(auth=auth))

    assert any("Authorization" in h for h in sent_headers)
    assert any("Bearer MY_TOKEN" in h.get("Authorization", "") for h in sent_headers)


def test_max_requests_respected():
    """max_requests 제한을 초과하지 않는다."""
    call_count = 0

    def side_effect(url, **kwargs):
        nonlocal call_count
        call_count += 1
        return mock_response(404)

    with patch("requests.get", side_effect=side_effect):
        ForcedBrowsingTool().run(make_tool_input())

    assert call_count <= ToolOptions().max_requests
