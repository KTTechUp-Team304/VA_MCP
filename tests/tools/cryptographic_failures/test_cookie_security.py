"""
CookieSecurityTool 테스트.

테스트 구성:
  test_skipped_no_request               - request가 None이면 SKIPPED 반환
  test_skipped_no_set_cookie            - Set-Cookie 헤더 없으면 SKIPPED 반환
  test_passed                           - Secure, HttpOnly, SameSite=Strict 모두 있으면 PASSED
  test_passed_samesite_none_with_secure - SameSite=None + Secure 조합은 PASSED (유효한 설정)
  test_vulnerable_missing_secure        - Secure 누락 시 VULNERABLE
  test_vulnerable_missing_httponly      - HttpOnly 누락 시 VULNERABLE
  test_vulnerable_missing_samesite      - SameSite 누락 시 VULNERABLE
  test_vulnerable_samesite_none_no_secure - SameSite=None + Secure 없음 → 단일 통합 메시지
  test_multiple_cookies_partial_vulnerable - 여러 쿠키 중 일부만 취약한 경우
  test_error_timeout                    - Timeout 발생 시 ERROR + errors
  test_error_request_fail               - RequestException 발생 시 ERROR + errors
"""

from unittest.mock import MagicMock, patch

import requests

from va_mcp.core import TargetInfo, ToolInput, ToolOptions
from va_mcp.core.schemas import ApiRequest
from va_mcp.tools.cryptographic_failures.cookie_security import CookieSecurityTool


# ------------------------------------------------------------------
# 공통 헬퍼
# ------------------------------------------------------------------

def make_tool_input(path: str = "/api/login") -> ToolInput:
    return ToolInput(
        target=TargetInfo(base_url="https://test.example.com"),
        request=ApiRequest(method="POST", path=path),
        options=ToolOptions(),
    )


def make_tool_input_no_request() -> ToolInput:
    return ToolInput(
        target=TargetInfo(base_url="https://test.example.com"),
        request=None,
        options=ToolOptions(),
    )


def mock_response(status_code: int = 200, set_cookies: list[str] | None = None) -> MagicMock:
    resp = MagicMock()
    resp.status_code = status_code
    resp.text = ""
    resp.headers = {}
    resp.raw.headers.getlist.return_value = set_cookies or []
    return resp


# ------------------------------------------------------------------
# 테스트
# ------------------------------------------------------------------

def test_skipped_no_request():
    """request가 None이면 SKIPPED를 반환한다."""
    result = CookieSecurityTool().run(make_tool_input_no_request())
    assert result.status == "skipped"
    assert result.evidence == []


def test_skipped_no_set_cookie():
    """응답에 Set-Cookie 헤더가 없으면 SKIPPED를 반환한다."""
    with patch("requests.request", return_value=mock_response(200, set_cookies=[])):
        result = CookieSecurityTool().run(make_tool_input())
    assert result.status == "skipped"
    assert result.evidence == []


def test_passed():
    """Secure, HttpOnly, SameSite=Strict 모두 있으면 PASSED를 반환한다."""
    cookie = "session=abc123; Secure; HttpOnly; SameSite=Strict"
    with patch("requests.request", return_value=mock_response(200, set_cookies=[cookie])):
        result = CookieSecurityTool().run(make_tool_input())
    assert result.status == "passed"
    assert result.severity == "info"
    assert result.confidence == "high"
    assert "CWE-319" in result.cwe
    assert "CWE-523" in result.cwe


def test_passed_samesite_none_with_secure():
    """SameSite=None + Secure 조합은 크로스사이트 쿠키로 유효하며 PASSED를 반환한다."""
    cookie = "tracking=xyz; Secure; HttpOnly; SameSite=None"
    with patch("requests.request", return_value=mock_response(200, set_cookies=[cookie])):
        result = CookieSecurityTool().run(make_tool_input())
    assert result.status == "passed"


def test_vulnerable_missing_secure():
    """Secure 속성이 누락된 쿠키가 있으면 VULNERABLE을 반환한다."""
    cookie = "session=abc123; HttpOnly; SameSite=Strict"
    with patch("requests.request", return_value=mock_response(200, set_cookies=[cookie])):
        result = CookieSecurityTool().run(make_tool_input())
    assert result.status == "vulnerable"
    assert result.severity == "medium"
    assert result.confidence == "high"
    assert len(result.evidence) > 0
    assert "Secure 속성 누락" in result.evidence[0].note


def test_vulnerable_missing_httponly():
    """HttpOnly 속성이 누락된 쿠키가 있으면 VULNERABLE을 반환한다."""
    cookie = "session=abc123; Secure; SameSite=Strict"
    with patch("requests.request", return_value=mock_response(200, set_cookies=[cookie])):
        result = CookieSecurityTool().run(make_tool_input())
    assert result.status == "vulnerable"
    assert "HttpOnly 속성 누락" in result.evidence[0].note


def test_vulnerable_missing_samesite():
    """SameSite 속성이 누락된 쿠키가 있으면 VULNERABLE을 반환한다."""
    cookie = "session=abc123; Secure; HttpOnly"
    with patch("requests.request", return_value=mock_response(200, set_cookies=[cookie])):
        result = CookieSecurityTool().run(make_tool_input())
    assert result.status == "vulnerable"
    assert "SameSite 속성 누락" in result.evidence[0].note


def test_vulnerable_samesite_none_no_secure():
    """SameSite=None이고 Secure가 없으면 중복 없이 단일 통합 메시지로 VULNERABLE을 반환한다."""
    cookie = "session=abc123; HttpOnly; SameSite=None"
    with patch("requests.request", return_value=mock_response(200, set_cookies=[cookie])):
        result = CookieSecurityTool().run(make_tool_input())
    assert result.status == "vulnerable"
    note = result.evidence[0].note
    assert "SameSite=None" in note
    # "Secure 속성 누락" 메시지와 통합 메시지가 동시에 나오지 않아야 한다
    assert note.count("Secure") == 1


def test_multiple_cookies_partial_vulnerable():
    """여러 쿠키 중 일부만 취약한 경우 VULNERABLE + evidence note에 비율 정보를 포함한다."""
    safe_cookie = "csrf=token; Secure; HttpOnly; SameSite=Strict"
    vuln_cookie = "session=abc123; HttpOnly; SameSite=Strict"  # Secure 누락
    with patch("requests.request", return_value=mock_response(200, set_cookies=[safe_cookie, vuln_cookie])):
        result = CookieSecurityTool().run(make_tool_input())
    assert result.status == "vulnerable"
    assert "1/2" in result.evidence[0].note


def test_error_timeout():
    """Timeout 발생 시 ERROR + errors를 반환한다."""
    with patch("requests.request", side_effect=requests.Timeout):
        result = CookieSecurityTool().run(make_tool_input())
    assert result.status == "error"
    assert result.severity == "info"
    assert result.confidence == "low"
    assert len(result.errors) > 0
    assert result.errors[0].error_code == "TIMEOUT"


def test_error_request_fail():
    """RequestException 발생 시 ERROR + errors를 반환한다."""
    with patch("requests.request", side_effect=requests.RequestException("conn fail")):
        result = CookieSecurityTool().run(make_tool_input())
    assert result.status == "error"
    assert result.errors[0].error_code == "HTTP_FAILURE"
