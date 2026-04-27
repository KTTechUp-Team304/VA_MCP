"""
HttpMethodTamperTool 테스트.

테스트 구성:
  test_passed                  - 모든 다른 메서드가 405로 차단될 때 PASSED 반환
  test_vulnerable_delete       - DELETE로 200 응답 시 VULNERABLE + evidence
  test_vulnerable_trace        - TRACE 200 응답 시 VULNERABLE, severity=MEDIUM
  test_options_warning         - OPTIONS Allow에 위험 메서드 포함 시 PASSED, severity=LOW
  test_safe_mode_excludes_write - safe_mode=True면 POST/PUT/DELETE 테스트 제외
  test_explicit_test_methods   - extra["test_methods"] 지정 시 해당 메서드만 테스트
  test_error_timeout           - Timeout 발생 시 ERROR + errors
  test_error_request_fail      - RequestException 발생 시 ERROR + errors
  test_skipped_no_request      - request 없으면 SKIPPED
"""

from unittest.mock import MagicMock, patch

import requests

from va_mcp.core import AuthContext, TargetInfo, ToolInput, ToolOptions
from va_mcp.core.schemas import ApiRequest
from va_mcp.tools.http_method_tamper import HttpMethodTamperTool


# ------------------------------------------------------------------
# 공통 헬퍼
# ------------------------------------------------------------------

def make_tool_input(request=None, auth=None, extra=None, safe_mode=True) -> ToolInput:
    return ToolInput(
        target=TargetInfo(base_url="https://test.example.com"),
        request=request or ApiRequest(method="GET", path="/api/users"),
        auth=auth or [],
        options=ToolOptions(safe_mode=safe_mode, extra=extra or {}),
    )


def mock_response(status_code: int, text: str = "{}", headers: dict = None) -> MagicMock:
    resp = MagicMock()
    resp.status_code = status_code
    resp.text = text
    resp.headers = headers or {"Content-Type": "application/json"}
    resp.request = MagicMock()
    resp.request.headers = {}
    return resp


# ------------------------------------------------------------------
# 테스트
# ------------------------------------------------------------------

def test_passed():
    """모든 다른 메서드가 405로 차단되면 PASSED를 반환한다."""
    with patch("requests.request", return_value=mock_response(405)):
        result = HttpMethodTamperTool().run(make_tool_input())

    assert result.status == "passed"
    assert result.evidence == []


def test_vulnerable_delete():
    """safe_mode=False에서 DELETE로 200 응답이 오면 VULNERABLE을 반환한다."""
    def side_effect(method, url, **kwargs):
        if method == "DELETE":
            return mock_response(200)
        if method == "OPTIONS":
            return mock_response(200, headers={"Allow": "GET, HEAD"})
        return mock_response(405)

    with patch("requests.request", side_effect=side_effect):
        result = HttpMethodTamperTool().run(make_tool_input(safe_mode=False))

    assert result.status == "vulnerable"
    assert len(result.evidence) >= 1
    assert result.severity == "high"
    assert any(e.request["method"] == "DELETE" for e in result.evidence)


def test_vulnerable_trace():
    """TRACE 200 응답 시 VULNERABLE, severity=MEDIUM을 반환한다."""
    def side_effect(method, url, **kwargs):
        if method == "TRACE":
            return mock_response(200, "TRACE response")
        if method == "OPTIONS":
            return mock_response(200, headers={"Allow": "GET"})
        return mock_response(405)

    with patch("requests.request", side_effect=side_effect):
        result = HttpMethodTamperTool().run(make_tool_input(safe_mode=True))

    assert result.status == "vulnerable"
    assert any(e.request["method"] == "TRACE" for e in result.evidence)


def test_options_warning_dangerous_method():
    """OPTIONS Allow 헤더에 DELETE 포함 시 PASSED, severity=LOW를 반환한다."""
    def side_effect(method, url, **kwargs):
        if method == "OPTIONS":
            return mock_response(200, headers={"Allow": "GET, POST, DELETE"})
        return mock_response(405)

    with patch("requests.request", side_effect=side_effect):
        result = HttpMethodTamperTool().run(make_tool_input(safe_mode=True))

    assert result.status == "passed"
    assert result.severity == "low"


def test_safe_mode_excludes_write_methods():
    """safe_mode=True면 POST/PUT/PATCH/DELETE 메서드를 테스트하지 않는다."""
    tested_methods = []

    def side_effect(method, url, **kwargs):
        tested_methods.append(method)
        return mock_response(405)

    with patch("requests.request", side_effect=side_effect):
        HttpMethodTamperTool().run(make_tool_input(safe_mode=True))

    for dangerous in ("POST", "PUT", "PATCH", "DELETE"):
        assert dangerous not in tested_methods


def test_explicit_test_methods_override_safe_mode():
    """extra['test_methods'] 지정 시 safe_mode 무관하게 해당 메서드만 테스트한다."""
    tested_methods = []

    def side_effect(method, url, **kwargs):
        tested_methods.append(method)
        return mock_response(405)

    with patch("requests.request", side_effect=side_effect):
        HttpMethodTamperTool().run(
            make_tool_input(
                safe_mode=True,
                extra={"test_methods": ["DELETE", "PUT"]},
            )
        )

    assert "DELETE" in tested_methods
    assert "PUT" in tested_methods
    assert "HEAD" not in tested_methods
    assert "TRACE" not in tested_methods


def test_error_timeout():
    """Timeout 발생 시 ERROR + errors를 반환한다."""
    with patch("requests.request", side_effect=requests.Timeout):
        result = HttpMethodTamperTool().run(make_tool_input())

    assert result.status == "error"
    assert len(result.errors) > 0
    assert result.errors[0].error_code == "TIMEOUT"
    assert result.severity == "info"
    assert result.confidence == "low"


def test_error_request_fail():
    """RequestException 발생 시 ERROR + errors를 반환한다."""
    with patch("requests.request", side_effect=requests.RequestException("refused")):
        result = HttpMethodTamperTool().run(make_tool_input())

    assert result.status == "error"
    assert result.errors[0].error_code == "HTTP_FAILURE"


def test_skipped_no_request():
    """request가 없으면 SKIPPED를 반환한다."""
    tool_input = ToolInput(
        target=TargetInfo(base_url="https://test.example.com"),
        request=None,
    )
    result = HttpMethodTamperTool().run(tool_input)

    assert result.status == "skipped"
    assert result.evidence == []
