"""
ParameterTamperTool 테스트.

테스트 구성:
  test_passed                     - 변조 후 응답 변화 없음 → PASSED 반환
  test_vulnerable_status_change   - 403→200 상태코드 변화 → VULNERABLE HIGH
  test_vulnerable_body_change     - 상태코드 동일 + body 변화 → VULNERABLE MEDIUM
  test_auto_detect_privilege_key  - query에 'role' 키 자동 탐지 후 변조
  test_explicit_target_params     - extra["target_params"] 명시 시 해당 파라미터만 변조
  test_skipped_no_request         - request 없으면 SKIPPED
  test_skipped_no_targets         - 권한 관련 파라미터 없으면 SKIPPED
  test_error_timeout              - Timeout 발생 시 ERROR + errors
  test_error_request_fail         - RequestException 발생 시 ERROR + errors
"""

from unittest.mock import MagicMock, patch

import requests

from va_mcp.core import AuthContext, TargetInfo, ToolInput, ToolOptions
from va_mcp.core.schemas import ApiRequest
from va_mcp.tools.access_control.parameter_tamper import ParameterTamperTool


# ------------------------------------------------------------------
# 공통 헬퍼
# ------------------------------------------------------------------

def make_tool_input(
    query=None,
    body=None,
    auth=None,
    extra=None,
) -> ToolInput:
    return ToolInput(
        target=TargetInfo(base_url="https://test.example.com"),
        request=ApiRequest(
            method="GET",
            path="/api/profile",
            query=query or {},
            body=body,
        ),
        auth=auth or [],
        options=ToolOptions(extra=extra or {}),
    )


def mock_response(status_code: int, text: str = "{}") -> MagicMock:
    resp = MagicMock()
    resp.status_code = status_code
    resp.text = text
    resp.headers = {"Content-Type": "application/json"}
    resp.request = MagicMock()
    resp.request.headers = {}
    return resp


# ------------------------------------------------------------------
# 테스트
# ------------------------------------------------------------------

def test_passed():
    """변조 후 응답 변화가 없으면 PASSED를 반환한다."""
    same_resp = mock_response(200, '{"data": "ok"}')

    with patch("requests.request", return_value=same_resp):
        result = ParameterTamperTool().run(
            make_tool_input(query={"role": "user"})
        )

    assert result.status == "passed"
    assert result.evidence == []


def test_vulnerable_status_change():
    """원본 403 → 변조 후 200이면 VULNERABLE HIGH를 반환한다."""
    call_count = 0

    def side_effect(*args, **kwargs):
        nonlocal call_count
        call_count += 1
        if call_count == 1:
            return mock_response(403, '{"error": "Forbidden"}')
        return mock_response(200, '{"data": "admin data"}')

    with patch("requests.request", side_effect=side_effect):
        result = ParameterTamperTool().run(
            make_tool_input(query={"role": "user"})
        )

    assert result.status == "vulnerable"
    assert result.severity == "high"
    assert result.confidence == "high"
    assert len(result.evidence) >= 1
    assert "CWE-639" in result.cwe


def test_vulnerable_body_change():
    """상태코드 동일 + body 변화 시 VULNERABLE MEDIUM을 반환한다."""
    original_resp = mock_response(200, '{"name": "user", "role": "user"}')
    tampered_resp = mock_response(200, '{"name": "user", "role": "admin", "secret": "xyz"}')

    with patch("requests.request", side_effect=[original_resp] + [tampered_resp] * 20):
        result = ParameterTamperTool().run(
            make_tool_input(query={"role": "user"})
        )

    assert result.status == "vulnerable"
    assert result.severity == "medium"
    assert result.confidence == "medium"


def test_auto_detect_privilege_key_in_query():
    """query에 'role' 키가 있으면 자동 탐지하여 변조한다."""
    call_count = 0

    def side_effect(*args, **kwargs):
        nonlocal call_count
        call_count += 1
        if call_count == 1:
            return mock_response(403, '{"error": "Forbidden"}')
        return mock_response(200, '{"admin": true}')

    with patch("requests.request", side_effect=side_effect):
        result = ParameterTamperTool().run(
            make_tool_input(query={"role": "user"})
        )

    assert result.status == "vulnerable"


def test_auto_detect_privilege_key_in_body():
    """body에 'is_admin' 키가 있으면 자동 탐지하여 변조한다."""
    call_count = 0

    def side_effect(*args, **kwargs):
        nonlocal call_count
        call_count += 1
        if call_count == 1:
            return mock_response(403, '{"error": "Forbidden"}')
        return mock_response(200, '{"success": true}')

    with patch("requests.request", side_effect=side_effect):
        result = ParameterTamperTool().run(
            make_tool_input(body={"is_admin": "false", "name": "test"})
        )

    assert result.status == "vulnerable"


def test_explicit_target_params():
    """extra['target_params'] 지정 시 해당 파라미터만 변조하고 VULNERABLE을 반환한다."""
    call_count = 0

    def side_effect(*args, **kwargs):
        nonlocal call_count
        call_count += 1
        if call_count == 1:
            return mock_response(403, '{"error": "Forbidden"}')
        return mock_response(200, '{"granted": true}')

    with patch("requests.request", side_effect=side_effect):
        result = ParameterTamperTool().run(
            make_tool_input(
                query={"user_id": "1"},
                extra={
                    "target_params": [
                        {"key": "user_id", "values": ["0", "-1"]}
                    ]
                },
            )
        )

    assert result.status == "vulnerable"
    assert call_count <= 3  # 원본 1회 + 페이로드 2회


def test_skipped_no_request():
    """request가 없으면 SKIPPED를 반환한다."""
    tool_input = ToolInput(
        target=TargetInfo(base_url="https://test.example.com"),
        request=None,
    )
    result = ParameterTamperTool().run(tool_input)

    assert result.status == "skipped"
    assert result.evidence == []


def test_skipped_no_privilege_params():
    """query/body에 권한 관련 키가 없고 extra도 없으면 SKIPPED를 반환한다."""
    result = ParameterTamperTool().run(
        make_tool_input(query={"page": "1", "limit": "10"})
    )

    assert result.status == "skipped"
    assert result.evidence == []


def test_error_timeout():
    """기준 요청에서 Timeout 발생 시 ERROR + errors를 반환한다."""
    with patch("requests.request", side_effect=requests.Timeout):
        result = ParameterTamperTool().run(
            make_tool_input(query={"role": "user"})
        )

    assert result.status == "error"
    assert len(result.errors) > 0
    assert result.errors[0].error_code == "TIMEOUT"
    assert result.severity == "info"
    assert result.confidence == "low"


def test_error_request_fail():
    """RequestException 발생 시 ERROR + errors를 반환한다."""
    with patch("requests.request", side_effect=requests.RequestException("ssl error")):
        result = ParameterTamperTool().run(
            make_tool_input(query={"role": "user"})
        )

    assert result.status == "error"
    assert result.errors[0].error_code == "HTTP_FAILURE"
