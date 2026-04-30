"""
SensitiveDataExposureTool 테스트.

테스트 구성:
  test_skipped_no_request               - request가 None이면 SKIPPED 반환
  test_passed                           - 민감 정보 없는 응답은 PASSED 반환
  test_vulnerable_email                 - 이메일 주소 포함 응답은 VULNERABLE HIGH
  test_vulnerable_ssn_with_separator    - 주민등록번호 (하이픈 포함) 탐지
  test_vulnerable_ssn_without_separator - 주민등록번호 (구분자 없음) 탐지
  test_vulnerable_password_double_quote - "password":"value" 형식 탐지
  test_vulnerable_password_single_quote - 'password':'value' 단따옴표 형식 탐지
  test_vulnerable_password_uppercase    - "Password":"value" 대소문자 탐지
  test_vulnerable_aws_access_key        - AKIA... AWS 키 탐지
  test_vulnerable_openssh_private_key   - BEGIN OPENSSH PRIVATE KEY 탐지
  test_vulnerable_custom_pattern        - extra["custom_patterns"] 적용 탐지
  test_error_invalid_custom_patterns_type - custom_patterns가 list가 아니면 ERROR
  test_error_timeout                    - Timeout 발생 시 ERROR + errors
  test_error_request_fail               - RequestException 발생 시 ERROR + errors
"""

from unittest.mock import MagicMock, patch

import requests

from va_mcp.core import TargetInfo, ToolInput, ToolOptions
from va_mcp.core.schemas import ApiRequest
from va_mcp.tools.cryptographic_failures.sensitive_data_exposure import SensitiveDataExposureTool


# ------------------------------------------------------------------
# 공통 헬퍼
# ------------------------------------------------------------------

def make_tool_input(extra: dict | None = None, with_request: bool = True) -> ToolInput:
    return ToolInput(
        target=TargetInfo(base_url="https://test.example.com"),
        request=ApiRequest(method="GET", path="/api/users/me") if with_request else None,
        options=ToolOptions(extra=extra or {}),
    )


def mock_response(body: str = "", status_code: int = 200) -> MagicMock:
    resp = MagicMock()
    resp.status_code = status_code
    resp.text = body
    resp.headers = {"Content-Type": "application/json"}
    return resp


# ------------------------------------------------------------------
# 테스트
# ------------------------------------------------------------------

def test_skipped_no_request():
    """request가 None이면 SKIPPED를 반환한다."""
    result = SensitiveDataExposureTool().run(make_tool_input(with_request=False))
    assert result.status == "skipped"
    assert result.evidence == []


def test_passed():
    """민감 정보가 없는 응답은 PASSED를 반환한다."""
    body = '{"id": 1, "username": "testuser", "created_at": "2026-01-01"}'
    with patch("requests.request", return_value=mock_response(body)):
        result = SensitiveDataExposureTool().run(make_tool_input())
    assert result.status == "passed"
    assert result.severity == "info"
    assert "CWE-319" in result.cwe
    assert "CWE-523" in result.cwe


def test_vulnerable_email():
    """이메일 주소가 포함된 응답은 VULNERABLE HIGH를 반환한다."""
    body = '{"id": 1, "email": "user@example.com"}'
    with patch("requests.request", return_value=mock_response(body)):
        result = SensitiveDataExposureTool().run(make_tool_input())
    assert result.status == "vulnerable"
    assert result.severity == "high"
    assert result.confidence == "medium"
    assert "이메일" in result.description
    assert len(result.evidence) > 0


def test_vulnerable_ssn_with_separator():
    """하이픈이 있는 주민등록번호 형식(900101-1234567)을 탐지한다."""
    body = '{"ssn": "900101-1234567"}'
    with patch("requests.request", return_value=mock_response(body)):
        result = SensitiveDataExposureTool().run(make_tool_input())
    assert result.status == "vulnerable"
    assert "주민등록번호" in result.description


def test_vulnerable_ssn_without_separator():
    """구분자 없는 주민등록번호 형식(9001011234567)도 탐지한다."""
    body = '{"ssn": "9001011234567"}'
    with patch("requests.request", return_value=mock_response(body)):
        result = SensitiveDataExposureTool().run(make_tool_input())
    assert result.status == "vulnerable"
    assert "주민등록번호" in result.description


def test_vulnerable_password_double_quote():
    """"password":"value" 이중따옴표 형식을 탐지한다."""
    body = '{"username": "admin", "password": "supersecret"}'
    with patch("requests.request", return_value=mock_response(body)):
        result = SensitiveDataExposureTool().run(make_tool_input())
    assert result.status == "vulnerable"
    assert "비밀번호 필드 노출" in result.description


def test_vulnerable_password_single_quote():
    """'password':'value' 단따옴표 형식도 탐지한다."""
    body = "{'username': 'admin', 'password': 'supersecret'}"
    with patch("requests.request", return_value=mock_response(body)):
        result = SensitiveDataExposureTool().run(make_tool_input())
    assert result.status == "vulnerable"
    assert "비밀번호 필드 노출" in result.description


def test_vulnerable_password_uppercase():
    """대소문자 혼용 "Password" 필드도 탐지한다."""
    body = '{"Username": "admin", "Password": "supersecret"}'
    with patch("requests.request", return_value=mock_response(body)):
        result = SensitiveDataExposureTool().run(make_tool_input())
    assert result.status == "vulnerable"
    assert "비밀번호 필드 노출" in result.description


def test_vulnerable_aws_access_key():
    """AWS Access Key 형식(AKIA...)을 탐지한다."""
    body = '{"aws_key": "AKIAIOSFODNN7EXAMPLE"}'
    with patch("requests.request", return_value=mock_response(body)):
        result = SensitiveDataExposureTool().run(make_tool_input())
    assert result.status == "vulnerable"
    assert "AWS Access Key" in result.description


def test_vulnerable_openssh_private_key():
    """-----BEGIN OPENSSH PRIVATE KEY----- 형식을 탐지한다."""
    body = "-----BEGIN OPENSSH PRIVATE KEY-----\nb3BlbnNzaC1rZXktdjEAAAA=\n-----END OPENSSH PRIVATE KEY-----"
    with patch("requests.request", return_value=mock_response(body)):
        result = SensitiveDataExposureTool().run(make_tool_input())
    assert result.status == "vulnerable"
    assert "Private Key 헤더" in result.description


def test_vulnerable_custom_pattern():
    """extra['custom_patterns']에 지정된 패턴도 탐지한다."""
    body = '{"internal_code": "CORP-SECRET-XYZ"}'
    with patch("requests.request", return_value=mock_response(body)):
        result = SensitiveDataExposureTool().run(
            make_tool_input(extra={"custom_patterns": [r"CORP-SECRET-\w+"]})
        )
    assert result.status == "vulnerable"
    assert "사용자 정의 패턴 #1" in result.description


def test_error_invalid_custom_patterns_type():
    """custom_patterns가 list가 아니면 ERROR + errors를 반환한다."""
    result = SensitiveDataExposureTool().run(
        make_tool_input(extra={"custom_patterns": "not-a-list"})
    )
    assert result.status == "error"
    assert result.severity == "info"
    assert result.confidence == "low"
    assert len(result.errors) > 0
    assert result.errors[0].error_code == "INVALID_INPUT"


def test_error_timeout():
    """Timeout 발생 시 ERROR + errors를 반환한다."""
    with patch("requests.request", side_effect=requests.Timeout):
        result = SensitiveDataExposureTool().run(make_tool_input())
    assert result.status == "error"
    assert result.severity == "info"
    assert result.confidence == "low"
    assert result.errors[0].error_code == "TIMEOUT"


def test_error_request_fail():
    """RequestException 발생 시 ERROR + errors를 반환한다."""
    with patch("requests.request", side_effect=requests.RequestException("conn error")):
        result = SensitiveDataExposureTool().run(make_tool_input())
    assert result.status == "error"
    assert result.errors[0].error_code == "HTTP_FAILURE"
