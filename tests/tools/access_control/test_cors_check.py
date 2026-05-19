"""
CorsCheckTool 테스트.

테스트 구성:
  test_passed                       - 모든 Origin이 차단될 때 PASSED 반환
  test_vulnerable_wildcard          - ACAO: * 허용 시 VULNERABLE HIGH
  test_vulnerable_reflected_origin  - 공격자 Origin 반사 시 VULNERABLE HIGH
  test_vulnerable_critical_with_credentials - ACAO 허용 + ACAC: true 시 VULNERABLE CRITICAL
  test_vulnerable_null_origin       - null Origin 허용 시 VULNERABLE MEDIUM
  test_worst_severity_wins          - 여러 Origin 중 가장 높은 severity가 결과에 반영
  test_custom_test_origins          - extra["test_origins"] 지정 시 해당 Origin만 테스트
  test_with_auth                    - auth 제공 시 Authorization 헤더 포함
  test_error_timeout                - Timeout 발생 시 ERROR + errors
  test_error_request_fail           - RequestException 발생 시 ERROR + errors
"""

from unittest.mock import MagicMock, patch

import requests

from va_mcp.core import TargetInfo, ToolInput, ToolOptions
from va_mcp.core.schemas import ApiRequest
from va_mcp.tools.access_control.cors_check import CorsCheckTool


# ------------------------------------------------------------------
# 공통 헬퍼
# ------------------------------------------------------------------

def make_tool_input(auth=None, extra=None, path="/api/data") -> ToolInput:
    return ToolInput(
        target=TargetInfo(base_url="https://test.example.com"),
        request=ApiRequest(method="GET", path=path),
        auth=auth or [],
        options=ToolOptions(extra=extra or {}),
    )


def mock_response(
    status_code: int = 200,
    acao: str = "",
    acac: str = "",
) -> MagicMock:
    resp = MagicMock()
    resp.status_code = status_code
    resp.text = "{}"
    headers = {}
    if acao:
        headers["Access-Control-Allow-Origin"] = acao
    if acac:
        headers["Access-Control-Allow-Credentials"] = acac
    resp.headers = headers
    resp.request = MagicMock()
    resp.request.headers = {"Origin": "https://evil.example.com"}
    return resp


# ------------------------------------------------------------------
# 테스트
# ------------------------------------------------------------------

def test_passed():
    """모든 Origin이 차단되면 PASSED를 반환한다."""
    with patch("requests.get", return_value=mock_response(200, acao="")):
        result = CorsCheckTool().run(make_tool_input())

    assert result.status == "passed"
    assert result.evidence == []


def test_vulnerable_wildcard():
    """ACAO: * 허용 시 VULNERABLE HIGH를 반환한다."""
    with patch("requests.get", return_value=mock_response(200, acao="*")):
        result = CorsCheckTool().run(make_tool_input())

    assert result.status == "vulnerable"
    assert result.severity == "high"
    assert result.confidence == "high"
    assert "CWE-942" in result.cwe
    assert len(result.evidence) >= 1


def test_vulnerable_reflected_origin():
    """공격자 Origin이 ACAO에 그대로 반사되면 VULNERABLE HIGH를 반환한다."""
    def side_effect(url, headers=None, **kwargs):
        origin = (headers or {}).get("Origin", "")
        return mock_response(200, acao=origin)

    with patch("requests.get", side_effect=side_effect):
        result = CorsCheckTool().run(
            make_tool_input(extra={"test_origins": ["https://evil.example.com"]})
        )

    assert result.status == "vulnerable"
    assert result.severity == "high"
    assert len(result.evidence) == 1


def test_vulnerable_critical_with_credentials():
    """ACAO 허용 + ACAC: true 조합이면 VULNERABLE CRITICAL을 반환한다."""
    def side_effect(url, headers=None, **kwargs):
        origin = (headers or {}).get("Origin", "")
        return mock_response(200, acao=origin, acac="true")

    with patch("requests.get", side_effect=side_effect):
        result = CorsCheckTool().run(
            make_tool_input(extra={"test_origins": ["https://evil.example.com"]})
        )

    assert result.status == "vulnerable"
    assert result.severity == "critical"


def test_vulnerable_wildcard_with_credentials_is_critical():
    """ACAO: * + ACAC: true 조합도 CRITICAL이다."""
    with patch("requests.get", return_value=mock_response(200, acao="*", acac="true")):
        result = CorsCheckTool().run(
            make_tool_input(extra={"test_origins": ["https://evil.example.com"]})
        )

    assert result.status == "vulnerable"
    assert result.severity == "critical"


def test_vulnerable_null_origin():
    """null Origin이 허용되면 VULNERABLE MEDIUM을 반환한다."""
    def side_effect(url, headers=None, **kwargs):
        origin = (headers or {}).get("Origin", "")
        if origin == "null":
            return mock_response(200, acao="null")
        return mock_response(200, acao="")

    with patch("requests.get", side_effect=side_effect):
        result = CorsCheckTool().run(
            make_tool_input(extra={"test_origins": ["null"]})
        )

    assert result.status == "vulnerable"
    assert result.severity == "medium"


def test_worst_severity_wins():
    """여러 Origin 테스트 중 가장 높은 severity가 최종 결과에 반영된다."""
    call_count = 0

    def side_effect(url, headers=None, **kwargs):
        nonlocal call_count
        call_count += 1
        origin = (headers or {}).get("Origin", "")
        if origin == "null":
            return mock_response(200, acao="null")             # MEDIUM
        if origin == "https://evil.example.com":
            return mock_response(200, acao=origin, acac="true")  # CRITICAL
        return mock_response(200, acao="")

    with patch("requests.get", side_effect=side_effect):
        result = CorsCheckTool().run(
            make_tool_input(
                extra={"test_origins": ["null", "https://evil.example.com"]}
            )
        )

    assert result.status == "vulnerable"
    assert result.severity == "critical"
    assert len(result.evidence) == 2


def test_custom_test_origins():
    """extra['test_origins'] 지정 시 해당 Origin만 테스트한다."""
    tested_origins = []

    def side_effect(url, headers=None, **kwargs):
        tested_origins.append((headers or {}).get("Origin", ""))
        return mock_response(200, acao="")

    with patch("requests.get", side_effect=side_effect):
        CorsCheckTool().run(
            make_tool_input(extra={"test_origins": ["https://custom-attacker.com"]})
        )

    assert tested_origins == ["https://custom-attacker.com"]


def test_error_timeout():
    """Timeout 발생 시 ERROR + errors를 반환한다."""
    with patch("requests.get", side_effect=requests.Timeout):
        result = CorsCheckTool().run(make_tool_input())

    assert result.status == "error"
    assert len(result.errors) > 0
    assert result.errors[0].error_code == "TIMEOUT"
    assert result.severity == "info"
    assert result.confidence == "low"


def test_error_request_fail():
    """RequestException 발생 시 ERROR + errors를 반환한다."""
    with patch("requests.get", side_effect=requests.RequestException("connection error")):
        result = CorsCheckTool().run(make_tool_input())

    assert result.status == "error"
    assert result.errors[0].error_code == "HTTP_FAILURE"
