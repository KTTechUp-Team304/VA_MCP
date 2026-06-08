"""
IdorBolaTool 테스트.

설계 변경 (T-21): access_type 기반 교차 접근 테스트
  - resource_context.access_type == "private"일 때만 실행
  - auth[0](소유자 역할), auth[-1](공격자 역할)로 교차 접근 테스트
  - JWT sub 비교 방식 제거
"""

from unittest.mock import MagicMock, patch

import pytest
import requests

from va_mcp.core import AuthContext, TargetInfo, ToolInput, ToolOptions
from va_mcp.core.schemas import ApiRequest
from va_mcp.tools.access_control.idor_bola import (
    IdorBolaTool,
    extract_resource_id,
    is_vacuous_response_body,
)


def make_tool_input(auth=None, request=None, access_type: str | None = "private") -> ToolInput:
    """
    access_type 기본값 'private' — 실제 테스트가 실행되는 케이스.
    access_type=None 전달 시 resource_context 미포함 → SKIPPED 케이스.
    """
    default_auth = [
        AuthContext(role="student", auth_type="bearer", token="token_student"),
        AuthContext(role="admin", auth_type="bearer", token="token_admin"),
    ]
    extra: dict = {}
    if access_type is not None:
        extra["resource_context"] = {"access_type": access_type}

    return ToolInput(
        target=TargetInfo(base_url="https://test.example.com"),
        request=request or ApiRequest(
            method="GET",
            path="/api/enrollments/116",
        ),
        auth=auth or default_auth,
        options=ToolOptions(extra=extra),
    )


def mock_response(status_code: int, text: str = "{}") -> MagicMock:
    resp = MagicMock()
    resp.status_code = status_code
    resp.text = text
    resp.headers = {"Content-Type": "application/json"}
    resp.request = MagicMock()
    resp.request.headers = {"Authorization": "Bearer TOKEN"}
    return resp


def test_passed():
    """소유자 접근 성공, 공격자 접근 차단 → PASSED"""
    owner_resp = mock_response(200, '{"id": 116, "userId": 1}')
    attacker_resp = mock_response(403, '{"error": "Forbidden"}')

    with patch("requests.request", side_effect=[owner_resp, attacker_resp]):
        result = IdorBolaTool().run(make_tool_input())

    assert result.status == "passed"
    assert result.evidence == []


def test_vulnerable():
    """소유자·공격자 모두 200, body 동일 → VULNERABLE HIGH"""
    body = '{"id": 116, "userId": 1}'
    owner_resp = mock_response(200, body)
    attacker_resp = mock_response(200, body)

    with patch("requests.request", side_effect=[owner_resp, attacker_resp]):
        result = IdorBolaTool().run(make_tool_input())

    assert result.status == "vulnerable"
    assert len(result.evidence) == 1
    # auth[0]=student(소유자), auth[-1]=admin(공격자)
    assert result.evidence[0].request["owner_role"] == "student"
    assert result.evidence[0].request["attacker_role"] == "admin"
    assert result.confidence == "high"


def test_vulnerable_body_mismatch_lowers_confidence():
    """공격자 200이지만 body 불일치 → VULNERABLE MEDIUM"""
    owner_resp = mock_response(200, '{"id": 116, "secret": "xyz"}')
    attacker_resp = mock_response(200, '{"id": 116}')

    with patch("requests.request", side_effect=[owner_resp, attacker_resp]):
        result = IdorBolaTool().run(make_tool_input())

    assert result.status == "vulnerable"
    assert result.confidence == "medium"


def test_skipped_no_access_type():
    """resource_context 미설정 → access_type 없음 → SKIPPED"""
    result = IdorBolaTool().run(make_tool_input(access_type=None))

    assert result.status == "skipped"
    assert "access_type" in result.description


def test_skipped_public_resource():
    """access_type='public' → 공개 리소스 → SKIPPED"""
    result = IdorBolaTool().run(make_tool_input(access_type="public"))

    assert result.status == "skipped"
    assert "access_type" in result.description


def test_skipped_both_vacuous_bodies():
    """소유자·공격자 모두 200이지만 빈 본문 → SKIPPED"""
    owner_resp = mock_response(200, "[]")
    attacker_resp = mock_response(200, "[]")

    with patch("requests.request", side_effect=[owner_resp, attacker_resp]):
        result = IdorBolaTool().run(make_tool_input())

    assert result.status == "skipped"
    assert "빈 본문" in result.description


def test_skipped_owner_fails():
    """소유자 요청 실패(404) → SKIPPED"""
    owner_fail = mock_response(404, '{"error": "Not Found"}')

    with patch("requests.request", return_value=owner_fail):
        result = IdorBolaTool().run(make_tool_input())

    assert result.status == "skipped"
    assert "소유자" in result.description


def test_skipped_no_request():
    """request 없음 → SKIPPED"""
    tool_input = ToolInput(
        target=TargetInfo(base_url="https://test.example.com"),
        request=None,
        auth=[
            AuthContext(role="student", auth_type="bearer", token="token_a"),
            AuthContext(role="admin", auth_type="bearer", token="token_b"),
        ],
    )
    result = IdorBolaTool().run(tool_input)

    assert result.status == "skipped"


def test_skipped_insufficient_auth():
    """auth 1개 → SKIPPED"""
    tool_input = make_tool_input(
        auth=[AuthContext(role="student", auth_type="bearer", token="token_a")]
    )
    result = IdorBolaTool().run(tool_input)

    assert result.status == "skipped"


def test_error_timeout():
    """요청 타임아웃 → ERROR(TIMEOUT)"""
    with patch("requests.request", side_effect=requests.Timeout):
        result = IdorBolaTool().run(make_tool_input())

    assert result.status == "error"
    assert result.errors[0].error_code == "TIMEOUT"


def test_error_request_fail():
    """네트워크 오류 → ERROR(HTTP_FAILURE)"""
    with patch("requests.request", side_effect=requests.RequestException("network error")):
        result = IdorBolaTool().run(make_tool_input())

    assert result.status == "error"
    assert result.errors[0].error_code == "HTTP_FAILURE"


@pytest.mark.parametrize(
    "body,expected",
    [
        ("[]", True),
        ("{}", True),
        ("  []  ", True),
        ('{"id": 1}', False),
        ("", True),
    ],
)
def test_is_vacuous_response_body(body, expected):
    assert is_vacuous_response_body(body) is expected


def test_extract_resource_id_from_path_and_me():
    assert extract_resource_id("/api/users/25", None) == "25"
    assert extract_resource_id("/api/enrollments/me", None) is None
