"""
IdorBolaTool 테스트.
"""

import base64
import json
from unittest.mock import MagicMock, patch

import pytest
import requests

from va_mcp.core import AuthContext, TargetInfo, ToolInput, ToolOptions
from va_mcp.core.schemas import ApiRequest
from va_mcp.tools.access_control.idor_bola import (
    IdorBolaTool,
    extract_resource_id,
    is_vacuous_response_body,
    resolve_idor_pair,
)


def _b64url_obj(data: dict) -> str:
    raw = json.dumps(data, separators=(",", ":")).encode()
    return base64.urlsafe_b64encode(raw).decode().rstrip("=")


def make_jwt(sub: str) -> str:
    header = _b64url_obj({"alg": "HS256", "typ": "JWT"})
    payload = _b64url_obj({"sub": sub})
    return f"{header}.{payload}.signature"


def make_tool_input(auth=None, request=None) -> ToolInput:
    default_auth = [
        AuthContext(role="user_a", auth_type="bearer", token=make_jwt("1")),
        AuthContext(role="user_b", auth_type="bearer", token=make_jwt("2")),
    ]
    return ToolInput(
        target=TargetInfo(base_url="https://test.example.com"),
        request=request
        or ApiRequest(
            method="GET",
            path="/api/users/2/profile",
            params={"userId": "2"},
        ),
        auth=auth or default_auth,
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


def test_passed():
    owner_resp = mock_response(200, '{"id": 2, "email": "user2@test.com"}')
    attacker_resp = mock_response(403, '{"error": "Forbidden"}')

    with patch("requests.request", side_effect=[owner_resp, attacker_resp]):
        result = IdorBolaTool().run(make_tool_input())

    assert result.status == "passed"
    assert result.evidence == []


def test_vulnerable():
    owner_resp = mock_response(200, '{"id": 2, "email": "user2@test.com"}')
    attacker_resp = mock_response(200, '{"id": 2, "email": "user2@test.com"}')

    with patch("requests.request", side_effect=[owner_resp, attacker_resp]):
        result = IdorBolaTool().run(make_tool_input())

    assert result.status == "vulnerable"
    assert len(result.evidence) == 1
    assert result.evidence[0].request["owner_role"] == "user_b"
    assert result.evidence[0].request["attacker_role"] == "user_a"
    assert result.confidence == "high"


def test_vulnerable_body_mismatch_lowers_confidence():
    owner_resp = mock_response(200, '{"id": 2, "email": "user2@test.com", "secret": "xyz"}')
    attacker_resp = mock_response(200, '{"id": 2}')

    with patch("requests.request", side_effect=[owner_resp, attacker_resp]):
        result = IdorBolaTool().run(make_tool_input())

    assert result.status == "vulnerable"
    assert result.confidence == "medium"


def test_resolve_owner_from_jwt_not_auth_order():
    """auth 순서와 무관하게 path ID와 JWT sub로 owner/attacker를 정한다."""
    auth = [
        AuthContext(role="admin", auth_type="bearer", token=make_jwt("99")),
        AuthContext(role="student", auth_type="bearer", token=make_jwt("25")),
    ]
    tool_input = make_tool_input(
        auth=auth,
        request=ApiRequest(method="GET", path="/api/users/25", params={"userId": "25"}),
    )
    owner_resp = mock_response(200, '{"id": 25}')
    attacker_resp = mock_response(403)

    with patch("requests.request", side_effect=[owner_resp, attacker_resp]):
        result = IdorBolaTool().run(tool_input)

    assert result.status == "passed"
    assert "admin" in result.description


def test_skipped_me_path_no_resource_id():
    tool_input = make_tool_input(
        request=ApiRequest(method="GET", path="/api/enrollments/me"),
        auth=[
            AuthContext(role="student1", auth_type="bearer", token=make_jwt("1")),
            AuthContext(role="student2", auth_type="bearer", token=make_jwt("2")),
        ],
    )
    result = IdorBolaTool().run(tool_input)

    assert result.status == "skipped"
    assert "/me" in result.description or "추출" in result.description


def test_skipped_both_vacuous_bodies():
    owner_resp = mock_response(200, "[]")
    attacker_resp = mock_response(200, "[]")

    with patch("requests.request", side_effect=[owner_resp, attacker_resp]):
        result = IdorBolaTool().run(make_tool_input())

    assert result.status == "skipped"
    assert "빈 본문" in result.description


def test_error_timeout():
    with patch("requests.request", side_effect=requests.Timeout):
        result = IdorBolaTool().run(make_tool_input())

    assert result.status == "error"
    assert result.errors[0].error_code == "TIMEOUT"


def test_error_request_fail():
    with patch("requests.request", side_effect=requests.RequestException("network error")):
        result = IdorBolaTool().run(make_tool_input())

    assert result.status == "error"
    assert result.errors[0].error_code == "HTTP_FAILURE"


def test_skipped_no_request():
    tool_input = ToolInput(
        target=TargetInfo(base_url="https://test.example.com"),
        request=None,
        auth=[
            AuthContext(role="user_a", auth_type="bearer", token=make_jwt("1")),
            AuthContext(role="user_b", auth_type="bearer", token=make_jwt("2")),
        ],
    )
    result = IdorBolaTool().run(tool_input)

    assert result.status == "skipped"


def test_skipped_insufficient_auth():
    tool_input = make_tool_input(
        auth=[AuthContext(role="user_a", auth_type="bearer", token=make_jwt("1"))]
    )
    result = IdorBolaTool().run(tool_input)

    assert result.status == "skipped"


def test_skipped_owner_fails():
    owner_fail = mock_response(404, '{"error": "Not Found"}')

    with patch("requests.request", return_value=owner_fail):
        result = IdorBolaTool().run(make_tool_input())

    assert result.status == "skipped"


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


def test_resolve_idor_pair():
    auth = [
        AuthContext(role="admin", auth_type="bearer", token=make_jwt("99")),
        AuthContext(role="student", auth_type="bearer", token=make_jwt("25")),
    ]
    attacker, owner, reason = resolve_idor_pair(auth, "/api/users/25", {"userId": "25"})
    assert reason is None
    assert owner.role == "student"
    assert attacker.role == "admin"
