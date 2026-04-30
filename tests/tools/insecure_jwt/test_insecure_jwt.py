"""
InsecureJwtTool 테스트.

테스트 구성:
  test_skipped_no_auth              - auth가 없으면 SKIPPED 반환
  test_skipped_no_token             - token이 비어 있으면 SKIPPED 반환
  test_error_invalid_jwt_format     - 3-part 형식이 아니면 ERROR + errors 반환
  test_error_decode_failure         - 디코딩 불가 토큰은 ERROR + errors 반환
  test_vulnerable_alg_none          - alg=none 시 VULNERABLE HIGH 반환
  test_vulnerable_alg_none_uppercase - alg=NONE (대소문자 무관) VULNERABLE HIGH 반환
  test_vulnerable_missing_alg       - alg 클레임 누락 시 VULNERABLE HIGH 반환
  test_vulnerable_weak_algorithm    - HS256 사용 시 VULNERABLE MEDIUM 반환
  test_vulnerable_missing_exp       - exp 누락 시 VULNERABLE MEDIUM 반환
  test_vulnerable_sensitive_payload - password 키 포함 시 VULNERABLE HIGH 반환
  test_passed                       - RS256 + exp + 민감 키 없음 시 PASSED 반환
"""

import base64
import json

from va_mcp.core import AuthContext, TargetInfo, ToolInput, ToolOptions
from va_mcp.tools.cryptographic_failures.insecure_jwt import InsecureJwtTool


# ------------------------------------------------------------------
# 공통 헬퍼
# ------------------------------------------------------------------

def _encode_segment(data: dict) -> str:
    raw = json.dumps(data, separators=(",", ":")).encode()
    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode()


def make_jwt(header: dict, payload: dict, sig: str = "fakesignature") -> str:
    return f"{_encode_segment(header)}.{_encode_segment(payload)}.{sig}"


def make_tool_input(token: str | None = None) -> ToolInput:
    auth = []
    if token is not None:
        auth = [AuthContext(role="user", auth_type="bearer", token=token)]
    return ToolInput(
        target=TargetInfo(base_url="https://test.example.com"),
        options=ToolOptions(),
        auth=auth,
    )


# ------------------------------------------------------------------
# 테스트
# ------------------------------------------------------------------

def test_skipped_no_auth():
    """auth가 없으면 SKIPPED를 반환한다."""
    tool_input = ToolInput(
        target=TargetInfo(base_url="https://test.example.com"),
        options=ToolOptions(),
        auth=[],
    )
    result = InsecureJwtTool().run(tool_input)
    assert result.status == "skipped"
    assert result.evidence == []


def test_skipped_no_token():
    """token이 비어 있으면 SKIPPED를 반환한다."""
    result = InsecureJwtTool().run(make_tool_input(token=""))
    assert result.status == "skipped"
    assert result.evidence == []


def test_bearer_prefix_stripped():
    """token에 'Bearer ' 접두사가 있어도 정상적으로 분석한다."""
    raw_token = make_jwt({"alg": "RS256", "typ": "JWT"}, {"sub": "1234", "exp": 9999999999})
    result = InsecureJwtTool().run(make_tool_input(token=f"Bearer {raw_token}"))
    assert result.status == "passed"


def test_error_invalid_jwt_format():
    """3-part 형식이 아닌 토큰은 ERROR + errors를 반환한다."""
    result = InsecureJwtTool().run(make_tool_input(token="notajwt"))
    assert result.status == "error"
    assert result.severity == "info"
    assert result.confidence == "low"
    assert len(result.errors) > 0
    assert result.errors[0].error_code == "INVALID_INPUT"


def test_error_decode_failure():
    """base64 디코딩이 불가능한 세그먼트는 ERROR + errors를 반환한다."""
    result = InsecureJwtTool().run(make_tool_input(token="!!!.!!!.!!!"))
    assert result.status == "error"
    assert len(result.errors) > 0
    assert result.severity == "info"
    assert result.confidence == "low"


def test_vulnerable_alg_none():
    """alg=none 시 서명 검증이 생략되므로 VULNERABLE HIGH를 반환한다."""
    token = make_jwt({"alg": "none", "typ": "JWT"}, {"sub": "1234", "exp": 9999999999})
    result = InsecureJwtTool().run(make_tool_input(token=token))
    assert result.status == "vulnerable"
    assert result.severity == "high"
    assert result.confidence == "high"
    assert "CWE-347" in result.cwe
    assert "CWE-327" in result.cwe


def test_vulnerable_alg_none_uppercase():
    """alg=NONE (대소문자 무관)도 VULNERABLE HIGH로 탐지한다."""
    token = make_jwt({"alg": "NONE", "typ": "JWT"}, {"sub": "1234", "exp": 9999999999})
    result = InsecureJwtTool().run(make_tool_input(token=token))
    assert result.status == "vulnerable"
    assert result.severity == "high"


def test_vulnerable_missing_alg():
    """alg 클레임이 헤더에 없으면 VULNERABLE HIGH를 반환한다."""
    token = make_jwt({"typ": "JWT"}, {"sub": "1234", "exp": 9999999999})
    result = InsecureJwtTool().run(make_tool_input(token=token))
    assert result.status == "vulnerable"
    assert result.severity == "high"
    assert "alg" in result.description


def test_vulnerable_weak_algorithm():
    """대칭키 알고리즘 HS256은 brute-force에 취약하므로 VULNERABLE MEDIUM을 반환한다."""
    token = make_jwt({"alg": "HS256", "typ": "JWT"}, {"sub": "1234", "exp": 9999999999})
    result = InsecureJwtTool().run(make_tool_input(token=token))
    assert result.status == "vulnerable"
    assert result.severity == "medium"
    assert "HS256" in result.description


def test_vulnerable_missing_exp():
    """exp 클레임이 없으면 토큰이 영구 유효하므로 VULNERABLE을 반환한다."""
    token = make_jwt({"alg": "RS256", "typ": "JWT"}, {"sub": "1234"})
    result = InsecureJwtTool().run(make_tool_input(token=token))
    assert result.status == "vulnerable"
    assert result.severity == "medium"
    assert "exp" in result.description


def test_vulnerable_sensitive_payload():
    """페이로드에 password 키가 포함되면 VULNERABLE HIGH를 반환한다."""
    token = make_jwt(
        {"alg": "RS256", "typ": "JWT"},
        {"sub": "1234", "exp": 9999999999, "password": "secret123"},
    )
    result = InsecureJwtTool().run(make_tool_input(token=token))
    assert result.status == "vulnerable"
    assert result.severity == "high"
    assert "password" in result.description


def test_passed():
    """RS256 + exp 포함 + 민감 키 없음 → PASSED를 반환한다."""
    token = make_jwt(
        {"alg": "RS256", "typ": "JWT"},
        {"sub": "1234", "exp": 9999999999, "role": "user"},
    )
    result = InsecureJwtTool().run(make_tool_input(token=token))
    assert result.status == "passed"
    assert result.severity == "info"
    assert result.confidence == "high"
    assert "CWE-347" in result.cwe
    assert "CWE-327" in result.cwe
