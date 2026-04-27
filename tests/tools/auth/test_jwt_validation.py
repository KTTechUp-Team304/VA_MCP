import pytest
from va_mcp.tools.auth.jwt_validation import JwtValidationTool
from .conftest import DummyResponse

def test_jwt_validation_vulnerable(monkeypatch, base_input):
    # 정상/변조 둘 다 200 → vulnerable
    monkeypatch.setattr(
        "va_mcp.tools.auth.jwt_validation.requests.request",
        lambda *args, **kwargs: DummyResponse(200),
    )
    tool = JwtValidationTool()
    result = tool.run(base_input)
    assert result.status == "vulnerable"
    assert "JWT 검증 실패" in result.title

def test_jwt_validation_passed(monkeypatch, base_input):
    # 변조 시 401 → passed
    def fake_req(method, url, headers, timeout):
        return DummyResponse(401) if "X" in headers["Authorization"] else DummyResponse(200)
    monkeypatch.setattr(
        "va_mcp.tools.auth.jwt_validation.requests.request",
        fake_req,
    )
    tool = JwtValidationTool()
    result = tool.run(base_input)
    assert result.status == "passed"