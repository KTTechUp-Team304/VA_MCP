import pytest
from va_mcp.tools.auth.rate_limit import RateLimitTool
from .conftest import DummyResponse

def test_rate_limit_vulnerable(monkeypatch, base_input):
    # 모든 요청이 200 → Rate Limit 없음 → vulnerable
    monkeypatch.setattr(
        "va_mcp.tools.auth.rate_limit.requests.request",
        lambda *args, **kwargs: DummyResponse(200, {"h": "v"}, "ok"),
    )
    tool = RateLimitTool()
    result = tool.run(base_input)
    assert result.status == "vulnerable"
    assert result.owasp == ["A07:2025 Identification and Authentication Failures"]
    assert "Rate Limit 없음" in result.title

def test_rate_limit_passed_on_429(monkeypatch, base_input):
    # 첫 요청부터 429 → 제한 동작 확인 → passed
    monkeypatch.setattr(
        "va_mcp.tools.auth.rate_limit.requests.request",
        lambda *args, **kwargs: DummyResponse(429),
    )
    tool = RateLimitTool()
    result = tool.run(base_input)
    assert result.status == "passed"
    assert "정상" in result.title