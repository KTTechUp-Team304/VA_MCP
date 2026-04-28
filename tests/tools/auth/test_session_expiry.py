import pytest
import time
from va_mcp.tools.auth.session_expiry import SessionExpiryTool
from .conftest import DummyResponse

@pytest.fixture(autouse=True)
def no_sleep(monkeypatch):
    # 테스트 중 시간 지연 제거
    monkeypatch.setattr(time, "sleep", lambda s: None)

def test_session_expiry_skipped(monkeypatch, base_input):
    # 첫 요청 401 → SKIPPED
    monkeypatch.setattr(
        "va_mcp.tools.auth.session_expiry.requests.request",
        lambda *args, **kwargs: DummyResponse(401),
    )
    tool = SessionExpiryTool()
    result = tool.run(base_input)
    assert result.status == "skipped"
    assert "건너뛰" in result.description

def test_session_expiry_vulnerable(monkeypatch, base_input):
    # 첫/두 번째 모두 200 → vulnerable
    seq = [DummyResponse(200), DummyResponse(200)]
    monkeypatch.setattr(
        "va_mcp.tools.auth.session_expiry.requests.request",
        lambda *args, **kwargs: seq.pop(0),
    )
    tool = SessionExpiryTool()
    result = tool.run(base_input)
    assert result.status == "vulnerable"

def test_session_expiry_passed(monkeypatch, base_input):
    # 첫 200 → 두 번째 401 → passed
    seq = [DummyResponse(200), DummyResponse(401)]
    monkeypatch.setattr(
        "va_mcp.tools.auth.session_expiry.requests.request",
        lambda *args, **kwargs: seq.pop(0),
    )
    tool = SessionExpiryTool()
    result = tool.run(base_input)
    assert result.status == "passed"