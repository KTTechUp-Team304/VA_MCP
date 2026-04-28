import pytest
from va_mcp.tools.auth.account_lockout import AccountLockoutTool
from .conftest import DummyResponse

def test_account_lockout_vulnerable(monkeypatch, base_input):
    # 모두 200 → 계정 잠금 없음 → vulnerable
    monkeypatch.setattr(
        "va_mcp.tools.auth.account_lockout.requests.request",
        lambda *args, **kwargs: DummyResponse(200),
    )
    tool = AccountLockoutTool()
    result = tool.run(base_input)
    assert result.status == "vulnerable"

def test_account_lockout_passed_on_403(monkeypatch, base_input):
    # 첫 시도에서 403 → 계정 잠금 정상 → passed
    monkeypatch.setattr(
        "va_mcp.tools.auth.account_lockout.requests.request",
        lambda *args, **kwargs: DummyResponse(403),
    )
    tool = AccountLockoutTool()
    result = tool.run(base_input)
    assert result.status == "passed"