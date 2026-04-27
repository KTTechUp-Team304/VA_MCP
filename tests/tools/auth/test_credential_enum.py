import pytest
from va_mcp.tools.auth.credential_enum import CredentialEnumTool
from .conftest import DummyResponse

def test_credential_enum_vulnerable(monkeypatch, base_input):
    # 응답 200 vs 404 → 차이 있음 → vulnerable
    seq = [DummyResponse(200, text="OK"), DummyResponse(404, text="NotFound")]
    monkeypatch.setattr(
        "va_mcp.tools.auth.credential_enum.requests.request",
        lambda *args, **kwargs: seq.pop(0),
    )
    tool = CredentialEnumTool()
    result = tool.run(base_input)
    assert result.status == "vulnerable"

def test_credential_enum_passed(monkeypatch, base_input):
    # 응답 동일(200/OK) → 방어됨
    monkeypatch.setattr(
        "va_mcp.tools.auth.credential_enum.requests.request",
        lambda *args, **kwargs: DummyResponse(200, text="OK"),
    )
    tool = CredentialEnumTool()
    result = tool.run(base_input)
    assert result.status == "passed"