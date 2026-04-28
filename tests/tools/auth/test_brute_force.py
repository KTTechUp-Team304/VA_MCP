import pytest
from va_mcp.tools.auth.brute_force import BruteForceTool
from .conftest import DummyResponse

def test_bruteforce_vulnerable(monkeypatch, base_input):
    # 첫 번은 실패(401), 두 번째 성공(200) 시뮬레이트
    seq = [DummyResponse(401), DummyResponse(200)]
    monkeypatch.setattr(
        "va_mcp.tools.auth.brute_force.requests.request",
        lambda *args, **kwargs: seq.pop(0),
    )
    tool = BruteForceTool()
    result = tool.run(base_input)
    assert result.status == "vulnerable"
    # description에 *** 마스킹 확인
    assert "***" in result.description

def test_bruteforce_passed(monkeypatch, base_input):
    # 모두 실패(401) → 방어됨
    monkeypatch.setattr(
        "va_mcp.tools.auth.brute_force.requests.request",
        lambda *args, **kwargs: DummyResponse(401),
    )
    tool = BruteForceTool()
    result = tool.run(base_input)
    assert result.status == "passed"