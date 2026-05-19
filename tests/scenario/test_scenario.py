"""
Scenario 테스트.

[기본 동작]
test_scenario_calls_orchestrator_with_plan_tool_ids  - orchestrator.run()에 plan.tool_ids 전달
test_scenario_returns_correct_owasp                  - ScenarioResult.owasp == plan.owasp
test_scenario_collects_tool_results                  - orchestrator 반환값이 ScenarioResult에 포함

[POC 생성]
test_poc_generated_for_vulnerable_result             - VULNERABLE 결과 있으면 POC 텍스트 생성
test_poc_empty_when_no_vulnerability                 - 취약점 없으면 poc=""
test_poc_contains_tool_id_and_title                  - POC에 tool_id, title 포함
test_poc_contains_request_info                       - POC에 method, path, response_status 포함

[스킵 조건]
test_empty_tool_ids_skips_orchestrator               - tool_ids 빈 목록 → orchestrator 미호출
test_none_endpoint_skips_orchestrator                - endpoint=None → orchestrator 미호출
test_empty_tool_ids_returns_empty_result             - tool_ids 빈 목록 → tool_results=[]
"""

from unittest.mock import MagicMock

import pytest

from va_mcp.core.constants import Severity, ToolStatus, Confidence
from va_mcp.endpoint_profile.endpoint_profile import EndpointProfile
from va_mcp.core.scenario_plan import ScenarioPlan
from va_mcp.core.schemas import Evidence, ToolResult
from va_mcp.scenario.scenario import Scenario


# ------------------------------------------------------------------
# 헬퍼
# ------------------------------------------------------------------

def make_profile() -> EndpointProfile:
    return EndpointProfile(base_url="https://api.example.com", method="GET", path="/api/items/1")


def make_tool_result(status: str = ToolStatus.PASSED.value, tool_id: str = "idor_bola") -> ToolResult:
    return ToolResult(
        tool_id=tool_id,
        tool_name="Test Tool",
        status=status,
        severity=Severity.HIGH.value if status == ToolStatus.VULNERABLE.value else Severity.INFO.value,
        confidence=Confidence.HIGH.value if status == ToolStatus.VULNERABLE.value else Confidence.LOW.value,
        title="다른 사용자 데이터 접근 가능" if status == ToolStatus.VULNERABLE.value else "",
        evidence=[
            Evidence(
                request={"method": "GET", "path": "/api/items/2"},
                response_status=200,
                note="user_a 권한으로 user_b 데이터 조회됨",
            )
        ] if status == ToolStatus.VULNERABLE.value else [],
    )


def make_orchestrator(returns: list[ToolResult] | None = None) -> MagicMock:
    orch = MagicMock()
    orch.run.return_value = returns or []
    return orch


# ------------------------------------------------------------------
# 기본 동작
# ------------------------------------------------------------------

def test_scenario_calls_orchestrator_with_plan_tool_ids():
    tool_ids = ["idor_bola", "bfla"]
    orch = make_orchestrator()
    profile = make_profile()
    plan = ScenarioPlan(owasp="A01", tool_ids=tool_ids, endpoint=profile)

    Scenario(orch).run(plan)

    orch.run.assert_called_once_with(tool_ids, profile)


def test_scenario_returns_correct_owasp():
    orch = make_orchestrator()
    plan = ScenarioPlan(owasp="A07", tool_ids=["auth_bruteforce"], endpoint=make_profile())
    result = Scenario(orch).run(plan)
    assert result.owasp == "A07"


def test_scenario_collects_tool_results():
    tr = make_tool_result(ToolStatus.PASSED.value)
    orch = make_orchestrator(returns=[tr])
    plan = ScenarioPlan(owasp="A01", tool_ids=["idor_bola"], endpoint=make_profile())

    result = Scenario(orch).run(plan)

    assert result.tool_results == [tr]


# ------------------------------------------------------------------
# POC 생성
# ------------------------------------------------------------------

def test_poc_generated_for_vulnerable_result():
    tr = make_tool_result(ToolStatus.VULNERABLE.value)
    orch = make_orchestrator(returns=[tr])
    plan = ScenarioPlan(owasp="A01", tool_ids=["idor_bola"], endpoint=make_profile())

    result = Scenario(orch).run(plan)

    assert result.poc != ""


def test_poc_empty_when_no_vulnerability():
    tr = make_tool_result(ToolStatus.PASSED.value)
    orch = make_orchestrator(returns=[tr])
    plan = ScenarioPlan(owasp="A01", tool_ids=["idor_bola"], endpoint=make_profile())

    result = Scenario(orch).run(plan)

    assert result.poc == ""


def test_poc_contains_tool_id_and_title():
    tr = make_tool_result(ToolStatus.VULNERABLE.value, tool_id="idor_bola")
    orch = make_orchestrator(returns=[tr])
    plan = ScenarioPlan(owasp="A01", tool_ids=["idor_bola"], endpoint=make_profile())

    result = Scenario(orch).run(plan)

    assert "idor_bola" in result.poc
    assert tr.title in result.poc


def test_poc_contains_request_info():
    tr = make_tool_result(ToolStatus.VULNERABLE.value)
    orch = make_orchestrator(returns=[tr])
    plan = ScenarioPlan(owasp="A01", tool_ids=["idor_bola"], endpoint=make_profile())

    result = Scenario(orch).run(plan)

    assert "GET" in result.poc
    assert "/api/items/2" in result.poc
    assert "200" in result.poc


# ------------------------------------------------------------------
# 스킵 조건
# ------------------------------------------------------------------

def test_empty_tool_ids_skips_orchestrator():
    orch = make_orchestrator()
    plan = ScenarioPlan(owasp="A09", tool_ids=[], endpoint=make_profile())

    Scenario(orch).run(plan)

    orch.run.assert_not_called()


def test_none_endpoint_skips_orchestrator():
    orch = make_orchestrator()
    plan = ScenarioPlan(owasp="A01", tool_ids=["idor_bola"], endpoint=None)

    Scenario(orch).run(plan)

    orch.run.assert_not_called()


def test_empty_tool_ids_returns_empty_result():
    orch = make_orchestrator()
    plan = ScenarioPlan(owasp="A09", tool_ids=[], endpoint=make_profile())

    result = Scenario(orch).run(plan)

    assert result.tool_results == []
    assert result.poc == ""
